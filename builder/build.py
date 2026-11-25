#!/usr/bin/env python3
"""Builds the VIctory and XCL trees PortWatch VI rates as playable enough, for VILauncher.

Railway runs this every 3 hours (railway.json). Each run:

 1. reads PortWatch VI's tracker and scores every effort the way the site does (0-100);
 2. keeps the efforts with public code scoring MIN_SCORE (59) or more, best first;
 3. for each, finds what it is from its default branch: a VIctory tree (apps/victory/Cargo.toml)
    or an XCL tree (crates/xcl/Cargo.toml); anything else, archived or gone, is skipped;
 4. builds the newest commit for Windows with cargo-xwin (x86_64-pc-windows-msvc), as the
    unprivileged `build` user and without any of this service's secrets in its environment;
    a repository and commit already published is not rebuilt;
 5. scans the result on VirusTotal (virustotal-scan.py); a flagged build is not published;
 6. publishes each build as a .tar.gz on the `runtimes` release of GITHUB_REPOSITORY, then
    runtimes.json, then deletes the archives the new manifest no longer names.

runtimes.json keeps the shape VILauncher already reads (schema 1): `victory` and `xcl` are the
best build of each family, so older launchers keep working, and `builds` lists every published
build with its score, for the launcher to offer them all.

Environment:
  GITHUB_TOKEN        token with contents:write on GITHUB_REPOSITORY (required unless DRY_RUN)
  GITHUB_REPOSITORY   where the release lives (default SixLauncher/vilauncher-builder)
  VT_API_KEY          VirusTotal key; without it builds are published as "skipped"
  MIN_SCORE           59
  MAX_NEW_BUILDS      at most this many builds compiled per run (default 4)
  BUILD_TIMEOUT       seconds per build (default 3600)
  TRACKER_URL         PortWatch VI's tracker.json
  WORK_DIR            the build user's scratch space (default /work)
  OUT_DIR             root-only output: staged builds, archives (default /var/lib/vilauncher-builder)
  DRY_RUN=1           build and scan, but publish nothing (prints runtimes.json)
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TRACKER_URL = os.environ.get("TRACKER_URL", "https://raw.githubusercontent.com/4lwayz/portwatch-vi/main/data/tracker.json")
REPO = os.environ.get("GITHUB_REPOSITORY", "SixLauncher/vilauncher-builder")
TAG = os.environ.get("RELEASE_TAG", "runtimes")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
MIN_SCORE = float(os.environ.get("MIN_SCORE", "59"))
MAX_NEW = int(os.environ.get("MAX_NEW_BUILDS", "4"))
BUILD_TIMEOUT = int(os.environ.get("BUILD_TIMEOUT", "3600"))
WORK = os.environ.get("WORK_DIR", "/work")  # the build user's scratch space (sources)
# Root-only: what gets scanned, packed and uploaded never sits where the build user can write.
OUT = os.environ.get("OUT_DIR", "/var/lib/vilauncher-builder")
DRY_RUN = os.environ.get("DRY_RUN", "") not in ("", "0", "false")
BUILD_USER = os.environ.get("BUILD_USER", "build")
TARGET = "x86_64-pc-windows-msvc"
API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

FAMILIES = {
    # family: (file that marks the tree, cargo package, exe, commit file, label, --locked)
    "victory": ("apps/victory/Cargo.toml", "victory", "victory.exe", "VICTORY_COMMIT.txt", "VIctory", True),
    "xcl": ("crates/xcl/Cargo.toml", "xcl", "xcl.exe", "XCL_COMMIT.txt", "xcl", False),
}


def log(msg):
    print(f"[{datetime.datetime.now(datetime.timezone.utc):%H:%M:%S}] {msg}", flush=True)


# -- scoring, as PortWatch VI and VILauncher's status.rs do it ------------------------------------

def clamp01(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0.0
    if v != v or v in (float("inf"), float("-inf")):
        return 0.0
    return min(max(v, 0.0), 1.0)


def stability_fraction(s):
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return clamp01(s)
    return {"often": 0.25, "sometimes": 0.55, "rarely": 0.8, "stable": 1.0}.get(s, 0.0)


def score(effort):
    """The site's 0-100 score: a ladder up to Playable (50), then four quality tracks."""
    g = effort.get("gta") or {}
    gw = effort.get("groundwork") or {}
    groundwork = (0.2 * clamp01(gw.get("loader")) + 0.28 * clamp01(gw.get("shaders"))
                  + 0.32 * clamp01(gw.get("graphics")) + 0.2 * clamp01(gw.get("proven")))
    value = 10.0 * groundwork
    prev = value
    reached = "groundwork"
    for key, at in (("loads", 10.0), ("boots", 20.0), ("menu", 30.0), ("world", 40.0), ("playable", 50.0)):
        v = clamp01(g.get(key))
        if v >= 1.0:
            value = prev = at
            reached = key
            continue
        if v > 0.0:
            value = max(value, prev + v * (at - prev))
        break
    if reached == "playable":
        fps = g.get("fps") if isinstance(g.get("fps"), (int, float)) else 0.0
        quality = (0.35 * clamp01(g.get("story")) + 0.25 * clamp01(g.get("render"))
                   + 0.2 * clamp01(fps / 30.0) + 0.2 * stability_fraction(g.get("stability")))
        value = 50.0 + quality * 50.0
    return value


def candidates(tracker, min_score):
    """Efforts with a GitHub repository scoring at least min_score, best first."""
    out = []
    for e in tracker.get("efforts", []):
        repo = (e.get("repo") or "").strip()
        if not repo or e.get("nuked") or e.get("dmca"):
            continue
        s = round(score(e), 1)
        if s >= min_score:
            out.append({"repo": repo, "name": e.get("name") or e.get("id") or repo,
                        "branch": e.get("branch") or "", "score": s})
    out.sort(key=lambda c: (-c["score"], c["name"].lower()))
    return out


def archive_name(family, repo, commit):
    slug = re.sub(r"[^a-z0-9]+", "-", repo.lower()).strip("-")
    return f"{family}-{slug}-{commit[:12]}.tar.gz"


# -- HTTP / GitHub ---------------------------------------------------------------------------------

def http(url, data=None, method=None, headers=None, timeout=60, raw=False):
    h = {"User-Agent": "vilauncher-builder", "Accept": "application/vnd.github+json"}
    if TOKEN and urllib.parse.urlparse(url).hostname in ("api.github.com", "uploads.github.com"):
        h["Authorization"] = f"Bearer {TOKEN}"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        # GitHub says why in the body ("Resource not accessible by personal access token", ...).
        detail = e.read()[:500].decode("utf-8", "replace").strip()
        hint = ""
        if e.code in (401, 403) and "github.com" in (urllib.parse.urlparse(url).hostname or ""):
            hint = (f" -- check GITHUB_TOKEN: it needs Contents: Read and write on {REPO} (a fine-grained"
                    " token owned by the organization, approved if the organization requires it)")
        e.msg = f"{e.msg}: {method or ('POST' if data else 'GET')} {url}: {detail}{hint}"
        raise
    if raw:
        return body
    return json.loads(body) if body else None


def gh(path, **kw):
    return http(f"{API}/{path.lstrip('/')}", **kw)


def gh_opt(path):
    try:
        return gh(path)
    except urllib.error.HTTPError as e:
        if e.code in (404, 451, 403):
            return None
        raise


def inspect(cand):
    """(family, branch, commit) of a candidate's repository, or a reason it is skipped."""
    repo = cand["repo"]
    if not REPO_RE.match(repo):
        return None, "not a GitHub owner/name"
    info = gh_opt(f"repos/{repo}")
    if not info:
        return None, "repository unavailable (gone, private or blocked)"
    if info.get("archived") or info.get("disabled"):
        return None, "archived or disabled"
    branch = cand["branch"] or info.get("default_branch") or "main"
    family = None
    for fam, (marker, *_rest) in FAMILIES.items():
        if gh_opt(f"repos/{repo}/contents/{marker}?ref={urllib.parse.quote(branch)}"):
            family = fam
            break
    if not family:
        return None, f"no build recipe on {branch} (not a VIctory or XCL tree)"
    commit = (gh_opt(f"repos/{repo}/commits/{urllib.parse.quote(branch)}") or {}).get("sha", "")
    if not SHA_RE.match(commit):
        return None, f"could not read the newest commit of {branch}"
    return (family, branch, commit), None


def release():
    rel = gh_opt(f"repos/{REPO}/releases/tags/{TAG}")
    if rel or DRY_RUN:
        return rel
    return gh(f"repos/{REPO}/releases", method="POST", data=json.dumps({
        "tag_name": TAG, "name": "Runtimes (every 3 h)", "prerelease": True,
        "body": "victory.exe and xcl.exe built by vilauncher-builder (Railway) from the PortWatch VI efforts "
                f"scoring {MIN_SCORE:g} or more, with their VirusTotal results. VILauncher installs them from "
                "Compatibilidade > Atualizar runtime."}).encode(), headers={"Content-Type": "application/json"})


def previous_manifest(rel):
    for a in (rel or {}).get("assets", []):
        if a["name"] == "runtimes.json":
            try:
                return json.loads(http(a["url"], headers={"Accept": "application/octet-stream"}, raw=True))
            except Exception as e:  # a broken manifest is rebuilt from scratch
                log(f"previous runtimes.json unreadable ({e}); starting over")
    return {}


def upload(rel, path, name=None):
    name = name or os.path.basename(path)
    for a in rel.get("assets", []):
        if a["name"] == name:
            gh(f"repos/{REPO}/releases/assets/{a['id']}", method="DELETE")
    url = rel["upload_url"].split("{")[0] + "?" + urllib.parse.urlencode({"name": name})
    with open(path, "rb") as f:
        data = f.read()
    ctype = "application/json" if name.endswith(".json") else "application/gzip"
    asset = http(url, data=data, method="POST", headers={"Content-Type": ctype}, timeout=600)
    rel["assets"] = [a for a in rel.get("assets", []) if a["name"] != name] + [asset]


# -- building ------------------------------------------------------------------------------------

def run_as_builder(cmd, cwd, timeout):
    """Runs cmd as the unprivileged build user with a clean environment: none of this
    service's secrets reach the projects' build scripts."""
    home = os.path.expanduser(f"~{BUILD_USER}")
    env = {
        "HOME": home,
        "PATH": f"{HERE}/bin:{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "CARGO_HOME": f"{home}/.cargo",
        "RUSTUP_HOME": f"{home}/.rustup",
        "XWIN_ACCEPT_LICENSE": "1",
        "CARGO_TERM_COLOR": "never",
        "CARGO_INCREMENTAL": "0",
        "LANG": "C.UTF-8",
    }
    full = ["runuser", "-u", BUILD_USER, "--", "env", "-i"] + [f"{k}={v}" for k, v in env.items()] + cmd
    if os.geteuid() != 0:  # local runs: just drop the environment
        full = ["env", "-i"] + [f"{k}={v}" for k, v in env.items()] + cmd
    log("$ " + " ".join(cmd))
    try:
        p = subprocess.run(full, cwd=cwd, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    finally:
        if os.geteuid() == 0:  # nothing the build started outlives it (also on a timeout)
            subprocess.run(["pkill", "-KILL", "-u", BUILD_USER], check=False)
    tail = "\n".join(p.stdout.splitlines()[-40:])
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed ({p.returncode}):\n{tail}")
    return p.stdout


def checkout(repo, commit, dest):
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    git = ["git", "-C", dest]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["fetch", "-q", "--depth", "1", f"https://github.com/{repo}", commit], check=True, timeout=900)
    subprocess.run(git + ["checkout", "-q", "FETCH_HEAD"], check=True)
    if os.geteuid() == 0:
        subprocess.run(["chown", "-R", f"{BUILD_USER}:{BUILD_USER}", dest], check=True)


def build_tree(family, src):
    _marker, package, exe, _cf, _label, locked = FAMILIES[family]
    deadline = time.monotonic() + BUILD_TIMEOUT
    left = lambda: max(60, int(deadline - time.monotonic()))  # noqa: E731
    # The toolchain the repository pins in rust-toolchain.toml (or stable), with the MSVC target.
    run_as_builder(["rustup", "toolchain", "install"], src, left())
    run_as_builder(["rustup", "target", "add", TARGET], src, left())
    cmd = ["cargo", "xwin", "build", "--release", "-p", package, "--target", TARGET]
    if locked:
        cmd.insert(3, "--locked")
    run_as_builder(cmd, src, left())
    out = os.path.join(src, "target", TARGET, "release")
    if not os.path.isfile(os.path.join(out, exe)):
        raise RuntimeError(f"the build finished without {exe}")
    return out


_dxc = {}


def dxc():
    """dxcompiler.dll and dxil.dll from DirectXShaderCompiler's newest release, once per run."""
    if not _dxc:
        rel = gh("repos/microsoft/DirectXShaderCompiler/releases/latest")
        zip_asset = next(a for a in rel["assets"] if re.match(r"^dxc_.*\.zip$", a["name"]))
        d = os.path.join(OUT, "dxc")
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        zpath = os.path.join(d, zip_asset["name"])
        with open(zpath, "wb") as f:
            f.write(http(zip_asset["browser_download_url"], raw=True, timeout=600, headers={"Accept": "*/*"}))
        with zipfile.ZipFile(zpath) as z:
            z.extractall(os.path.join(d, "x"))
        _dxc.update(dir=os.path.join(d, "x"), version=f"DXC {rel['tag_name']} ({zip_asset['name']})")
    return _dxc


def opus_dll():
    """opus.dll, built once by the image (Dockerfile) with clang-cl against the same SDK."""
    path = os.environ.get("OPUS_DLL", "/opt/opus/bin/opus.dll")
    if not os.path.isfile(path):
        raise RuntimeError(f"{path} is missing; the image builds it (Dockerfile, opus stage)")
    return path


def collect(family, repo, commit, src, out_dir, stage):
    """Lays out the build the way VILauncher unpacks it (the old workflow's layout)."""
    _m, _p, exe, commit_file, label, _l = FAMILIES[family]
    shutil.rmtree(stage, ignore_errors=True)
    lic = os.path.join(stage, "licenses")
    os.makedirs(lic)
    shutil.copy2(os.path.join(out_dir, exe), stage)
    pdb = os.path.join(out_dir, exe[:-4] + ".pdb")
    if os.path.isfile(pdb):
        shutil.copy2(pdb, stage)
    if os.path.isfile(os.path.join(src, "LICENSE")):
        shutil.copy2(os.path.join(src, "LICENSE"), os.path.join(lic, f"{label}-LICENSE.txt"))
    lines = [f"{label} {commit}", f"repo {repo}"]
    if family == "xcl":
        d = dxc()
        for dll in ("dxcompiler.dll", "dxil.dll"):
            shutil.copy2(os.path.join(d["dir"], "bin", "x64", dll), stage)
        for name in os.listdir(d["dir"]):
            if name.upper().startswith("LICENSE"):
                shutil.copy2(os.path.join(d["dir"], name), os.path.join(lic, f"DXC-{name}.txt"))
        shutil.copy2(opus_dll(), os.path.join(stage, "opus.dll"))
        copying = os.environ.get("OPUS_COPYING", "/opt/opus/COPYING")
        if os.path.isfile(copying):
            shutil.copy2(copying, os.path.join(lic, "opus-COPYING.txt"))
        lines.append(d["version"])
    with open(os.path.join(stage, commit_file), "w") as f:
        f.write("\n".join(lines) + "\n")


def pack(stage, dest):
    def plain(ti):
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        ti.mtime = 0
        return ti
    with tarfile.open(dest, "w:gz") as t:
        for name in sorted(os.listdir(stage)):
            t.add(os.path.join(stage, name), arcname=name, filter=plain)
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest(), os.path.getsize(dest)


def scan(stage, repo, commit):
    out = os.path.join(OUT, "vt.json")
    env = dict(os.environ, VT_STATE_FILE=os.path.join(OUT, "vt-state.json"))
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "virustotal-scan.py"), stage, out,
                    "--repo", repo, "--commit", commit], check=True, env=env, timeout=3600)
    with open(out) as f:
        return json.load(f)


# -- the run -------------------------------------------------------------------------------------

def main():
    if not TOKEN and not DRY_RUN:
        sys.exit("GITHUB_TOKEN is not set (or set DRY_RUN=1)")
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT, mode=0o700, exist_ok=True)
    tracker = json.loads(http(TRACKER_URL, raw=True, headers={"Accept": "application/json"}))
    rel = release()
    prev = previous_manifest(rel)
    published = {(b.get("repo"), b.get("commit")): b for b in prev.get("builds", []) if b.get("file")}
    asset_names = {a["name"] for a in (rel or {}).get("assets", [])}

    cands = candidates(tracker, MIN_SCORE)
    log(f"{len(cands)} efforts with public code score {MIN_SCORE:g} or more: "
        + ", ".join(f"{c['name']} ({c['score']})" for c in cands))
    notes, builds, new_files = [], [], []
    built = 0
    for c in cands:
        note = {"repo": c["repo"], "name": c["name"], "score": c["score"], "family": None}
        notes.append(note)
        try:
            found, why = inspect(c)
        except Exception as e:
            found, why = None, f"GitHub lookup failed: {e}"
        if not found:
            note["result"] = why
            log(f"{c['name']}: skipped, {why}")
            continue
        family, branch, commit = found
        note["family"] = family
        old = published.get((c["repo"], commit))
        if old and old["file"] in asset_names:
            builds.append(dict(old, score=c["score"], effort=c["name"]))
            note["result"] = f"unchanged ({branch} @ {commit[:12]})"
            log(f"{c['name']}: {commit[:12]} already published")
            continue
        if built >= MAX_NEW:
            note["result"] = f"waits for the next run (at most {MAX_NEW} builds per run)"
            keep = next((b for b in prev.get("builds", []) if b.get("repo") == c["repo"] and b["file"] in asset_names), None)
            if keep:
                builds.append(dict(keep, score=c["score"], effort=c["name"]))
            continue
        built += 1
        src = os.path.join(WORK, "src")
        stage = os.path.join(OUT, "stage")
        try:
            log(f"{c['name']}: building {c['repo']} {branch} @ {commit[:12]} ({family})")
            checkout(c["repo"], commit, src)
            out_dir = build_tree(family, src)
            collect(family, c["repo"], commit, src, out_dir, stage)
            vt = scan(stage, c["repo"], commit)
            if vt.get("verdict") == "flagged":
                note["result"] = "VirusTotal flagged the build; not published"
                log(f"{c['name']}: flagged by VirusTotal, not published")
                continue
            file = archive_name(family, c["repo"], commit)
            path = os.path.join(OUT, file)
            sha, size = pack(stage, path)
            new_files.append(path)
            builds.append({"family": family, "file": file, "sha256": sha, "size": size, "commit": commit,
                           "repo": c["repo"], "effort": c["name"], "score": c["score"], "virustotal": vt})
            note["result"] = f"built ({branch} @ {commit[:12]}, VirusTotal {vt.get('verdict')})"
            log(f"{c['name']}: built {file} ({size} bytes)")
        except Exception as e:
            note["result"] = f"build failed: {str(e).splitlines()[0][:300]}"
            log(f"{c['name']}: build failed\n{e}")
            keep = next((b for b in prev.get("builds", []) if b.get("repo") == c["repo"] and b["file"] in asset_names), None)
            if keep:
                builds.append(dict(keep, score=c["score"], effort=c["name"]))
                note["result"] += f"; keeping {keep['commit'][:12]}"
        finally:
            shutil.rmtree(src, ignore_errors=True)

    builds.sort(key=lambda b: -b["score"])
    best = {fam: next((b for b in builds if b["family"] == fam), None) for fam in FAMILIES}
    manifest = {
        "schema": 1,
        "published_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_url": f"https://github.com/{REPO}/releases/tag/{TAG}",
        "min_score": MIN_SCORE,
        "victory": best["victory"],
        "xcl": best["xcl"],
        "recommended": builds[0]["family"] if builds else None,
        "builds": builds,
        "candidates": [dict(n, result=n.get("result", "")) for n in notes],
    }
    mpath = os.path.join(OUT, "runtimes.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    if DRY_RUN:
        print(json.dumps(manifest, indent=2))
        return
    for path in new_files:  # archives before the manifest, so it never names a missing one
        upload(rel, path)
    upload(rel, mpath)
    keep = {b["file"] for b in builds} | {"runtimes.json"}
    for a in list(rel.get("assets", [])):
        if a["name"] not in keep:
            gh(f"repos/{REPO}/releases/assets/{a['id']}", method="DELETE")
            log(f"deleted {a['name']} (no longer in runtimes.json)")
    log(f"published {len(builds)} builds ({len(new_files)} new)")


if __name__ == "__main__":
    main()
