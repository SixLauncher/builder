#!/usr/bin/env python3
"""Scans a runtime build on VirusTotal and writes the result as JSON.

Usage: virustotal-scan.py DIR OUT_JSON --repo OWNER/NAME --commit SHA

Every executable under DIR is looked up by SHA-256 first. Executables are recognised by
their first bytes, not their names, so the common kinds are all covered on Linux:
Windows PE (.exe, .dll, .sys), ELF (Linux programs, .so libraries, AppImages), Debian
packages (.deb), MSI installers, Mach-O, and scripts with a #! line. Only a file VirusTotal
has not seen is uploaded (these are builds of public source code, made by this workflow),
and its analysis is waited for. The key comes from VT_API_KEY; without it the result says
"skipped".

A free key allows 4 requests a minute, 500 a day and 15,500 a month, for non-commercial
use only. So:
  * requests are at least VT_GAP_SECONDS (16) apart, also across the runs of one job: the
    time of the last request is kept in VT_STATE_FILE when it is set;
  * one job makes at most VT_MAX_REQUESTS (60) requests, counted in the same file; past
    that, the files left are reported "pending" instead of asked about;
  * an analysis is polled once a minute for at most VT_WAIT_SECONDS (600);
  * a 429 (quota) answer waits a minute and is retried twice, then gives up.
The workflow only scans a backend whose commit changed, so a typical night costs about
15 requests per backend and an unchanged one costs none.

The JSON names the repository and commit the build came from, so the result stays tied
to that exact build:

  {"repo", "commit", "scanned_at", "verdict": "clean" | "flagged" | "pending" | "skipped" | "error",
   "files": [{"name", "sha256", "malicious", "suspicious", "harmless", "undetected", "engines", "link", "state"}]}

The exit code is 0 whatever the verdict; the caller decides what a verdict means.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

API = os.environ.get("VT_API", "https://www.virustotal.com/api/v3")
GAP = float(os.environ.get("VT_GAP_SECONDS", "16"))        # 4 requests a minute
WAIT = float(os.environ.get("VT_WAIT_SECONDS", "600"))      # how long to wait for an analysis
POLL = float(os.environ.get("VT_POLL_SECONDS", "60"))       # how often to ask about it
MAX_REQUESTS = int(os.environ.get("VT_MAX_REQUESTS", "60"))  # per job, across runs
STATE = os.environ.get("VT_STATE_FILE", "")
DIRECT_UPLOAD = 32 << 20


class OutOfBudget(Exception):
    pass


def load_state():
    try:
        with open(STATE) as f:
            s = json.load(f)
        return float(s.get("last", 0)), int(s.get("count", 0))
    except (OSError, ValueError):
        return 0.0, 0


def save_state():
    if STATE:
        with open(STATE, "w") as f:
            json.dump({"last": _last, "count": _count}, f)


# Wall-clock time, so the gap holds across the runs of one job.
_last, _count = load_state() if STATE else (0.0, 0)


def request(key, method, url, body=None, headers=None, retries=2):
    """Returns (status, parsed JSON or None)."""
    global _last, _count
    if _count >= MAX_REQUESTS:
        raise OutOfBudget()
    pause = _last + GAP - time.time()
    if pause > 0:
        time.sleep(pause)
    req = urllib.request.Request(url, data=body, method=method, headers={"x-apikey": key, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            status, data = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, data = e.code, e.read()
    finally:
        _last = time.time()
        _count += 1
        save_state()
    if status == 429 and retries > 0:
        print("VirusTotal quota reached (429); waiting a minute", file=sys.stderr)
        time.sleep(60)
        return request(key, method, url, body, headers, retries - 1)
    try:
        return status, json.loads(data) if data else None
    except ValueError:
        return status, None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stats_of(report):
    return ((report or {}).get("data") or {}).get("attributes", {}).get("last_analysis_stats") or {}


def upload(key, path):
    size = os.path.getsize(path)
    url = f"{API}/files"
    if size > DIRECT_UPLOAD:
        status, j = request(key, "GET", f"{API}/files/upload_url")
        if status != 200 or not j or not j.get("data"):
            raise RuntimeError(f"upload_url: HTTP {status}")
        url = j["data"]
    boundary = uuid.uuid4().hex
    with open(path, "rb") as f:
        data = f.read()
    name = os.path.basename(path).replace('"', "")
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    status, j = request(key, "POST", url, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    if status != 200 or not j:
        raise RuntimeError(f"upload: HTTP {status}")
    return j["data"]["id"]


def wait_for(key, analysis):
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        status, j = request(key, "GET", f"{API}/analyses/{analysis}")
        if status == 200 and ((j or {}).get("data") or {}).get("attributes", {}).get("status") == "completed":
            return True
        time.sleep(max(0.0, POLL - GAP))
    return False


def scan_file(key, path):
    digest = sha256(path)
    entry = {"name": os.path.basename(path), "sha256": digest, "link": f"https://www.virustotal.com/gui/file/{digest}"}
    try:
        return scan_known(key, path, entry)
    except OutOfBudget:
        print(f"{entry['name']}: request budget for this job used up; left pending", file=sys.stderr)
        entry.update(malicious=0, suspicious=0, harmless=0, undetected=0, engines=0, state="pending")
        return entry


def scan_known(key, path, entry):
    digest = entry["sha256"]
    status, report = request(key, "GET", f"{API}/files/{digest}")
    if status == 404:
        analysis = upload(key, path)
        print(f"{entry['name']}: uploaded, analysis {analysis}", file=sys.stderr)
        if wait_for(key, analysis):
            status, report = request(key, "GET", f"{API}/files/{digest}")
    if status not in (200, 404):
        raise RuntimeError(f"{entry['name']}: HTTP {status}")
    s = stats_of(report if status == 200 else None)
    for k in ("malicious", "suspicious", "harmless", "undetected"):
        entry[k] = int(s.get(k, 0))
    entry["engines"] = sum(entry[k] for k in ("malicious", "suspicious", "harmless", "undetected"))
    entry["state"] = "flagged" if entry["malicious"] else ("clean" if entry["engines"] else "pending")
    return entry


MAGIC = [
    (b"MZ", "pe"),                      # Windows .exe / .dll / .sys
    (b"\x7fELF", "elf"),                # Linux programs, .so, AppImage
    (b"!<arch>\ndebian", "deb"),         # Debian package
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "msi"),  # Windows Installer
    (b"\xcf\xfa\xed\xfe", "macho"),      # Mach-O 64-bit
    (b"\xca\xfe\xba\xbe", "macho"),      # Mach-O universal
    (b"#!", "script"),
]


def kind_of(path):
    """The executable kind of `path` from its first bytes, or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    for magic, kind in MAGIC:
        if head.startswith(magic):
            return kind
    return None


def executables(directory):
    """(relative path, kind) of every executable under `directory`, sorted; symlinks skipped."""
    found = []
    for root, dirs, names in os.walk(directory):
        dirs.sort()
        for n in names:
            full = os.path.join(root, n)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            kind = kind_of(full)
            if kind:
                found.append((os.path.relpath(full, directory), kind))
    return sorted(found)


def scan(directory, key):
    files = []
    for rel, kind in executables(directory):
        entry = scan_file(key, os.path.join(directory, rel))
        entry["name"], entry["kind"] = rel, kind
        files.append(entry)
    states = {f["state"] for f in files}
    verdict = "flagged" if "flagged" in states else ("pending" if "pending" in states or not files else "clean")
    return verdict, files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("out")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--commit", required=True)
    a = ap.parse_args()
    result = {"repo": a.repo, "commit": a.commit,
              "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        result.update(verdict="skipped", files=[], note="no VT_API_KEY secret")
    else:
        try:
            result["verdict"], result["files"] = scan(a.dir, key)
        except Exception as e:  # the build is published as unchecked rather than not at all
            result.update(verdict="error", files=[], note=str(e))
    with open(a.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
