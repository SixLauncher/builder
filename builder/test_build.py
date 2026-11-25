import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build  # noqa: E402

PLAYABLE = {"loads": 1, "boots": 1, "menu": 1, "world": 1, "playable": 1}


def effort(name, repo, **gta):
    return {"id": name.lower(), "name": name, "repo": repo, "gta": gta}


class Score(unittest.TestCase):
    def test_like_the_site(self):
        # ZETTROX on 2026-11-25: stability as a number. 50 + 50 * (0.035 + 0.075 + 0.2 * 2/30 + 0.16)
        z = effort("ZETTROX", "Zettrox/ztrx", **PLAYABLE, story=0.1, render=0.3, fps=2, stability=0.8)
        self.assertAlmostEqual(build.score(z), 64.1667, places=3)
        # A word: rarely = 0.8.
        w = effort("W", "a/b", **PLAYABLE, story=0.1, render=0.3, fps=2, stability="rarely")
        self.assertAlmostEqual(build.score(w), build.score(z))
        # Half way from Menus (30) to In the world (40), as status.rs's test.
        self.assertEqual(build.score(effort("XCL", "xcl-dev/xcl", loads=1, boots=1, menu=1, world=0.5)), 35.0)
        # Groundwork only: 10 * (0.2 * 1 + 0.32 * 0.5) = 3.6
        e = {"name": "E", "repo": "a/b", "gta": {}, "groundwork": {"loader": 1, "graphics": 0.5}}
        self.assertAlmostEqual(build.score(e), 3.6)
        self.assertEqual(build.score({"gta": {"loads": 1, "boots": "x", "fps": None}}), 10.0)

    def test_candidates(self):
        tracker = {"efforts": [
            effort("Uilian", "uiliannn/VItoriaBr", **PLAYABLE, story=0.1, render=0.2, fps=4, stability=0.4),
            effort("ZETTROX", "Zettrox/ztrx", **PLAYABLE, story=0.1, render=0.3, fps=2, stability=0.8),
            effort("closed", None, **PLAYABLE, render=0.8, fps=3),
            effort("hyphennn", "fxceless/victory-fork", **PLAYABLE, render=0.7, fps=3, stability="unknown"),
            effort("VIctory", "Marvisak/VIctory", loads=1, boots=1, menu=1, world=1),
            dict(effort("gone", "x/y", **PLAYABLE, story=1, render=1, fps=60, stability="stable"), nuked={"at": "2026-11-23"}),
        ]}
        got = [(c["name"], c["score"]) for c in build.candidates(tracker, 59)]
        self.assertEqual(got, [("ZETTROX", 64.2), ("hyphennn", 59.8), ("Uilian", 59.6)])

    def test_archive_name_is_plain(self):
        name = build.archive_name("victory", "Zettrox/ztrx", "90b529f878a470fec9bf07b7be316bc769a12232")
        self.assertEqual(name, "victory-zettrox-ztrx-90b529f878a4.tar.gz")
        self.assertTrue(all(c.isalnum() or c in "._-" for c in name))


class Extras(unittest.TestCase):
    def test_only_what_portwatch_lists_at_the_score(self):
        tracker = {"efforts": [
            effort("ZETTROX", "Zettrox/ztrx", **PLAYABLE, story=0.1, render=0.3, fps=2, stability=0.8),
            effort("Mac", "x/Mac", **PLAYABLE, story=0.1, render=0.3, fps=2, stability=0.8),
            effort("Low", "a/low", loads=1),
        ]}
        extras = [{"repo": "x/mac", "name": "Mac", "platform": "macos"},
                  {"repo": "a/low", "name": "Low"},
                  {"repo": "n/unlisted", "name": "Unlisted"}]
        got, waiting = build.with_extras(build.candidates(tracker, 59), extras)
        self.assertEqual([(c["name"], c.get("platform")) for c in got], [("Mac", "macos"), ("ZETTROX", None)])
        self.assertEqual([x["repo"] for x in waiting], ["a/low", "n/unlisted"])

    def test_the_real_list(self):
        self.assertEqual([x["repo"] for x in build.EXTRA],
                         ["romainhedouin/VIctory-macOS", "romainhedouin/VIctory-Belobug-AMD"])
        self.assertTrue(all(build.REPO_RE.match(x["repo"]) for x in build.EXTRA))


class Supplied(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.src = self.tmp.name
        build._supplied.clear()
        self.orig = build.http
        self.geteuid = build.os.geteuid
        build.os.geteuid = lambda: 1000  # no chown in tests

    def tearDown(self):
        build.http = self.orig
        build.os.geteuid = self.geteuid
        self.tmp.cleanup()

    def test_fills_a_missing_table_and_checks_it(self):
        item = build.SUPPLIED[0]
        os.makedirs(os.path.join(self.src, os.path.dirname(item["path"])))
        build.http = lambda *a, **k: b"not the table"
        with self.assertRaises(RuntimeError):
            build.supply_missing(self.src)
        self.assertFalse(os.path.exists(os.path.join(self.src, item["path"])))
        good = os.environ.get("BCPACK_TABLE")
        if not good:
            self.skipTest("set BCPACK_TABLE to the real file to check the SHA-256")
        build.http = lambda *a, **k: open(good, "rb").read()
        self.assertEqual(build.supply_missing(self.src), [item["path"]])
        self.assertEqual(build.supply_missing(self.src), [], "already there: left alone")

    def test_only_where_the_folder_exists(self):
        build.http = lambda *a, **k: self.fail("no download for a tree without the folder")
        self.assertEqual(build.supply_missing(self.src), [])


class Flagged(unittest.TestCase):
    def scan(self, **states):
        return {"verdict": "flagged", "files": [
            {"name": n, "sha256": n, "state": st, "malicious": 2 if st == "flagged" else 0, "engines": 69}
            for n, st in states.items()]}

    def test_an_extra_is_dropped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as stage:
            for n in ("victory.exe", "victory-play.exe", "victory-play.pdb", "victory-warm.exe"):
                open(os.path.join(stage, n), "w").close()
            vt = build.drop_flagged_extras("victory", self.scan(**{
                "victory.exe": "clean", "victory-play.exe": "flagged", "victory-warm.exe": "clean"}), stage)
            self.assertEqual(vt["verdict"], "clean")
            self.assertEqual([f["name"] for f in vt["files"]], ["victory.exe", "victory-warm.exe"])
            self.assertEqual([d["name"] for d in vt["dropped"]], ["victory-play.exe"])
            self.assertEqual(sorted(os.listdir(stage)), ["victory-warm.exe", "victory.exe"])

    def test_the_main_program_keeps_the_build_out(self):
        self.assertIsNone(build.drop_flagged_extras("victory", self.scan(**{"victory.exe": "flagged", "a.exe": "clean"}), "/nonexistent"))
        self.assertIsNone(build.drop_flagged_extras("xcl", self.scan(**{"xcl.exe": "clean", "opus.dll": "flagged"}), "/nonexistent"))

    def test_still_pending_stays_pending(self):
        import tempfile
        with tempfile.TemporaryDirectory() as stage:
            vt = build.drop_flagged_extras("victory", self.scan(**{"victory.exe": "pending", "x.exe": "flagged"}), stage)
            self.assertEqual(vt["verdict"], "pending")


if __name__ == "__main__":
    unittest.main()
