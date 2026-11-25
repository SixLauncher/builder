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


if __name__ == "__main__":
    unittest.main()
