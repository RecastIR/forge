import json
from pathlib import Path
import tempfile
import unittest

from manifests import load_cases


class ManifestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.manifests = self.root / "manifests"
        self.manifests.mkdir()
        self.source = self.root / "fixtures" / "example.c"
        self.source.parent.mkdir()
        self.source.touch()
        self.case = dict(schema_version=1, id="example/basic", description="Test case",
                         source="fixtures/example.c", binary="example.exe", args=["ab"],
                         expected=dict(exit_code=0, stdout="value=1\n", stderr=""))

    def write(self, case, name="example.json"):
        (self.manifests / name).write_text(json.dumps(case), encoding="utf-8")

    def test_catalog(self):
        self.write(self.case)
        self.assertEqual(load_cases(self.root), [self.case])

    def test_required_types(self):
        for key in self.case:
            with self.subTest(missing=key):
                self.write({k: v for k, v in self.case.items() if k != key})
                with self.assertRaisesRegex(ValueError, key):
                    load_cases(self.root)
        for key, value in (("schema_version", True), ("schema_version", 2), ("id", "invalid"),
                           ("description", ""), ("args", "ab"), ("args", [7]), ("args", ["a\0b"])):
            with self.subTest(key=key, value=value):
                self.write(dict(self.case, **{key: value}))
                with self.assertRaisesRegex(ValueError, key):
                    load_cases(self.root)
        for key, value in (("exit_code", False), ("exit_code", -1), ("stdout", 1), ("stderr", [])):
            for expected in ({k: v for k, v in self.case["expected"].items() if k != key},
                             dict(self.case["expected"], **{key: value})):
                with self.subTest(expected=expected):
                    self.write(dict(self.case, expected=expected))
                    with self.assertRaisesRegex(ValueError, key):
                        load_cases(self.root)

    def test_duplicate_id_and_windows_filename(self):
        self.write(self.case)
        for overrides, message in ((dict(binary="other.exe"), "duplicate id"),
                                   (dict(id="example/other", binary="EXAMPLE.exe"), "duplicate binary")):
            with self.subTest(overrides=overrides):
                self.write(dict(self.case, **overrides), "other.json")
                with self.assertRaisesRegex(ValueError, message):
                    load_cases(self.root)

    def test_paths(self):
        for key, value in (("source", str(self.source)), ("source", "fixtures/../fixtures/example.c"),
                           ("source", "C:/fixtures/example.c"), ("source", "fixtures/absent.c"),
                           ("binary", "../example.exe"), ("binary", "/example.exe"),
                           ("binary", r"C:\example.exe"), ("binary", "CON.exe")):
            with self.subTest(key=key, value=value):
                self.write(dict(self.case, **{key: value}))
                with self.assertRaisesRegex(ValueError, "example.json"):
                    load_cases(self.root)
        self.source.unlink()
        outside = self.root / "elsewhere.c"
        outside.touch()
        self.source.symlink_to(outside)
        self.write(self.case)
        with self.assertRaisesRegex(ValueError, "outside"):
            load_cases(self.root)

    def test_unlisted_source(self):
        self.write(self.case)
        (self.source.parent / "forgotten.cpp").touch()
        with self.assertRaisesRegex(ValueError, "forgotten.cpp"):
            load_cases(self.root)


if __name__ == "__main__":
    unittest.main()
