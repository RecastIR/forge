import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SUITE, FORGE, fixture_dir, READOBJ = sys.argv[1:]
FIXTURES = Path(fixture_dir)


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()

    def copy(self, name, dest=None):
        dest = self.dir / (dest or name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / name, dest)
        return dest

    def invoke(self, *args, code=0, **options):
        p = subprocess.run([FORGE, *args], capture_output=True, timeout=15, **options)
        self.assertEqual(p.returncode, code, (args, p.stderr.decode(errors="replace")))
        self.assertNotIn(b"Sanitizer", p.stderr)
        self.assertNotIn(b"runtime error:", p.stderr)
        return p

    def report(self, image, *args, code=0):
        p = self.invoke("inspect", image, *args, "--format", "json", code=code)
        r = json.loads(p.stdout)
        self.assertEqual(r["schema_version"], 1)
        self.assertEqual(r["inspection"], {"status": "completed", "root_module": 0})
        for diagnostic in r["diagnostics"]:
            self.assertIn(diagnostic["code"].encode(), p.stderr)
        return r

    def readobj(self, name, *flags):
        return subprocess.check_output([READOBJ, *flags, FIXTURES / name], text=True)
