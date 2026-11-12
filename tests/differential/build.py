"""Build and inspect the Windows fixtures inside the pinned Linux container."""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from manifests import SUITE, load_cases


def compile_suite(tree, config):
    subprocess.run(["cmake", "-S", SUITE / "fixtures", "-B", tree, "-G", "Ninja",
                    f"-DCMAKE_TOOLCHAIN_FILE={SUITE}/toolchain/windows-x64.cmake",
                    f"-DCMAKE_BUILD_TYPE={config.capitalize()}"], check=True)
    subprocess.run(["cmake", "--build", tree], check=True)
    return tree / "bin"


def inspect_pe(path, fixture_id):
    report = subprocess.check_output(["x86_64-w64-mingw32-objdump", "-p", path], text=True)
    characteristics = re.search(r"^Characteristics\s+(0x[0-9a-fA-F]+)$", report, re.MULTILINE)
    flags = int(characteristics[1], 16) if characteristics else 0
    if (not re.search(r"file format pei-x86-64$", report, re.MULTILINE)
            or not re.search(r"^Magic\s+020b\s+\(PE32\+\)", report, re.MULTILINE)
            or not flags & 0x0002 or flags & 0x2000):
        raise ValueError(f"{path}: expected an AMD64 PE32+ executable image")
    if not re.search(r"^Time/Date\s+Thu Jan\s+1 00:00:00 1970$", report, re.MULTILINE):
        raise ValueError(f"{path}: expected a zero COFF timestamp")

    tables = re.split(r"^\s*DLL Name: (\S+)\s*$", report, flags=re.MULTILINE)
    imports = {dll.lower(): table for dll, table in zip(tables[1::2], tables[2::2])}
    for dll in imports:
        if dll.startswith(("libgcc_s_", "libstdc++-", "libwinpthread-")):
            raise ValueError(f"{path}: unexpected MinGW runtime dependency {dll}")
    if fixture_id == "imports/kernel32":
        for name in ("GetCurrentProcessId", "GetModuleHandleW", "SetLastError", "GetLastError"):
            if not re.search(rf"^\s*[0-9a-f]+\s+\d+\s+{name}$",
                             imports.get("kernel32.dll", ""), re.MULTILINE):
                raise ValueError(f"{path}: missing KERNEL32.dll import {name}")


def publish(staged, target):
    # Both renames are on the export filesystem. Serialize writers and recover a
    # previous export if an interrupted invocation stopped between the renames.
    parent = os.open(target.parent, os.O_RDONLY)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        previous = target.with_name("." + target.name + ".previous")
        if previous.exists():
            if target.exists():
                shutil.rmtree(previous)
            else:
                previous.rename(target)
        if target.exists():
            target.rename(previous)
        try:
            staged.rename(target)
        except OSError:
            if previous.exists():
                previous.rename(target)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    finally:
        os.close(parent)


def build(config, cases, output):
    expected = {case["binary"]: case["id"] for case in cases}
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory(dir=output) as staging:
        first = compile_suite(Path(tmp) / "first", config)
        second = compile_suite(Path(tmp) / "second", config)
        for directory in (first, second):
            names = {p.name for p in directory.iterdir()}
            if names != expected.keys():
                raise ValueError(f"{directory}: missing {sorted(expected.keys() - names)}, "
                                 f"unexpected {sorted(names - expected.keys())}")

        staged = Path(staging) / config
        staged.mkdir()
        checksums = []
        for binary, fixture_id in sorted(expected.items()):
            path = first / binary
            data = path.read_bytes()
            if data != (second / binary).read_bytes():
                raise ValueError(f"{config}/{binary}: clean builds differ")
            inspect_pe(path, fixture_id)
            checksums.append(f"{hashlib.sha256(data).hexdigest()}  {binary}\n")
            shutil.copy2(path, staged / binary)
        (staged / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
        publish(staged, output / config)
        print(f"{config}: inspected {len(cases)} byte-reproducible PE executables.", flush=True)


if __name__ == "__main__":
    try:
        cases = load_cases()
        for config in sys.argv[1:]:
            build(config, cases, Path("/output"))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
