"""Run the original console probes through capture.exe and preserve every observation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine", help="absolute path to the pinned Wine 8 executable")
    parser.add_argument("--sweep", action="store_true", help="measure CRT IDs 0 through 256, 32767 and 2147483647")
    options = parser.parse_args()
    root = Path("raw")
    root.mkdir()
    aggregate = {"environment": {}, "pe_sha256": {}, "cases": {}, "error_id_sweep": {}}
    env = aggregate["environment"]
    env["host"] = platform.platform()
    pefiles = sorted(Path.cwd().glob("*.exe"))
    aggregate["pe_sha256"] = {p.name: digest(p) for p in pefiles}
    if options.wine:
        env["wine"] = subprocess.check_output([options.wine, "--version"], text=True).strip()
        env["image_id"] = os.environ.get("FORGE_REFERENCE_IMAGE")
        env["docker_host_arch"] = os.environ.get("FORGE_DOCKER_ARCH")
        startup = [options.wine, r".\capture.exe"]
    else:
        startup = [str(Path("capture.exe").resolve())]
        dll = Path(os.environ["SystemRoot"]) / "System32" / "msvcrt.dll"
        env.update(dll=str(dll), dll_sha256=digest(dll), architecture=os.environ.get("PROCESSOR_ARCHITECTURE"),
                   image=os.environ.get("ImageOS"), image_version=os.environ.get("ImageVersion"),
                   actions_run=os.environ.get("GITHUB_RUN_ID"), actions_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"))
        if sys.platform == "win32":
            import ctypes
            env["user_ui_language"] = ctypes.windll.kernel32.GetUserDefaultUILanguage()
    errors = []

    def observe(label, program, mode, arguments=()):
        directory = root / f"{label}-{mode}"
        terminal = bool(options.wine and mode.startswith("console"))
        capture_mode = mode.replace("console", "terminal") if terminal else mode
        command = [*startup, ".\\" + program, capture_mode, str(directory).replace("/", "\\"), *arguments]
        try:
            if terminal:
                # script(1) allocates a controlling terminal. OPOST is disabled so the host PTY
                # cannot further translate CR or LF. Its stdout contains terminal bytes only.
                import shlex
                tty_command = "stty -opost rows 30 cols 120 && exec " + shlex.join(command)
                result = subprocess.run(["script", "-qefc", tty_command, "/dev/null"],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            else:
                result = subprocess.run(command, timeout=120 if options.wine else 30, capture_output=True)
        except subprocess.TimeoutExpired:
            errors.append(f"{directory}: launcher timeout")
            return {"error": "launcher timeout"}
        if result.returncode:
            diagnostic = result.stderr.decode("utf-8", "backslashreplace")
            errors.append(f"{directory}: launcher exit {result.returncode}: {diagnostic}")
            return {"error": diagnostic, "launcher_exit": result.returncode}
        info = (directory / "observation.txt").read_text()
        match = re.search(r"^exit=(\d+)$", info, re.M)
        if not match:
            raise ValueError(f"missing exit status in {directory}")
        item = {"exit_code": int(match[1])}
        if terminal:
            (directory / "terminal.bin").write_bytes(result.stdout)
            item["terminal_hex"] = result.stdout.hex()
        for stream in ("stdout", "stderr"):
            path = directory / f"{stream}.bin"
            if path.exists():
                item[stream + "_hex"] = path.read_bytes().hex()
        for screen in ("before", "after"):
            path = directory / f"{screen}.utf16le"
            if path.exists():
                parsed = re.search(r"^" + screen + r"\.utf16le size=(\d+),(\d+) cursor=(\d+),(\d+)$", info, re.M)
                width, height, x, y = map(int, parsed.groups())
                cells = path.read_bytes().decode("utf-16-le")
                item[screen] = {"screen_size": [width, height], "cursor": [x, y], "raw_sha256": digest(path),
                                "text_rows": [row for start in range(0, len(cells), width)
                                              if (row := cells[start:start + width].rstrip(" "))]}
        return item

    for label in ("31", "8", "-1", "-2147483648", "unused"):
        program = f"crt-amsg-exit-{label}.exe"
        observations = aggregate["cases"][label] = {}
        for mode in ("pipe", "file", "invalid", "broken-pipe", "console-pipe", "console"):
            observations[mode] = observe(label, program, mode)
        print(label, observations["pipe"], flush=True)
    for label in ("marker-control", "marker-fatal"):
        aggregate["cases"][label] = {"pipe": observe(label, "crt-amsg-" + label + ".exe", "pipe")}
    aggregate["cases"]["console-control"] = {mode: observe("control", "capture.exe", mode, ["--marker"])
                                             for mode in ("pipe", "console-pipe", "console")}
    if options.sweep:
        for number in (*range(257), 32767, 2147483647):
            aggregate["error_id_sweep"][str(number)] = observe("sweep-" + str(number), "capture.exe",
                                                              "pipe", ["--error", str(number)])
    result = root / "results.json"
    result.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n")
    if errors:
        print("\n".join(errors), file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
