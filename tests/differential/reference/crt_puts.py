"""Raw redirected observations of the SDK-free legacy puts executables."""
import hashlib
import json
import os
from pathlib import Path
import re
from functools import cache

from crt_streams import summarize

@cache
def baseline():
    return json.loads(Path(__file__).with_name("crt-puts.json").read_bytes())


VARIANTS = tuple(name.removeprefix("crt-puts-").removesuffix(".exe") for name in baseline()["inputs"])


def check_input(pe):
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    if digest != baseline()["inputs"][pe.name]:
        raise ValueError(f"unexpected {pe.name} checksum {digest}")
    return digest


def check_wine_fault(variant, stdout, stderr):
    report = re.match(rb"Unhandled exception: page fault on read access to 0x([0-9a-f]+) in 64-bit code", stdout)
    notice = re.fullmatch(rb"wine: Unhandled page fault on read access to ([0-9A-Fa-f]+) at address "
                          rb"[0-9A-Fa-f]+ \(thread [0-9A-Fa-f]+\), starting debugger\.\.\.\n", stderr)
    registers, _, remainder = stdout.partition(b"\nStack dump:\n")
    stack, _, trace = remainder.partition(b"Backtrace:\n")
    rcx = re.search(rb"\brcx:([0-9a-f]+)\b", registers)
    if not report or not notice or not rcx or b"Q\r\n" in stdout:
        raise ValueError(f"{variant}: unexpected Wine diagnostic boundary")

    # The producer-hashed PEs have distinct return RVAs for their final puts call.
    rva = b"1048" if variant == "fault" else b"102d"
    caller = re.search(rb"(?m)^ +\d+ 0x[0-9a-f]+ puts\+0x[0-9a-f]+\(.* in msvcrt .*\n"
                       rb" +\d+ 0x([0-9a-f]+) in crt-puts-" + variant.encode() +
                       rb" \(\+0x" + rva + rb"\)", trace)
    if not re.match(rb"=>0 0x[0-9a-f]+ strlen\(.* in msvcrt ", trace) or not caller:
        raise ValueError(f"{variant}: unexpected Wine call site")

    # CALL pushes the return PC eight bytes below the fixture's pre-call RSP.
    slots = [int(base, 16) + 8 * index
             for base, words in re.findall(rb"(?m)^0x([0-9a-f]+): +([0-9a-f ]+)$", stack)
             for index, word in enumerate(words.split()) if int(word, 16) == int(caller[1], 16)]
    if len(slots) != 1:
        raise ValueError(f"{variant}: missing or ambiguous Wine return slot")
    expected = slots[0] + 8 + 0x40000000 if variant == "fault" else 0
    if any(int(value, 16) != expected for value in (report[1], notice[1], rcx[1])):
        raise ValueError(f"{variant}: unexpected Wine fault address")


def observation(backend, variant, status, stdout, stderr):
    if backend == "wine" and variant in ("fault", "null"):
        check_wine_fault(variant, stdout, stderr)
        return dict(status=status, stdout="Wine read fault", stderr="Wine debugger notice")
    return dict(status=status, stdout=summarize(stdout), stderr=summarize(stderr))


def check_observation(backend, variant, mode, status, stdout, stderr):
    key = variant if mode in ("pipe", "file") else f"{variant}-{mode}"
    row = observation(backend, variant, status, stdout, stderr)
    wanted = baseline()[backend][key]
    if row != wanted:
        raise ValueError(f"puts {backend} {variant}-{mode}: observed {row}, expected {wanted}")
    return row


def expected_modes(backend):
    modes = {variant: ["file", "pipe"] for variant in VARIANTS}
    cases = baseline()[backend]
    if not modes.keys() <= cases.keys():
        raise ValueError(f"{backend}: missing ordinary puts observations {modes.keys() - cases.keys()}")
    for case in cases.keys() - modes.keys():
        variant, mode = case.split("-", 1)
        if mode not in ("readonly", "broken", "missing", "full", "short", "prefix"):
            raise ValueError(f"{backend}: unknown puts observation {case}")
        modes[variant].append(mode)
    return modes


def check_coverage(observations, expected):
    keys = {f"{variant}-{mode}" for variant, modes in expected.items() for mode in modes}
    if observations.keys() != keys:
        raise ValueError(f"puts observations: missing {keys - observations.keys()}, "
                         f"unexpected {observations.keys() - keys}")


def observe_puts(directory, destination, wine, declared, launch, windows_failure):
    backend = "wine" if wine else "windows"
    observations = {}
    expected = expected_modes(backend)
    for variant, modes in expected.items():
        pe = (directory / f"crt-puts-{variant}.exe").resolve()
        digest = check_input(pe)
        if digest != declared[pe.name]:
            raise ValueError(f"unexpected producer checksum for {pe.name}")
        for mode in sorted(modes):
            key = f"{variant}-{mode}"
            prefix = destination / ("puts-" + key)
            out, err = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
            if mode == "pipe":
                result = launch(pe, [], wine, capture_output=True)
                out.write_bytes(result.stdout)
                err.write_bytes(result.stderr)
            elif mode == "file":
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=stdout, stderr=stderr)
            elif mode == "readonly":
                with pe.open("rb") as reader, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=reader, stderr=stderr)
                out.write_bytes(b"")
            elif wine and mode == "broken":
                read, write = os.pipe()
                os.close(read)
                with os.fdopen(write, "wb") as writer, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=writer, stderr=stderr)
                out.write_bytes(b"")
            else:
                with err.open("wb") as stderr:
                    result, output = windows_failure(pe, [], mode, stderr)
                out.write_bytes(output)
            stdout, stderr = out.read_bytes(), err.read_bytes()
            status = result.returncode & 0xffffffff
            row = check_observation(backend, variant, mode, status, stdout, stderr)
            observations[key] = row
            print(f"puts {backend} {key} {digest} {row}", flush=True)
    check_coverage(observations, expected)
    (destination / "puts-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
