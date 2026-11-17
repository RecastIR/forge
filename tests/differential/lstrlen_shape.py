"""Require actual linked lstrlenA IAT calls and their guest continuations."""
import re
import subprocess
import sys

from build import iat_call_slot


def check_listing(pe, listing):
    base = int(re.search(r"^ImageBase\s+([0-9a-f]+)$", pe, re.M)[1], 16)
    descriptor = re.search(r"^ [0-9a-f]{8}\s+(?:[0-9a-f]{8} ){4}([0-9a-f]{8})\n\s*"
                           r"DLL Name: KERNEL32\.dll\n[^\n]+\n(.*?)\n\n", pe, re.M | re.S)
    if not descriptor:
        raise ValueError("missing ordinary KERNEL32 import descriptor")
    first = base + int(descriptor[1], 16)
    slots = {line.split()[2]: first + 8 * i for i, line in enumerate(descriptor[2].splitlines())}
    helper = int(re.search(r"^([0-9a-f]+) <string_length_helper>:$", listing, re.M)[1], 16)
    direct_calls = []
    for symbol, expected in (("string_length", ["SetLastError", "lstrlenA", "lstrlenA", "GetLastError"]),
                             ("string_length_helper", ["lstrlenA"])):
        body = listing.split(f" <{symbol}>:\n", 1)[1].split("\n\n", 1)[0]
        calls = []
        instructions = []
        for line in body.splitlines():
            fields = line.strip().split("\t", 2)
            if len(fields) != 3:
                continue
            address, raw, instruction = fields
            raw = bytes.fromhex(raw)
            instructions.append(instruction)
            if instruction.startswith("call") and raw[:1] == b"\xe8":
                direct_calls.append(int(address.rstrip(":"), 16) + len(raw) +
                                    int.from_bytes(raw[1:], "little", signed=True))
            if instruction.startswith("call") and raw[:1] != b"\xe8":
                slot = iat_call_slot(raw, int(address.rstrip(":"), 16))
                name = next((name for name, value in slots.items() if value == slot), None)
                if name is None:
                    raise ValueError("unproven lstrlen fixture IAT call")
                calls.append(name)
        if calls != expected or not any(op.startswith("ret") for op in instructions):
            raise ValueError(f"missing imported call or continuation in {symbol}")
    if direct_calls != [helper]:
        raise ValueError("missing nested string helper")


def check(objdump, path):
    check_listing(subprocess.check_output([objdump, "-p", path], text=True),
                  subprocess.check_output([objdump, "-Mintel", "-d", path], text=True))


if __name__ == "__main__":
    check(*sys.argv[1:])
