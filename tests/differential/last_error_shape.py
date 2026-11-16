"""Check the linked last-error fixture using the pinned MinGW objdump."""
import re
import subprocess
import sys


def check(objdump, path):
    pe = subprocess.check_output([objdump, "-p", path], text=True)
    base = int(re.search(r"^ImageBase\s+([0-9a-f]+)$", pe, re.M)[1], 16)
    descriptor = re.search(r"^ [0-9a-f]{8}\s+(?:[0-9a-f]{8} ){4}([0-9a-f]{8})\n\s*"
                           r"DLL Name: KERNEL32\.dll\n[^\n]+\n(.*?)\n\n", pe, re.M | re.S)
    if not descriptor:
        raise ValueError("missing ordinary KERNEL32.dll import descriptor")
    first = base + int(descriptor[1], 16)
    slots = {line.split()[2]: first + 8 * index for index, line in enumerate(descriptor[2].splitlines())}
    listing = subprocess.check_output([objdump, "-Mintel", "-d", path], text=True)

    def body(symbol):
        lines = listing.split(f" <{symbol}>:\n", 1)[1].split("\n\n", 1)[0].splitlines()
        rows = []
        for line in lines:
            address, raw, instruction = line.strip().split("\t", 2)
            rows.append((int(address.rstrip(":"), 16), bytes.fromhex(raw), instruction.split()[0]))
            if rows[-1][2] == "ret":
                return rows
        raise ValueError(f"missing RET in {symbol}")

    def target(row):
        address, raw, _ = row
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    root, helper = body("last_error"), body("last_error_set")
    if ([row[2] for row in root] != ["sub", "test", "jne", "call", "call", "mov", "call",
                                      "cmp", "je", "mov", "add", "ret"]
            or [row[2] for row in helper] != ["sub", "call", "add", "ret"]
            or root[3][1][:1] != b"\xe8" or target(root[3]) != helper[0][0]):
        raise ValueError("unexpected last-error guest call or continuation")
    for index, destination in ((2, 4), (8, 10)):
        address, raw, _ = root[index]
        if len(raw) != 2 or address + 2 + int.from_bytes(raw[1:], "little", signed=True) != root[destination][0]:
            raise ValueError("branch bypasses the last-error fixture contract")
    for row, api in ((root[4], "GetLastError"), (root[6], "GetLastError"), (helper[1], "SetLastError")):
        if len(row[1]) != 6 or row[1][:2] != b"\xff\x15" or target(row) != slots.get(api):
            raise ValueError(f"expected RIP-relative CALL through KERNEL32.dll!{api} slot")


if __name__ == "__main__":
    check(*sys.argv[1:])
