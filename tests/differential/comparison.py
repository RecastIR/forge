"""Exact observable behavior of a completed run, independent of its execution backend."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Observation:
    exit_code: int
    stdout: bytes
    stderr: bytes

    @classmethod
    def from_manifest(cls, expected):
        return cls(expected["exit_code"], expected["stdout"].encode(), expected["stderr"].encode())


def differences(expected, actual):
    errors = []
    if expected.exit_code != actual.exit_code:
        errors.append(dict(field="exit_code", expected=expected.exit_code, actual=actual.exit_code))
    for name in ("stdout", "stderr"):
        wanted, got = getattr(expected, name), getattr(actual, name)
        if wanted == got:
            continue
        offset = next((i for i, (a, b) in enumerate(zip(wanted, got)) if a != b),
                      min(len(wanted), len(got)))
        window = slice(max(0, offset - 12), offset + 20)
        errors.append(dict(field=name, offset=offset, expected_size=len(wanted), actual_size=len(got),
                           expected=repr(wanted[window]), actual=repr(got[window])))
    return errors


def describe(error):
    if error["field"] == "exit_code":
        return f"exit-code mismatch: expected {error['expected']}, actual {error['actual']}"
    return (f"{error['field']} mismatch at byte {error['offset']}\n"
            f"  expected ({error['expected_size']} bytes): {error['expected']}\n"
            f"  actual   ({error['actual_size']} bytes): {error['actual']}")
