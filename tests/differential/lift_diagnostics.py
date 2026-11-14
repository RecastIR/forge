"""Validate the schema-v1 execution failure from one forge lift invocation."""
import json
from dataclasses import dataclass
from pathlib import Path
import re

from manifests import field, unique_keys


INSTRUCTION_FAILURES = {"LIFT_UNSUPPORTED_INSTRUCTION", "LIFT_UNSUPPORTED_REGISTER", "LIFT_UNSUPPORTED_PREFIX",
                        "LIFT_UNSUPPORTED_CONTROL_FLOW", "LIFT_UNDEFINED_REGISTER", "LIFT_UNDEFINED_FLAG"}
FAILURE_KINDS = {
    ("input", "io"): {"INPUT_OPEN", "INPUT_READ"},
    ("input", "internal"): {"INPUT_INTERNAL"},
    ("pe", "invalid_input"): {"INVALID_PE"},
    ("pe", "unsupported"): {"UNSUPPORTED_ARCHITECTURE"},
    ("pe", "internal"): {"PE_INTERNAL"},
    ("analysis", "internal"): {"ANALYSIS_INTERNAL"},
    ("entry", "invalid_input"): {"ENTRY_INVALID_START", "ENTRY_UNMAPPED_CODE"},
    ("entry", "unsupported"): {"ENTRY_DLL", "ENTRY_UNWIND_VERSION", "ENTRY_CHAINED_FRAGMENT",
                               "ENTRY_RELOCATION_OVERLAP"},
    ("entry", "internal"): {"ENTRY_INTERNAL"},
    ("lifting", "invalid_input"): {"LIFT_INVALID_ENCODING"},
    ("lifting", "unsupported"): {"LIFT_FUNCTION_SIZE", *INSTRUCTION_FAILURES},
    ("lifting", "internal"): {"LIFT_BACKEND_SETUP", "LIFTING_INTERNAL"},
    ("verification", "internal"): {"IR_VERIFICATION_FAILED", "VERIFICATION_INTERNAL"},
    ("publication", "io"): {"OUTPUT_CREATE", "OUTPUT_DESCRIPTOR", "OUTPUT_WRITE", "OUTPUT_CLOSE",
                            "OUTPUT_REPLACE"},
    ("publication", "internal"): {"PUBLICATION_INTERNAL"},
}


@dataclass(frozen=True)
class SelectedFunction:
    """Facts from successful AMD64 inspection and discovery of an eligible entry."""
    start: int
    end: int
    file_offset: int
    image_kind: str
    relocation_overlap: bool

    def entry_restriction(self):
        if self.image_kind == "dll":
            return "ENTRY_DLL"
        if self.relocation_overlap:
            return "ENTRY_RELOCATION_OVERLAP"
        if self.end - self.start > 64 * 1024:
            return "LIFT_FUNCTION_SIZE"
        return None


def context_rva(context, name):
    text = field(context, name, str)
    if not re.fullmatch(r"0x[0-9a-f]{1,8}", text):
        raise ValueError(f"invalid {name}")
    return int(text, 16)


def validate_context(context, stage, category, code, image, selected, ir):
    allowed = {"input", "entry_rva", "signature"}
    if "signature" in context and field(context, "signature", str) != "i64(i64,i64)":
        raise ValueError("diagnostic signature disagrees with the function harness")
    if code in INSTRUCTION_FAILURES or code == "LIFT_INVALID_ENCODING":
        allowed.add("block_rva")
        if "block_rva" in context:
            start = context_rva(context, "block_rva")
            if not selected.start <= start <= context_rva(context, "instruction_rva"):
                raise ValueError("basic block disagrees with the instruction location")
    if code == "LIFT_UNSUPPORTED_CONTROL_FLOW":
        allowed.add("branch_target")
        if "branch_target" in context:
            target = field(context, "branch_target", int)
            if not -(1 << 31) <= target < (1 << 32) + (1 << 31):
                raise ValueError("invalid direct branch destination")
    if stage in ("pe", "entry", "lifting", "verification"):
        allowed.add("file_offset")
    if stage in ("entry", "lifting", "verification"):
        allowed.add("end_rva")
    if stage == "publication":
        allowed.add("output")
        if field(context, "output", str) != str(ir):
            raise ValueError("diagnostic disagrees with the output path")
    if category == "unsupported":
        restriction = selected.entry_restriction()
        if code != restriction and (restriction is not None or code not in INSTRUCTION_FAILURES):
            raise ValueError("capability diagnostic contradicts inspection or discovery")
    if code in INSTRUCTION_FAILURES:
        allowed.update(("instruction_rva", "bytes", "opcode"))
    elif code == "LIFT_INVALID_ENCODING":
        allowed.update(("instruction_rva", "bytes"))
    if context.keys() - allowed:
        raise ValueError("unexpected context fields for this diagnostic")
    entry = context_rva(context, "entry_rva")
    if field(context, "input", str) != str(image) or entry != selected.start:
        raise ValueError("diagnostic disagrees with the requested image or RVA")
    if "end_rva" in context and context_rva(context, "end_rva") != selected.end:
        raise ValueError("diagnostic disagrees with the discovered function end")
    offset = selected.file_offset
    if "instruction_rva" in context:
        instruction = context_rva(context, "instruction_rva")
        if not entry <= instruction < selected.end:
            raise ValueError("instruction RVA outside the discovered function range")
        offset += instruction - entry
    elif "opcode" in context or "bytes" in context:
        raise ValueError("instruction detail without an instruction RVA")
    if "opcode" in context and not field(context, "opcode", str).strip().encode("utf-8"):
        raise ValueError("empty opcode")
    if "file_offset" in context:
        supplied = field(context, "file_offset", int)
        if not 0 <= supplied <= 0xffffffffffffffff:
            raise ValueError("invalid file offset")
        if stage in ("entry", "lifting", "verification") and supplied != offset:
            raise ValueError("file offset disagrees with the inspected section")
    if "bytes" in context:
        text = field(context, "bytes", str)
        if not re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", text):
            raise ValueError("invalid instruction bytes")
        encoded = bytes.fromhex(text)
        if instruction + len(encoded) > selected.end:
            raise ValueError("instruction bytes extend beyond the diagnostic function range")
        with Path(image).open("rb") as source:
            source.seek(offset)
            if source.read(len(encoded)) != encoded:
                raise ValueError("instruction bytes disagree with the PE snapshot")


def parse_diagnostic(raw, image, selected, ir):
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("expected one newline-terminated JSON record")
    try:
        diagnostic = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except RecursionError as error:
        raise ValueError("excessively nested JSON record") from error
    if field(diagnostic, "schema_version", int) != 1:
        raise ValueError("unsupported diagnostic schema version")
    if diagnostic.keys() != {"schema_version", "stage", "category", "code", "message", "context"}:
        raise ValueError("unexpected diagnostic fields")
    kind = field(diagnostic, "stage", str), field(diagnostic, "category", str)
    if field(diagnostic, "code", str) not in FAILURE_KINDS.get(kind, ()):
        raise ValueError("unrecognized diagnostic stage, category and code combination")
    message = field(diagnostic, "message", str)
    if not message.strip():
        raise ValueError("empty diagnostic message")
    # Escaped unpaired surrogates can survive JSON parsing but cannot be reported as UTF-8.
    message.encode("utf-8")
    validate_context(field(diagnostic, "context", dict), *kind, diagnostic["code"], image, selected, ir)
    return diagnostic
