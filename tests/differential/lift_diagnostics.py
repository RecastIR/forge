"""Validate the schema-v1 execution failure from one forge lift invocation."""
import json
from dataclasses import dataclass
from pathlib import Path
import re

from build import register_call_encoding
from manifests import field, unique_keys


INSTRUCTION_FAILURES = {"LIFT_IMAGE_MEMORY", "LIFT_UNSUPPORTED_INSTRUCTION", "LIFT_UNSUPPORTED_REGISTER", "LIFT_UNSUPPORTED_PREFIX",
                        "LIFT_UNSUPPORTED_CONTROL_FLOW", "LIFT_UNDEFINED_REGISTER", "LIFT_UNDEFINED_FLAG"}
INVALID_TARGETS = {"LIFT_INVALID_CALL_TARGET", "LIFT_INVALID_BRANCH_TARGET"}
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
    ("lifting", "invalid_input"): {"LIFT_INVALID_ENCODING", *INVALID_TARGETS},
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


def validate_context(context, stage, category, code, image, selected, ir, resolve_callee, register_target):
    allowed = {"input", "entry_rva", "signature"}
    owner = selected
    # A malformed fixup selected by a jump table has both PE and dispatch provenance.
    dispatch_pe = code == "INVALID_PE" and "instruction_rva" in context
    instruction_failure = (code in INSTRUCTION_FAILURES or code in INVALID_TARGETS
                           or code == "LIFT_INVALID_ENCODING" or dispatch_pe)
    if "function_rva" in context and (instruction_failure or code == "LIFT_FUNCTION_SIZE"):
        start = context_rva(context, "function_rva")
        if resolve_callee is None or start == selected.start or selected.entry_restriction():
            raise ValueError("diagnostic requires an independently discovered callee")
        if instruction_failure and "instruction_rva" not in context:
            raise ValueError("callee instruction diagnostic lacks the instruction RVA")
        if "call_site_rva" in context:
            owner = resolve_callee(start, context_rva(context, "caller_rva"), context_rva(context, "call_site_rva"))
            allowed.update(("caller_rva", "call_site_rva"))
        else:
            owner = resolve_callee(start)
        if owner.start != start:
            raise ValueError("diagnostic disagrees with the discovered callee")
        allowed.add("function_rva")
    if "signature" in context and field(context, "signature", str) != "i64(i64,i64)":
        raise ValueError("diagnostic signature disagrees with the function harness")
    if instruction_failure:
        allowed.add("block_rva")
        if "block_rva" in context:
            start = context_rva(context, "block_rva")
            if not owner.start <= start <= context_rva(context, "instruction_rva"):
                raise ValueError("basic block disagrees with the instruction location")
    if code == "LIFT_UNSUPPORTED_CONTROL_FLOW" or code in INVALID_TARGETS or (dispatch_pe and context.get("opcode") == "CALL64r"):
        allowed.add("branch_target")
        if "branch_target" in context:
            target = field(context, "branch_target", int)
            if not -(1 << 31) <= target < (1 << 32) + (1 << 31):
                raise ValueError("invalid branch destination")
    if code == "LIFT_INVALID_CALL_TARGET" and (context.get("opcode") not in {"CALL64pcrel32", "CALL64r"}
            or not {"instruction_rva", "branch_target", "bytes"} <= context.keys()):
        raise ValueError("invalid call target diagnostic lacks a resolved call site")
    if context.get("opcode") == "CALL64r" and "bytes" not in context:
        raise ValueError("register call diagnostic lacks instruction bytes")
    if code == "LIFT_INVALID_BRANCH_TARGET" and (context.get("opcode") != "JMP64r"
            or not {"instruction_rva", "branch_target", "bytes"} <= context.keys()):
        raise ValueError("invalid branch target diagnostic lacks a dispatch site")
    if dispatch_pe and (context.get("opcode") not in {"JMP64r", "CALL64r"} or "bytes" not in context):
        raise ValueError("PE diagnostic at a dispatch lacks register jump evidence")
    if stage in ("pe", "entry", "lifting", "verification"):
        allowed.add("file_offset")
    if stage in ("entry", "lifting", "verification") or dispatch_pe:
        allowed.add("end_rva")
    if stage == "publication":
        allowed.add("output")
        if field(context, "output", str) != str(ir):
            raise ValueError("diagnostic disagrees with the output path")
    if category == "unsupported":
        restriction = owner.entry_restriction()
        if code != restriction and (restriction is not None or code not in INSTRUCTION_FAILURES):
            raise ValueError("capability diagnostic contradicts inspection or discovery")
    if code in INSTRUCTION_FAILURES or code in INVALID_TARGETS or dispatch_pe:
        allowed.update(("instruction_rva", "bytes", "opcode"))
    elif code == "LIFT_INVALID_ENCODING":
        allowed.update(("instruction_rva", "bytes"))
    if context.get("opcode") == "CALL64m" and "iat_slot_rva" in context:
        allowed.update(("iat_slot_rva", "import_dll", "import_symbol"))
        for key in ("import_dll", "import_symbol"):
            if key in context and not field(context, key, str):
                raise ValueError("empty import identity")
        if "import_symbol" in context and "import_dll" not in context:
            raise ValueError("import symbol requires its module")
    if context.keys() - allowed:
        raise ValueError("unexpected context fields for this diagnostic")
    entry = context_rva(context, "entry_rva")
    if field(context, "input", str) != str(image) or entry != selected.start:
        raise ValueError("diagnostic disagrees with the requested image or RVA")
    if "end_rva" in context and context_rva(context, "end_rva") != selected.end:
        raise ValueError("diagnostic disagrees with the discovered function end")
    offset = owner.file_offset
    if "instruction_rva" in context:
        instruction = context_rva(context, "instruction_rva")
        if not owner.start <= instruction < owner.end:
            raise ValueError("instruction RVA outside the discovered function range")
        offset += instruction - owner.start
    elif "opcode" in context or "bytes" in context:
        raise ValueError("instruction detail without an instruction RVA")
    if "opcode" in context and not field(context, "opcode", str).strip().encode("utf-8"):
        raise ValueError("empty opcode")
    if "file_offset" in context:
        supplied = field(context, "file_offset", int)
        if not 0 <= supplied <= 0xffffffffffffffff:
            raise ValueError("invalid file offset")
        if (stage in ("entry", "lifting", "verification") or dispatch_pe) and supplied != offset:
            raise ValueError("file offset disagrees with the inspected section")
    if "bytes" in context:
        text = field(context, "bytes", str)
        if not re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", text):
            raise ValueError("invalid instruction bytes")
        encoded = bytes.fromhex(text)
        if instruction + len(encoded) > owner.end:
            raise ValueError("instruction bytes extend beyond the diagnostic function range")
        if code == "LIFT_INVALID_BRANCH_TARGET" or (dispatch_pe and context.get("opcode") == "JMP64r"):
            # JMP r64 is FF /4 with register addressing and one optional REX.
            body = encoded[1:] if 0x40 <= encoded[0] <= 0x4f else encoded
            if len(body) != 2 or body[0] != 0xff or body[1] & 0xf8 != 0xe0:
                raise ValueError("invalid register jump encoding")
        if "iat_slot_rva" in context:
            body = encoded[1:] if 0x40 <= encoded[0] <= 0x4f else encoded
            if (len(body) != 6 or body[:2] != b"\xff\x15"
                    or context_rva(context, "iat_slot_rva") != instruction + len(encoded)
                    + int.from_bytes(body[2:], "little", signed=True)):
                raise ValueError("IAT slot disagrees with RIP-relative CALL")
        if context.get("opcode") == "CALL64r":
            if not register_call_encoding(encoded, rejected_prefix=code == "LIFT_UNSUPPORTED_PREFIX"):
                raise ValueError("invalid register call encoding")
            if code == "LIFT_INVALID_CALL_TARGET" and (register_target is None
                    or register_target(owner, instruction) != context["branch_target"]):
                raise ValueError("call target disagrees with the reachable RIP-relative LEA")
        elif code == "LIFT_INVALID_CALL_TARGET":
            if len(encoded) < 5 or encoded[-5] != 0xe8:
                raise ValueError("invalid direct call encoding")
            target = instruction + len(encoded) + int.from_bytes(encoded[-4:], "little", signed=True)
            if target != context["branch_target"]:
                raise ValueError("call target disagrees with the signed displacement")
        with Path(image).open("rb") as source:
            source.seek(offset)
            if source.read(len(encoded)) != encoded:
                raise ValueError("instruction bytes disagree with the PE snapshot")


def parse_diagnostic(raw, image, selected, ir, resolve_callee=None, register_target=None):
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
    validate_context(field(diagnostic, "context", dict), *kind, diagnostic["code"], image,
                     selected, ir, resolve_callee, register_target)
    return diagnostic
