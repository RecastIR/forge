"""Native regression runs using the genuine PE, Wine publication, Forge and native build."""
import argparse
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import differential as diff
import startup
from calculate_driver_cases import CASES as CALCULATE_INPUTS

CASE = "arithmetic/add_i64"
WEIGHTED = "arithmetic/weighted_pair_i64"
OUTPUT = diff.OUTPUT.parent / "negative-tests"


class NativeDifferentialTests(unittest.TestCase):
    forge = diff.DEFAULT_FORGE

    def setUp(self):
        self.tmp = diff.BUILD / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def check_startup_blocker(self, manifest, config, work, slot):
        report = startup.run_case(self.forge, manifest, config, work)
        self.assertEqual(report.get("failure_stage"), "translation", report.get("diagnostic"))
        self.assertEqual(report["stages"], dict(reference="passed", recovery="failed", translation="failed",
                                                native_build="not_run", publication="not_run", artifact="not_run",
                                                execution="not_run", comparison="not_run"))
        self.assertFalse(os.path.lexists(work / "translated"))
        record = report["compiler_diagnostic"]
        self.assertEqual((record["stage"], record["category"], record["code"]),
                         ("lifting", "unsupported", "LIFT_UNSUPPORTED_CONTROL_FLOW"))
        ctx = record["context"]
        self.assertIs(ctx["entry_recovered"], True)
        self.assertIs(ctx["recovery_complete"], False)
        self.assertEqual((ctx["entry_rva"], ctx["function_rva"], ctx["instruction_rva"], ctx["opcode"]),
                         ("0x14d0", "0x1010", "0x1072", "CALL64pcrel32"))
        self.assertEqual((ctx["caller_rva"], ctx["call_site_rva"], ctx["initializer_target_rva"]),
                         ("0x1180", "0x1494", "0x1010"))
        self.assertEqual((ctx["import_dll"], ctx["import_symbol"], ctx["iat_slot_rva"]),
                         ("msvcrt.dll", "__set_app_type", slot))
        # The original .text starts at file offset 0x600 and RVA 0x1000 in both builds.
        data = (diff.BINARIES / config / manifest.case["binary"]).read_bytes()
        self.assertEqual(data[0x644:0x649], bytes.fromhex("66 81 38 4d 5a"))
        call = data[0x672:0x677]
        self.assertEqual((call[0], ctx["bytes"]), (0xe8, call.hex()))
        thunk = 0x1077 + struct.unpack_from("<i", call, 1)[0]
        self.assertIn({"caller_rva": "0x1010", "instruction_rva": "0x1072", "target_rva": hex(thunk)},
                      ctx["unresolved_calls"])
        return report

    def test_other_conventional_startup_blockers(self):
        slots = {"argc_none": "0x81f0", "argv": "0x81f8", "argv_edges": "0x81f8", "cleanup": "0x8220",
                 "globals": "0x81f0", "puts": "0x81f8", "return": "0x81f0"}
        manifests = {m.case["id"]: m for m in diff.load_catalog()}
        for name, slot in slots.items():
            for config in ("debug", "release"):
                with self.subTest(name=name, config=config), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                    self.check_startup_blocker(manifests["startup/" + name], config, Path(tmp), slot)

    def test_conventional_startup_readiness(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == "startup/argc")
        # Independent llvm-readobj import/header and llvm-objdump .CRT/disassembly
        # observations for these two reproducible PEs. TLS callback order matters.
        inputs = {
            "debug": ("e2192c63caae30f8dfe5697c3bec3888abcb7831cd7fe33a0f07c09309b0bfb6",
                      ["0x140001690", "0x140001660"]),
            "release": ("d21038a0b109685d0946014d2a1982a7464bcec35565996f42db000449233aaa",
                        ["0x140001660", "0x140001630"]),
        }
        imports = {
            "kernel32.dll": "DeleteCriticalSection EnterCriticalSection GetLastError GetStartupInfoA "
                            "InitializeCriticalSection LeaveCriticalSection SetUnhandledExceptionFilter Sleep "
                            "TlsGetValue VirtualProtect VirtualQuery __C_specific_handler",
            "msvcrt.dll": "__getmainargs __initenv __iob_func __set_app_type __setusermatherr _acmdln "
                          "_amsg_exit _cexit _commode _fmode _initterm _onexit abort calloc exit fprintf "
                          "free fwrite malloc memcpy signal strlen strncmp vfprintf",
        }
        for config, (digest, callbacks) in inputs.items():
            with self.subTest(config=config), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                work = Path(tmp)
                report = self.check_startup_blocker(manifest, config, work, "0x81f0")
                self.assertEqual(report["binary_sha256"], digest)
                context = report["compiler_diagnostic"]["context"]
                self.assertIn({"caller_rva": "0x1180", "instruction_rva": "0x142a",
                               "first_rva": "0x9000", "last_rva": "0x9010",
                               "initial_target_rvas": ["0x1130"]}, context["initializer_tables"])
                unresolved = context["unresolved_calls"]
                self.assertIn({"caller_rva": "0x1180", "instruction_rva": "0x1494",
                               "first_rva": "0x9018", "last_rva": "0x9028",
                               "initial_target_rvas": ["0x1010"]}, context["initializer_tables"])
                for dll, symbol, site in (("kernel32.dll", "GetStartupInfoA", "0x1453"),
                                          ("kernel32.dll", "Sleep", "0x11e6"),
                                          ("kernel32.dll", "SetUnhandledExceptionFilter", "0x1258"),
                                          ("msvcrt.dll", "_amsg_exit", "0x140c"),
                                          ("msvcrt.dll", "_cexit", "0x1460"),
                                          ("msvcrt.dll", "exit", "0x14a8"),
                                          ("msvcrt.dll", "_initterm", "0x142a"),
                                          ("msvcrt.dll", "_initterm", "0x1494")):
                    self.assertIn({"dll": dll, "name": symbol}, context["imports"])
                    self.assertNotIn(site, [c["instruction_rva"] for c in unresolved])
                pe = diff.BINARIES / config / manifest.case["binary"]
                data = pe.read_bytes()
                call_bytes = "e891120000" if config == "debug" else "e861120000"
                self.assertEqual(data[0xa2a:0xa2f], bytes.fromhex(call_bytes))
                # llvm-objdump and llvm-readobj place the original R12 load and register CALL
                # in the pinned .text section at file offsets 0x7c8 and 0x7e6.
                self.assertEqual(data[0x7c8:0x7cf], bytes.fromhex("4c8b25d96f0000"))
                self.assertEqual(data[0x7e6:0x7e9], bytes.fromhex("41ffd4"))
                # RCX receives the relocated filter from .rdata, then RAX is saved after the IAT call.
                self.assertEqual(data[0x851:0x85e], bytes.fromhex("488b0d68320000 ff15426f0000"))
                self.assertEqual(data[0x86c:0x86f], bytes.fromhex("488902"))
                filter_va, = struct.unpack_from("<Q", data, 0x24c0)
                self.assertEqual(filter_va, 0x140001dd0 if config == "debug" else 0x140001da0)
                scope = context["entry_unwind_handler"]["c_specific_handler"]["scope"]
                self.assertEqual((scope["begin_rva"], scope["end_rva"], scope["filter_rva"]),
                                 ("0x14d4", "0x14e7", "0x1dd0" if config == "debug" else "0x1da0"))
                tls = context["tls"]
                self.assertEqual((tls["raw_data_start_va"], tls["raw_data_end_va"], tls["index_va"]),
                                 ("0x14000a000", "0x14000a008", "0x14000708c"))
                self.assertEqual(tls["callback_vas"], callbacks)
                self.assertIn("unsupported", tls["limitation"])
                directories = context["load_imports"]
                crt = next(d for d in directories if d["dll"].lower() == "msvcrt.dll")
                fatal = next(s for s in crt["symbols"] if s["name"] == "_amsg_exit")
                self.assertEqual(fatal["iat_slot_rva"], "0x8208")
                self.assertIs(fatal["catalogued_service"], True)
                initializer = next(s for s in crt["symbols"] if s["name"] == "_initterm")
                self.assertEqual(initializer["iat_slot_rva"], "0x8228")
                self.assertIs(initializer["catalogued_service"], True)
                self.assertCountEqual([d["dll"].lower() for d in directories], imports)
                for directory in directories:
                    self.assertIs(directory["delayed"], False)
                    self.assertCountEqual([s["name"] for s in directory["symbols"]],
                                          imports[directory["dll"].lower()].split())

    def test_both_conventional_initializer_tables(self):
        sys.path.insert(0, str(diff.SUITE.parent / "integration"))
        from pe_layout import Layout
        sys.path.pop(0)

        original = (diff.BINARIES / "debug/crt_argc.exe").read_bytes()
        # Isolate each original argument sequence, import call and table. The startup
        # comparison above uses the untouched PE and reaches the second table’s initializer.
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            pe, output = Path(tmp) / "probe.exe", Path(tmp) / "translated"
            for start, site, slot in ((0x141c, 0x142a, 0x9008), (0x1480, 0x1494, 0x9020)):
                for invalid in (False, True):
                    with self.subTest(site=hex(site), invalid=invalid):
                        data = bytearray(original)
                        layout = Layout(data)
                        entry = layout.file_offset(0x1180)
                        data[entry:entry+5] = b"\xe9" + struct.pack("<i", start - 0x1185)
                        data[layout.file_offset(site + 5)] = 0xc3
                        if invalid:
                            struct.pack_into("<Q", data, layout.file_offset(slot), 0x140009000)
                        pe.write_bytes(data)
                        result = subprocess.run([self.forge, "lift", pe, "--executable", "--output", output,
                                                 "--diagnostics-format", "json"], capture_output=True, timeout=30)
                        record = startup.compiler_diagnostic(result.stderr, result.returncode, pe, output)
                        ctx = record["context"]
                        if not invalid:
                            first, last, target = ((0x9000, 0x9010, 0x1130) if site == 0x142a
                                                   else (0x9018, 0x9028, 0x1010))
                            self.assertIn({"caller_rva": "0x1180", "instruction_rva": hex(site),
                                           "first_rva": hex(first), "last_rva": hex(last),
                                           "initial_target_rvas": [hex(target)]},
                                          ctx["initializer_tables"])
                        if invalid:
                            self.assertEqual((record["code"], ctx["instruction_rva"]),
                                             ("LIFT_INVALID_CALL_TARGET", hex(site)))
                        elif site == 0x142a:
                            self.assertIs(ctx["recovery_complete"], True)
                            self.assertIn({"dll": "msvcrt.dll", "name": "__getmainargs"}, ctx["imports"])
                        else:
                            self.assertEqual((record["code"], ctx["function_rva"], ctx["instruction_rva"],
                                              ctx["opcode"], ctx["bytes"]),
                                             ("LIFT_UNSUPPORTED_CONTROL_FLOW", "0x1010", "0x1072",
                                              "CALL64pcrel32", "e829160000"))
                            self.assertEqual((ctx["initializer_target_rva"], ctx["caller_rva"],
                                              ctx["call_site_rva"], ctx["import_symbol"], ctx["iat_slot_rva"]),
                                             ("0x1010", "0x1180", hex(site), "__set_app_type", "0x81f0"))
                            self.assertEqual(ctx["unresolved_calls"], [
                                {"caller_rva": "0x1010", "instruction_rva": "0x1072",
                                 "target_rva": "0x26a0"}])

    def test_lstrlen_rebased_reference(self):
        fixture = "imports/lstrlen"
        contract = self.forge.resolve().parent / "tests/lift_contract"
        if not contract.is_file():
            contract = self.forge.resolve().parent.parent / "tests" / self.forge.parent.name / "lift_contract"
        manifest = next(m for m in diff.load_catalog(diff.SUITE) if m.case["id"] == fixture)
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                case = output / config / fixture
                module = diff.read_json(case / "inspect.json")["modules"][0]
                rva = next(e["rva"] for e in module["exports"] if "string_length" in e["names"])
                base = int(module["image_base_va"], 16) + 0x1000000
                ir = case / "rebased.ll"
                ir.write_bytes(subprocess.check_output([contract, "--emit-rebased-checked",
                                                        case / "lstrlen.exe", rva, hex(base)], timeout=30))
                # The ordinary run verified the Wine publication before these comparisons.
                expected = (case / "baseline/stdout.bin").read_bytes()
                for variant in diff.VARIANTS:
                    work = case / "rebased" / variant
                    work.mkdir(parents=True)
                    exe, _ = diff.native.build(ir, "runtime_pairs", work, config, variant)
                    result = subprocess.run([exe, *manifest.case["args"]], capture_output=True, timeout=10)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_calculate_driver(self):
        fixture = "frames/calculate"
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    exe = output / config / fixture / variant / "native/bin/differential_calculate_pairs"
                    for args, status, stdout in CALCULATE_INPUTS:
                        with self.subTest(config=config, variant=variant, args=args):
                            result = subprocess.run([exe, *args], capture_output=True, timeout=10)
                            self.assertEqual((result.returncode, result.stdout, result.stderr), (status, stdout, b""))

    def test_runtime_entry(self):
        fixture = "imports/last_error"
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    exe = output / config / fixture / variant / "native/bin/differential_runtime_pairs"
                    for args, expected in ((["--probe", "isolation", "get"], 0),
                                           (["5", "0", "bad", "0"], 2)):
                        with self.subTest(config=config, variant=variant, args=args):
                            result = subprocess.run([exe, *args], capture_output=True, timeout=10)
                            self.assertEqual((result.returncode, result.stdout, result.stderr), (expected, b"", b""))

    def test_mixed_import_and_guest_call_evidence(self):
        image = diff.BINARIES / "release/last_error.exe"
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            work = Path(tmp)
            caller = diff.analyze(self.forge, image, "last_error", work)
            module = diff.read_json(work / "inspect.json")["modules"][0]
            base = int(module["image_base_va"], 16)
            code = image.read_bytes()
            decode = diff.caller_decoder(image, base + caller.start, base + caller.end)
            address = base + caller.start
            guests, imports = [], []
            while address < base + caller.end:
                asm, following = decode(address)
                if asm.startswith("call "):
                    site = address - base
                    offset = caller.file_offset + site - caller.start
                    raw = code[offset:offset + following - address]
                    if raw[0] == 0xe8:
                        guests.append((site, following - base + int.from_bytes(raw[1:], "little", signed=True)))
                    else:
                        imports.append(site)
                address = following
            self.assertTrue(guests and imports)
            for site, target in guests:
                self.assertEqual(diff.verified_call_target(image, module, caller, site, self.forge,
                                                           require_continuation=True), target)
            with self.assertRaisesRegex(ValueError, "reachable direct CALL"):
                diff.verified_call_target(image, module, caller, imports[0], self.forge, require_continuation=True)

            # The same FF /2 bytes fall through only when the addressed slot can be proved.
            changed = bytearray(code)
            site = imports[0]
            struct.pack_into("<i", changed, caller.file_offset + site - caller.start + 2, 0)
            forged = work / "forged.exe"
            forged.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "unproven supported-service IAT call"):
                diff.verified_call_target(forged, module, caller, guests[0][0], self.forge, require_continuation=True)

    def test_bound_iat_and_external_call_frames(self):
        for config in diff.CONFIGS:
            with self.subTest(config=config):
                self.check_external_call_frames(config)

    def check_external_call_frames(self, config):
        sys.path.insert(0, str(diff.SUITE.parent / "integration"))
        from pe_layout import Layout
        sys.path.pop(0)
        source = diff.BINARIES / config / "last_error.exe"
        data = bytearray(source.read_bytes())
        layout = Layout(data)
        desc = layout.file_offset(layout.directory(1)[0])
        slots = {}
        while layout.u32(desc + 12):
            name = layout.file_offset(layout.u32(desc + 12))
            if data[name:name+13].lower() == b"kernel32.dll\0":
                lookup, iat = layout.u32(desc), layout.u32(desc + 16)
                struct.pack_into("<I", data, desc + 4, 0xffffffff)
                i = 0
                while (hint := layout.u32(layout.file_offset(lookup) + 8*i)):
                    start = layout.file_offset(hint) + 2
                    slots[data[start:data.index(0, start)].decode()] = iat + 8*i
                    struct.pack_into("<Q", data, layout.file_offset(iat) + 8*i, 0x7ffa00001000 + 32*i)
                    i += 1
                break
            desc += 20

        for api, frame in ((None, None), ("SetLastError", 40), ("GetLastError", 40),
                           ("GetLastError", 8), ("GetLastError", 32)):
            with self.subTest(api=api, frame=frame), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                work = Path(tmp).resolve()
                image = work / source.name
                image.write_bytes(data)
                entry = diff.analyze(self.forge, image, "last_error", work)
                if api:
                    # One service and a balanced frame. Without the specific boundary guard
                    # each negative can return normally, including after the void setter.
                    prefix = bytes.fromhex("4883ec") + bytes([frame]) + bytes.fromhex("ff15")
                    disp = struct.pack("<i", slots[api] - (entry.start + len(prefix) + 4))
                    result_reg = bytes.fromhex("b807000000") if api == "SetLastError" else b""
                    code = prefix + disp + result_reg + bytes.fromhex("4883c4") + bytes([frame, 0xc3])
                    self.assertLessEqual(len(code), entry.end - entry.start)
                    with image.open("r+b") as output:
                        output.seek(entry.file_offset)
                        output.write(code)

                ir = work / diff.CANONICAL_IR
                ir.parent.mkdir()
                diff.lift(self.forge, image, {"signature": "i64(i64,i64)", "harness": "runtime_pairs"}, entry, ir)
                for variant in diff.VARIANTS:
                    directory = work / variant
                    directory.mkdir()
                    exe, _ = diff.native.build(ir, "runtime_pairs", directory, config, variant)
                    if api is None:
                        result = subprocess.run([exe, "4294967295", "0", "0", "1"], capture_output=True, timeout=10)
                        self.assertEqual((result.returncode, result.stdout), (0, b"4294967295\n4294967295\n"))
                        continue

                    result = subprocess.run([exe, "5", "0"], capture_output=True, timeout=10)
                    if frame != 40:
                        self.assertEqual(result.returncode, -signal.SIGTRAP)
                        continue

                    expected = b"7\n" if api == "SetLastError" else b"0\n"
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
                    for mode in ("zero", "foreign", "retired", "null"):
                        with self.subTest(variant=variant, mode=mode):
                            operation = "set" if api == "SetLastError" else "get"
                            result = subprocess.run([exe, "--probe", mode, operation], capture_output=True, timeout=10)
                            self.assertEqual((result.returncode, result.stdout), (-signal.SIGTRAP, b""))

    def test_continuation_faults(self):
        fixture = "functions/continuations"
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp).resolve()
            for config in diff.CONFIGS:
                # The ordinary reads must match Wine in these exact native binaries.
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    work = output / config / fixture / variant
                    exe = work / "native/bin/differential_decimal_pairs"
                    for mode in ("3", "4"):
                        with self.subTest(config=config, variant=variant, mode=mode):
                            with self.assertRaises(diff.native.ExecutionFailure) as raised:
                                diff.native.execute(exe, ["0", mode], output)
                            self.assertEqual((raised.exception.outcome, raised.exception.status),
                                             ("signaled", -signal.SIGTRAP))

    def test_undefined_af_at_shared_entry_and_return(self):
        for config in diff.CONFIGS:
            with self.subTest(config=config), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                work = Path(tmp)
                source = diff.BINARIES / config / "call_flags.exe"
                image = work / source.name
                original = source.read_bytes()
                image.write_bytes(original)
                root = diff.analyze(self.forge, image, "call_flags", work)
                leaf = diff.resolve_export(diff.read_json(work / "inspect.json"),
                                           diff.read_json(work / "analysis.json"), "shared_flags")
                self.assertEqual(original[leaf.file_offset], 0x90)

                # Only the TEST path returns through SETZ AL followed by MOVZX EAX,AL.
                body = original[root.file_offset:root.file_offset + root.end - root.start]
                consumer = bytes.fromhex("0f 94 c0 0f b6 c0")
                self.assertEqual(body.count(consumer), 1)
                continuation = body.index(consumer)
                self.assertGreaterEqual(continuation, 5)
                self.assertEqual(body[continuation - 5], 0xe8)

                ir = work / diff.CANONICAL_IR
                ir.parent.mkdir()
                for owner, position, block_rva, replacement in (
                        (leaf, 0, leaf.start, b"\x9f"),  # NOP -> LAHF at shared entry
                        (root, continuation, root.start + continuation - 5, b"\x9f\x90\x90")):
                    with self.subTest(instruction_rva=hex(owner.start + position)):
                        offset = owner.file_offset + position
                        data = bytearray(original)
                        data[offset:offset + len(replacement)] = replacement
                        image.write_bytes(data)
                        with self.assertRaisesRegex(diff.Unsupported, r"lifting/LIFT_UNDEFINED_FLAG: .*flags: AF\b"):
                            diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, root, ir)
                        context = diff.read_json(work / "lifting.log")["context"]
                        self.assertEqual(context.get("function_rva", context["entry_rva"]), hex(owner.start))
                        self.assertEqual((context["block_rva"], context["instruction_rva"]),
                                         (hex(block_rva), hex(owner.start + position)))
                        self.assertEqual((context["file_offset"], context["opcode"], context["bytes"]),
                                         (offset, "LAHF", "9f"))
                        self.assertFalse(ir.exists())

    def test_inferred_diagnostic_call_sites(self):
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            work = Path(tmp)
            image = work / "source.exe"
            original = (diff.BINARIES / "debug/call_leaves.exe").read_bytes()
            image.write_bytes(original)
            caller = diff.analyze(self.forge, image, "call_leaves", work)
            module = diff.read_json(work / "inspect.json")["modules"][0]
            analysis = diff.read_json(work / "analysis.json")
            first = caller.file_offset + 4
            self.assertEqual(original[first], 0xe8)
            leaf = caller.start + 9 + struct.unpack_from("<i", original, first + 1)[0]
            leaf_code = diff.resolve_leaf_window(module, analysis, image, leaf, caller.start, caller.start + 4)
            ir = work / diff.CANONICAL_IR
            ir.parent.mkdir()

            for prefix, site, suffix, reachable in (
                    (b"", 0, b"\xc3", True), (b"\xd5\x00", 0, b"\xc3", True),
                    (b"\x48\xb8", 2, b"\x00\x00\x00\xc3", False),
                    (b"\xeb\x05", 2, b"\xc3", False),
                    (b"\xeb\x01\xb8", 3, b"\xc3", True)):
                with self.subTest(prefix=prefix.hex()):
                    displacement = leaf - (caller.start + len(prefix) + 5)
                    body = prefix + b"\xe8" + struct.pack("<i", displacement) + suffix
                    data = bytearray(original)
                    data[caller.file_offset:caller.file_offset + len(body)] = body
                    data[leaf_code.file_offset:leaf_code.file_offset + 2] = b"\x0f\x0b"
                    image.write_bytes(data)
                    if reachable:
                        with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_INSTRUCTION"):
                            diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, caller, ir)
                        with self.assertRaisesRegex(ValueError, "reachable direct CALL"):
                            diff.resolve_leaf_window(module, analysis, image, leaf + 1, caller.start, caller.start + site)
                    else:
                        with self.assertRaisesRegex(ValueError, "reachable direct CALL"):
                            diff.resolve_leaf_window(module, analysis, image, leaf, caller.start, caller.start + site)

    def test_mutable_state_in_a_fresh_process(self):
        fixture = "globals/counters"
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == fixture)
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                binary = diff.BINARIES / config / manifest.case["binary"]
                observed, _ = diff.reference(diff.REFERENCES, manifest, config, diff.sha256(binary.read_bytes()))
                # Both endpoints use a zero update. Their different values witness the intervening calls.
                self.assertNotEqual(observed.stdout.splitlines()[0], observed.stdout.splitlines()[-1])
                for variant in diff.VARIANTS:
                    with self.subTest(config=config, variant=variant):
                        exe = output / config / fixture / variant / "native/bin/differential_decimal_pairs"
                        repeated = subprocess.run([exe, *manifest.case["args"]], capture_output=True, timeout=10)
                        self.assertEqual((repeated.returncode, repeated.stdout, repeated.stderr),
                                         (observed.exit_code, observed.stdout, observed.stderr))

    def negative(self, name, category, *, fixture=CASE, binaries=diff.BINARIES):
        output = OUTPUT / name
        self.assertEqual(diff.run("debug", fixture, binaries=binaries, output=output, forge=self.forge), 1)
        report = diff.read_json(output / "debug" / fixture / "result.json")
        self.assertEqual(report["failure_categories"], [category])
        return report

    def modified_ir(self, fixture, name, category, mutate, only=None):
        compile_native = diff.native.build

        def compile_copy(ir, harness, work, config, variant):
            if only and only != variant:
                return compile_native(ir, harness, work, config, variant)
            changed = work / (name + ".ll")
            changed.write_text(mutate(ir.read_text()))
            return compile_native(changed, harness, work, config, variant)

        with patch.object(diff.native, "build", compile_copy):
            return self.negative(name, category, fixture=fixture)

    def test_real_unsupported_instruction_diagnostic(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == CASE)
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            work = Path(tmp).resolve()
            image = work / manifest.case["binary"]
            data = bytearray((diff.BINARIES / "debug" / image.name).read_bytes())
            image.write_bytes(data)
            entry = diff.analyze(self.forge, image, "add_i64", work)
            length = entry.end - entry.start
            # PUSH [RCX], RET and padding preserve every PE table and the discovered extent.
            self.assertGreaterEqual(length, 3)
            data[entry.file_offset:entry.file_offset + length] = b"\xff\x31\xc3".ljust(length, b"\xcc")
            image.write_bytes(data)
            selected = diff.analyze(self.forge, image, "add_i64", work)
            ir = work / diff.CANONICAL_IR
            ir.parent.mkdir()
            with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_INSTRUCTION"):
                diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, selected, ir)
            failure = diff.read_json(work / "lifting.log")
            self.assertEqual((failure["context"]["instruction_rva"], failure["context"]["file_offset"],
                              failure["context"]["bytes"]), (hex(selected.start), entry.file_offset, "ff31"))
            self.assertFalse(ir.exists())

    def test_image_spill_selects_only_the_table(self):
        for config in diff.CONFIGS:
            with self.subTest(config=config), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                work = Path(tmp)
                image = diff.BINARIES / config / "image_spill.exe"
                selected = diff.analyze(self.forge, image, "image_spill", work)
                ir = work / diff.CANONICAL_IR
                ir.parent.mkdir()
                diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, selected, ir)
                source = ir.read_text()
                backings = re.findall(r"^@image_[0-9a-f]+ = private constant \[(\d+) x i8\]", source, re.M)
                self.assertEqual(backings, ["8"])
                ranges = next(line for line in source.splitlines() if line.startswith("@image.ranges = "))
                self.assertIn("constant [1 x", ranges)

    def test_original_image_table(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == "image/lookup")
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            work = Path(tmp)
            image = work / "lookup.exe"
            data = bytearray((diff.BINARIES / "release" / image.name).read_bytes())
            observed, _ = diff.reference(diff.REFERENCES, manifest, "release", diff.sha256(data))
            image.write_bytes(data)
            selected = diff.analyze(self.forge, image, "lookup", work)
            # The linked Release export takes its array base with LEA RAX,[RIP+disp32].
            body = data[selected.file_offset:selected.file_offset + selected.end - selected.start]
            opcode = bytes.fromhex("488d05")
            self.assertEqual(body.count(opcode), 1)
            pos = body.index(opcode)
            table = selected.start + pos + 7 + struct.unpack_from("<i", body, pos + 3)[0]
            sections = diff.read_json(work / "inspect.json")["modules"][0]["sections"]
            section, = [s for s in sections if s["permissions"] == "r--"
                        and 0 <= table-int(s["rva"], 16) <= min(s["raw_size"], s["virtual_size"]) - 8]
            entry = section["file_offset"] + table - int(section["rva"], 16) + 4
            struct.pack_into("<I", data, entry, struct.unpack_from("<I", data, entry)[0] + 1)
            image.write_bytes(data)
            ir = work / diff.CANONICAL_IR
            ir.parent.mkdir()
            diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, selected, ir)
            image.unlink()
            args = manifest.case["args"]
            lines = [int(line) for line in observed.stdout.splitlines()]
            for i, (index, multiplier) in enumerate(zip(args[::2], args[1::2])):
                if int(index) & 7 == 1:
                    lines[i] += int(multiplier)
            expected = "".join(f"{value}\n" for value in lines).encode()
            self.assertNotEqual(expected, observed.stdout)
            for variant in diff.VARIANTS:
                directory = work / variant
                directory.mkdir()
                exe, _ = diff.native.build(ir, "decimal_pairs", directory, "release", variant)
                result = diff.native.execute(exe, args, directory)
                self.assertEqual((result.stdout, result.stderr, result.exit_code), (expected, b"", 0))

    def test_changed_return(self):
        def change_return(source):
            changed, count = re.subn(r"^  ret i64 (%\w+)$",
                                     r"  %nonzero = icmp ne i64 \1, 0\n  %delta = zext i1 %nonzero to i64\n"
                                     r"  %changed = add i64 \1, %delta\n  ret i64 %changed",
                                     source, flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected one return in the native wrapper")
            return changed

        for fixture, pair_index, variant in ((CASE, 0, "baseline"), (WEIGHTED, 1, "o2")):
            with self.subTest(fixture=fixture):
                report = self.modified_ir(fixture, "changed-return", "stdout_mismatch", change_return, only=variant)
                other = "baseline" if variant == "o2" else "o2"
                self.assertEqual(report["variants"][other]["status"], "passed")
                self.assertEqual(report["status"], "behavioral_failure")
                self.assertEqual(report["stages"]["native_execution"], "passed")
                self.assertEqual(report["stages"]["comparison"], "failed")
                mismatch, = report["variants"][variant]["differences"]
                self.assertEqual(mismatch["field"], "stdout")
                manifest = next(m for m in diff.load_catalog() if m.case["id"] == fixture)
                self.assertEqual(mismatch["operands"], manifest.case["args"][2 * pair_index:2 * pair_index + 2])

    def test_signed_comparison_with_truncated_right_operand(self):
        def truncate_right(source):
            # Change the incoming RDX bits once. The weighted term already uses
            # only EDX, so the only behavior affected is the signed comparison.
            # SSA argument numbers are local to each function in the module.
            start = source.index(" @forge_lifted(")
            end = source.index("\n}", start)
            pattern = r"^(  store i64 )%1(, ptr %\w+, align \d+)$"
            changed, count = re.subn(pattern, r"  %low = trunc i64 %1 to i32\n"
                                     r"  %right = sext i32 %low to i64\n\1%right\2", source[start:end],
                                     flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected the wrapper to initialize RDX once")
            return source[:start] + changed + source[end:]

        report = self.modified_ir(WEIGHTED, "truncated-right", "stdout_mismatch", truncate_right)
        self.assertEqual(report["stages"]["native_execution"], "passed")
        self.assertEqual(report["stages"]["comparison"], "failed")
        for evidence in report["variants"].values():
            mismatch, = evidence["differences"]
            self.assertEqual(mismatch["operands"], ["1", "4294967295"])

    def test_stack_index_scale(self):
        def use_byte_stride(source):
            changed, count = re.subn(r"(\bmul i64 %\w+, )4\b", r"\g<1>1", source)
            self.assertEqual(count, 1, "expected one four-byte index scale")
            return changed

        report = self.modified_ir("memory/indexed", "byte-stride", "stdout_mismatch", use_byte_stride)
        for variant in diff.VARIANTS:
            evidence = report["variants"][variant]
            self.assertEqual(evidence["stages"]["native_execution"], "passed")
            self.assertEqual(evidence["failure_categories"], ["stdout_mismatch"])

    def test_word_sign_extension(self):
        def zero_extend(source):
            changed, count = re.subn(r"\bsext i16 (%\w+) to i64\b", r"zext i16 \1 to i64", source)
            self.assertEqual(count, 1, "expected one signed word-to-quadword extension")
            return changed

        report = self.modified_ir("arithmetic/extensions", "unsigned-word", "stdout_mismatch", zero_extend)
        for variant in diff.VARIANTS:
            self.assertEqual(report["variants"][variant]["failure_categories"], ["stdout_mismatch"])

    def test_native_build_failures(self):
        def missing_wrapper(source):
            self.assertEqual(source.count("@forge_lifted("), 1)
            return source.replace("@forge_lifted(", "@missing_wrapper(")

        def invalid_ir(source):
            return source + "\ninvalid IR for the native build regression\n"

        for fixture, name, mutate, phase in (
                (CASE, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "missing-wrapper", missing_wrapper, "linking")):
            with self.subTest(fixture=fixture, name=name):
                report = self.modified_ir(fixture, name, "native_compilation_failure", mutate)
                self.assertEqual(report["status"], "infrastructure_failure")
                self.assertIn(f"native {phase} failed", report["diagnostic"])
                if name == "missing-wrapper":
                    self.assertIn("_forge_lifted", report["diagnostic"])
                self.assertEqual(report["stages"]["native_execution"], "not_run")
                self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_instrumented_harness_link(self):
        for generator in ("Unix Makefiles", "Xcode"):
            with self.subTest(generator=generator), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                output = Path(tmp).resolve()
                flags = "-fsanitize=undefined"
                link_map = output / "harness.map"
                # The Xcode generator takes link options separately from CXXFLAGS.
                ldflags = f'{flags} -Xlinker -map -Xlinker "{link_map}"' if generator == "Xcode" else ""
                with patch.dict(os.environ, CMAKE_GENERATOR=generator, CXXFLAGS=flags, LDFLAGS=ldflags,
                                CMAKE_TOOLCHAIN_FILE=str(output / "unavailable-conan-toolchain.cmake")):
                    self.assertEqual(diff.run("debug", WEIGHTED, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    cache = (output / "debug" / WEIGHTED / variant / "native/CMakeCache.txt").read_text()
                    self.assertIn("FORGE_BUILD_CLI:BOOL=OFF", cache)
                    self.assertNotIn("CLI11_DIR:", cache)
                if generator == "Xcode":
                    self.assertIn("_forge_lifted", link_map.read_text())

    def test_suite_build_isolates_native_link_failures(self):
        catalog = diff.load_catalog()
        selected = [m for m in catalog if m.case["id"] in (CASE, WEIGHTED)]
        definitions = diff.case_definitions(catalog, diff.SUITE / "cases.json")
        original = diff.lift

        def broken_wrapper(forge, image, case, entry, ir):
            original(forge, image, case, entry, ir)
            if case["fixture_id"] == CASE:
                source = ir.read_text()
                self.assertIn("@forge_lifted(", source)
                ir.write_text(source.replace("@forge_lifted(", "@missing_wrapper("))

        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp).resolve()
            with patch.object(diff, "lift", broken_wrapper), patch.object(diff, "load_catalog", return_value=selected), \
                    patch.object(diff, "case_definitions", return_value=definitions):
                self.assertEqual(diff.run("release", output=output, forge=self.forge), 1)
            suite = diff.read_json(output / "release/suite.json")
            self.assertEqual((suite["passed"], suite["executed"]), (1, 1))
            folder = output / "release"
            failed = diff.read_json(folder / CASE / "result.json")
            passed = diff.read_json(folder / WEIGHTED / "result.json")
            self.assertEqual(set(failed["variants"]), set(diff.VARIANTS))
            for variant in diff.VARIANTS:
                self.assertIn("native linking failed", failed["variants"][variant]["diagnostic"])
                self.assertEqual(passed["variants"][variant]["status"], "passed")
            self.assertEqual(len(list((folder / "cmake-workers").rglob("CMakeCache.txt"))), 1)

    def test_weighted_repeatability(self):
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            observations = []
            for run in ("first", "second"):
                output = Path(tmp).resolve() / run
                self.assertEqual(diff.run("debug", WEIGHTED, output=output, forge=self.forge), 0)
                work = output / "debug" / WEIGHTED
                report = diff.read_json(work / "result.json")
                self.assertEqual(report["status"], "passed")
                observations.append((report["binary_sha256"], report["forge_sha256"], report["reference"],
                                     (work / "generated/lifted.ll").read_bytes(), report["variants"],
                                     [(work / v / file).read_bytes() for v in diff.VARIANTS
                                      for file in ("stdout.bin", "stderr.bin")]))
            self.assertEqual(observations[0], observations[1])

    def test_nonterminating_lifted_loop(self):
        # Force the taken backedge of the existing guest loop in the baseline IR.
        def close_loop(source):
            latch = re.compile(r"^rva_([0-9a-f]+):[^\n]*\n(?:  [^\n]*\n)*?"
                               r"  br i1 (%\w+), label %rva_([0-9a-f]+), label %rva_([0-9a-f]+)$",
                               re.MULTILINE)
            backedges = [match for match in latch.finditer(source)
                         if int(match[3], 16) <= int(match[1], 16) < int(match[4], 16)]
            self.assertEqual(len(backedges), 1)
            start, end = backedges[0].span(2)
            return source[:start] + "true" + source[end:]

        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, args, work, timeout=1)):
            report = self.modified_ir("control_flow/counted_sum", "closed-loop", "native_execution_failure",
                                      close_loop, only="baseline")
        self.assertEqual(report["variants"]["baseline"]["execution_outcome"], "timeout")
        self.assertEqual(report["variants"]["o2"]["status"], "passed")

    def test_harness_failure(self):
        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, ["invalid", "1"], work)):
            report = self.negative("invalid-operands", "native_execution_failure")
        self.assertIn("exited 2", report["diagnostic"])
        for evidence in report["variants"].values():
            self.assertEqual((evidence["execution_outcome"], evidence["native_process_status"]), ("harness_error", 2))
        self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_stale_reference(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == CASE)
        binary = manifest.case["binary"]
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            root = Path(tmp).resolve()
            (root / "debug").mkdir()
            release = (diff.BINARIES / "release" / binary).read_bytes()
            (root / "debug" / binary).write_bytes(release)
            (root / "debug/SHA256SUMS").write_text(f"{diff.sha256(release)}  {binary}\n")
            report = self.negative("stale-pe", "reference_validation_failure", binaries=root)
        self.assertIn("binary_sha256 mismatch", report["diagnostic"])
        self.assertEqual(report["stages"]["analysis"], "not_run")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--forge", type=Path, default=diff.DEFAULT_FORGE)
    args, tests = parser.parse_known_args()
    NativeDifferentialTests.forge = args.forge.resolve()
    unittest.main(argv=[sys.argv[0], *tests])
