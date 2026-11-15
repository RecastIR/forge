"""Instruction and control-flow witnesses for the linked MinGW fixtures."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build import check_frame, check_global_leaf, check_image_leaf, check_leaf, check_nested_exits, leaf_instructions


# Both loops are laid out after a shared return. Absolute addresses are immaterial.
NESTED = """
10: jmp 30 <cfg_nested_exits+0x20>
11: ret
30: je 11
31: je 60
40: je 80
41: jne 40
60: je 90
61: jmp 30
80: ret
90: ret
"""


class FixtureShapeTests(unittest.TestCase):
    def check(self, listing):
        entry = listing.lstrip().split(":", 1)[0]
        output = f"{entry} <cfg_nested_exits>:\n{listing}"
        check_nested_exits(leaf_instructions(output, "cfg_nested_exits"))

    def reject(self, listing):
        with self.assertRaisesRegex(ValueError, "nested natural loops"):
            self.check(listing)

    def test_lookup_requires_a_reachable_load_through_the_table_base(self):
        sections = "  0 .literal 00000020 00002000 00002000\n  CONTENTS, ALLOC, LOAD, READONLY, DATA"
        leaf = dict(enumerate(["lea rax,[rip+0xff] # 2000", "mov eax,DWORD PTR [rax+rcx*4]", "ret"]))
        check_image_leaf("lookup", leaf, sections, "release")
        for load in ("mov eax,7", "mov eax,DWORD PTR [rdx+rcx*4]", "mov eax,DWORD PTR [rax+0x4]", "ret"):
            with self.subTest(load=load), self.assertRaisesRegex(ValueError, "load|lookup"):
                check_image_leaf("lookup", {**leaf, 1: load}, sections, "release")
        for overwrite in ("mov rax,rdx", "mov eax,edx", "mov ah,dl", "and eax,0x7"):
            body = [leaf[0], overwrite, leaf[1], "ret"]
            with self.subTest(overwrite=overwrite), self.assertRaisesRegex(ValueError, "lookup"):
                check_image_leaf("lookup", dict(enumerate(body)), sections, "release")
        bypass = dict(enumerate(["je 2", leaf[0], leaf[1], "ret"]))
        with self.assertRaisesRegex(ValueError, "lookup"):
            check_image_leaf("lookup", bypass, sections, "debug")
        with self.assertRaisesRegex(ValueError, "immutable section"):
            check_image_leaf("lookup", leaf, sections.replace("READONLY", "DATA"), "debug")

    def test_global_pointer_requires_the_used_relocation_and_alias(self):
        code = ["mov rax,QWORD PTR [rip+0x10] # 401010 <_ZL7current>", "mov QWORD PTR [rsp+0x8],rax",
                "mov rax,QWORD PTR [rsp+0x8]", "mov rdx,QWORD PTR [rax]", "mov rax,QWORD PTR [rsp+0x8]",
                "mov QWORD PTR [rax],rdx", "mov QWORD PTR [rip+0x8],rdx # 401008 <_ZL7counter>",
                "mov rax,QWORD PTR [rsp+0x8]", "mov rax,QWORD PTR [rax]", "ret"]
        sections = [(0x401000, 32, 0, "CONTENTS, ALLOC, LOAD, DATA")]
        report = "ImageBase 400000\nreloc 0 offset 10 [1010] DIR64"
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "global_pointer.exe"
            image.write_bytes(bytes(16) + (0x401008).to_bytes(8, "little"))
            def check(body, pe_report=report):
                check_global_leaf(image, dict(enumerate(body)), sections, pe_report, "release")

            check(code)
            check([*code[:2], "nop", "sub r9,rcx", "cmp QWORD PTR [rsp+0x8],rdx", *code[2:]])
            for broken in (report.replace("1010", "1018"), report.replace("DIR64", "ABSOLUTE")):
                with self.assertRaisesRegex(ValueError, "DIR64"):
                    check(code, broken)
            with self.assertRaisesRegex(ValueError, "pointer read or write"):
                check([line.replace("[rax],rdx", "[rcx],rdx") for line in code])
            for overwrite in ("mov QWORD PTR [rsp+0x8],rdx", "mov BYTE PTR [rsp+0xc],al",
                              "add rsp,0x8", "seto spl", "push rdx", "pop r9"):
                with self.subTest(overwrite=overwrite), self.assertRaisesRegex(ValueError, "overwritten"):
                    check([*code[:2], overwrite, *code[2:]])
            with self.assertRaisesRegex(ValueError, "straight-line"):
                check(["je 3", *code])  # Reach the first reload without executing the spill.
            with self.assertRaisesRegex(ValueError, "direct counter update"):
                check([*code[:6], *code[7:9], code[6], code[9]])
            image.write_bytes(bytes(32))
            with self.assertRaisesRegex(ValueError, "pointer initializer"):
                check(code)

    def test_image_target_join_requires_distinct_sections_on_branch_arms(self):
        sections = ("  0 .choicea 00000008 00002000 00002000\n  CONTENTS, ALLOC, LOAD, READONLY, DATA\n"
                    "  1 .choiceb 00000008 00003000 00003000\n  CONTENTS, ALLOC, LOAD, READONLY, DATA")
        body = ["test rcx,rcx", "je 6", "lea r8,[rip+0x20] # 3000", "xor r10,r10", "sub r11,r11", "jmp 9",
                "lea r8,[rip+0x10] # 2000", "xor r10d,r10d", "sub r11d,r11d", "sub r10d,0x1", "mov eax,0xffffffff",
                "sub r10,rax", "add eax,0x4", "mov r9,r8", "add r9,r10", "add r9,r11", "add r9,rax",
                "mov QWORD PTR [rsp+0x8],r9", "mov r10,QWORD PTR [rsp+0x8]", "movzx eax,WORD PTR [r10+0x1]",
                "add rax,rdx", "ret"]
        check_image_leaf("image_target_join", dict(enumerate(body)), sections, "debug")
        interior = dict(enumerate(body))
        interior[2] = body[2].replace("3000", "3001")
        interior[6] = body[6].replace("2000", "2001")
        check_image_leaf("image_target_join", interior, sections, "release")
        for index, change, reason in ((1, "jmp 6", "expected 'je'"), (2, "lea r8,[rip+0x20] # 2004", "distinct"),
                                      (3, "xor r10d,r10d", "xor r10,r10"), (5, "jmp a", "shared join"),
                                      (8, "sub r11d,r10d", "sub r11d,r11d"), (9, "sub r10,0x1", "sub r10d,0x1"),
                                      (12, "jmp d", "add eax,0x4"), (13, "mov r9,r11", "mov r9,r8"),
                                      (18, "mov r10,QWORD PTR [rsp+0x10]", r"rsp\+0x8")):
            modified = dict(enumerate(body))
            modified[index] = change
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, reason):
                check_image_leaf("image_target_join", modified, sections, "release")

    def test_retarget_requires_a_writable_relocated_slot_and_distinct_targets(self):
        body = ["test rcx,rcx", "je 7", "lea r9,[rip+0x8] # 402000 <.other>", "cmp rcx,0x1", "je 6",
                "lea r9,[rip+0x8] # 401000 <.initial>",
                "mov QWORD PTR [rip+0x8],r9 # 403000 <.ptrslot>", "mov r8,QWORD PTR [rip+0x8] # 403000 <.ptrslot>",
                "lea r9,[r8+0x2]", "add WORD PTR [r9],dx", "mov rax,QWORD PTR [r8]", "ret"]
        sections = [(0x401000 + n * 4096, 8, n * 8, "CONTENTS, ALLOC, LOAD, DATA") for n in range(3)]
        report = "ImageBase 400000\nreloc 0 offset 0 [3000] DIR64"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "global_retarget.exe"
            path.write_bytes(bytes(16) + (0x401000).to_bytes(8, "little"))
            def check(code):
                check_global_leaf(path, dict(enumerate(code)), sections, report, "debug")

            check(body)
            # Both addresses and the relocated slot are present, but every call replaces it.
            always_retarget = [body[5], body[2], *body[6:]]
            with self.assertRaisesRegex(ValueError, "test rcx,rcx"):
                check(always_retarget)
            for index, change, reason in ((2, body[2].replace("402000", "401000"), "cross writable sections"),
                                          (1, "je 8", "same slot reload"), (4, "je 7", "same pointer store"),
                                          (6, body[6].replace(",r9", ",rdx"), "expected 'mov QWORD PTR"),
                                          (8, "lea r9,[r8+0x4]", "expected 'lea r9"),
                                          (9, "jmp a", "expected 'add WORD PTR")):
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, reason):
                    check([*body[:index], change, *body[index + 1:]])

    def test_global_static_uses_the_live_weights_base_in_the_loop(self):
        sections = [(0x401000, 32, 0, "CONTENTS, ALLOC, READONLY, DATA"),
                    (0x402000, 32, 32, "CONTENTS, ALLOC, DATA")]
        store = "mov DWORD PTR [rip+0x8],eax # 402000 <_ZZ13global_staticE5total>"
        weights = "[rip+0x10] # 401000 <_ZL7weights>"
        debug = ["nop", "lea rax," + weights, "mov edx,DWORD PTR [rdx+rax*1]", store, "jne 1", "ret"]
        release = ["lea r8," + weights, "je 6", "mov eax,ecx", "add eax,DWORD PTR [r8+rdx*4]", store,
                   "jne 2", "ret"]

        def check(code, config):
            check_global_leaf(Path("global_static.exe"), dict(enumerate(code)), sections, "", config)

        check(debug, "debug")
        check(release, "release")
        check([*release[:2], "cmp r8,rdx", *release[3:]], "release")
        for config, broken in (("debug", ["je 2", *debug[1:]]),
                               ("debug", [*debug[:2], "mov edx,DWORD PTR [rdx+rcx*1]", *debug[3:]]),
                               ("release", [*release[:3], "add eax,DWORD PTR [rax+rdx*4]", *release[4:]]),
                               ("release", [*release[:2], "mov r8d,ecx", *release[3:]])):
            with self.subTest(config=config, body=broken), self.assertRaisesRegex(ValueError, "weights base"):
                check(broken, config)

    def test_frame_loop_must_store_inside_a_reachable_loop(self):
        instructions = dict(enumerate([
            "push rbp", "mov rbp,rsp", "sub rsp,0x10", "mov QWORD PTR [rbp-0x10],rdx",
            "mov rax,QWORD PTR [rbp-0x10]", "mov QWORD PTR [rbp-0x10],rax", "add DWORD PTR [rbp-0x4],0x1",
            "cmp eax,DWORD PTR [rbp-0x8]", "jb 4", "add rsp,0x10", "pop rbp", "ret"]))
        check_frame("count_locals", instructions, "debug")
        instructions[8] = "jb 6"
        with self.assertRaisesRegex(ValueError, "stack-resident accumulator"):
            check_frame("count_locals", instructions, "debug")
        instructions[0] = "nop"
        with self.assertRaisesRegex(ValueError, "RBP frame"):
            check_frame("count_locals", instructions, "debug")

    def test_frame_branch_has_three_reachable_epilogue_paths(self):
        instructions = dict(enumerate([
            "push rbp", "mov rbp,rsp", "sub rsp,0x10", "mov BYTE PTR [rbp-1],al",
            "mov WORD PTR [rbp-4],dx", "mov DWORD PTR [rbp-8],eax", "cdqe",
            "js a", "je b", "jmp c", "jmp c", "jmp c", "add rsp,0x10", "pop rbp", "ret"]))
        check_frame("branch_locals", instructions, "debug")
        instructions[8] = "je a"
        with self.assertRaisesRegex(ValueError, "three return paths"):
            check_frame("branch_locals", instructions, "debug")

    def test_nested_after_first_return(self):
        self.check(NESTED)

    def test_release_calculate_requires_all_array_slots_and_multiply(self):
        def check(body):
            check_frame("calculate", dict(enumerate(["sub rsp,0x28", *body, "add rsp,0x28", "ret"])), "release")

        body = ["mov QWORD PTR [rsp+0x8],rax", "mov QWORD PTR [rsp],r9", "mov QWORD PTR [rsp+0x10],rdx",
                "mov r10,QWORD PTR [rsp+0x10]", "mov rdx,QWORD PTR [rsp]", "mov r8,QWORD PTR [rsp+0x8]",
                "imul rdx,r8"]
        check(body)
        for incomplete in ([*body[:3], *body[4:]], body[1:], body[:-1],
                           ["mov rax,rcx", "imul rax,rdx", "add rax,rcx", "add rax,rdx"]):
            with self.subTest(body=incomplete), self.assertRaisesRegex(ValueError, "array slots"):
                check(incomplete)

    def test_release_branch_requires_reachable_returns_and_matching_loads(self):
        body = ["sub rsp,0x18", "mov BYTE PTR [rsp+0x9],al", "mov WORD PTR [rsp+0xa],dx",
                "mov DWORD PTR [rsp+0xc],r8d", "movsx r9d,WORD PTR [rsp+0xa]", "movzx eax,BYTE PTR [rsp+0x9]",
                "movsxd r11,DWORD PTR [rsp+0xc]", "js a", "add rsp,0x18", "ret", "add rsp,0x18", "ret"]
        check_frame("branch_locals", dict(enumerate(body)), "release")
        for index, replacement, reason in ((7, "jmp a", "two reachable returns"), (4, "mov eax,edx", "movsx"),
                                           (5, "movzx eax,BYTE PTR [rsp+0x8]", "movzx"),
                                           (3, "mov r8d,edx", "movsxd")):
            instructions = dict(enumerate(body))
            instructions[index] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, reason):
                check_frame("branch_locals", instructions, "release")

    def test_release_loop_requires_load_and_store_of_one_rsp_slot_inside_loop(self):
        body = ["sub rsp,0x18", "mov QWORD PTR [rsp+0x8],rdx", "mov r8,QWORD PTR [rsp+0x8]",
                "add r8,rax", "mov QWORD PTR [rsp+0x8],r8", "jne 2", "add rsp,0x18", "ret"]
        check_frame("count_locals", dict(enumerate(body)), "release")
        for changed in ([s.replace("rsp+0x8", "rcx") for s in body],
                        [*body[:4], "mov QWORD PTR [rsp+0x10],r8", *body[5:]],
                        [*body[:4], "jne 2", body[4], *body[6:]]):
            with self.subTest(body=changed), self.assertRaisesRegex(ValueError, "stack-resident accumulator"):
                check_frame("count_locals", dict(enumerate(changed)), "release")

    def test_former_nested_exits(self):
        # Control transfers of the previous compiled fixture, at offsets from its export.
        self.reject("""
            06: js 58
            0b: je 4b
            10: je 50
            17: jmp 2c
            19: lea r8,[rax+r8+7]
            25: je 3c
            27: cmp rdx,rax
            2a: je 40
            2c: test al,1
            2e: je 19
            3a: jne 27
            3c: mov rax,r8
            3f: ret
            40: add r8,1000
            4a: ret
            4b: xor r8d,r8d
            4e: jmp 3c
            50: mov r8d,1000
            56: jmp 3c
            58: mov r8,-7
            5f: jmp 3c
        """)

    def test_sequential_loops(self):
        self.reject("10: jne 10\n20: jne 20\n30: je 50\n40: ret\n50: ret")

    def test_two_latches_one_header(self):
        self.reject("10: je 40\n20: jne 10\n30: ret\n40: jne 10\n50: ret")

    def test_backward_jumps_to_shared_return(self):
        self.reject("10: je 60\n20: jmp 40\n30: ret\n40: je 30\n50: jmp 30\n60: ret")

    def test_unreachable_nesting_and_transfer(self):
        self.reject("01: je 03\n02: ret\n03: ret\n" + NESTED)
        self.check(NESTED + "a0: jmp rax\n")

    def test_missing_inner_or_outer_exit(self):
        self.reject(NESTED.replace("40: je 80", "40: cmp rcx,rdx"))
        self.reject(NESTED.replace("60: je 90", "60: cmp rcx,rdx"))
        # A peeled inner exit before the inner header cannot witness the outer exit.
        self.reject(NESTED.replace("60: je 90", "60: cmp rcx,rdx").replace("31: je 60", "31: je 80"))

    def test_one_reachable_return(self):
        with self.assertRaisesRegex(ValueError, "two reachable returns"):
            self.check(NESTED.replace("80: ret", "80: jmp 11").replace("90: ret", "90: jmp 11"))

    def test_adjacent_symbol_is_outside_leaf(self):
        adjacent = "\na0 <neighbor>:\na0: ret\n"
        self.check(NESTED + adjacent)
        with self.assertRaisesRegex(ValueError, "invalid direct target"):
            self.check(NESTED.replace("40: je 80", "40: je a0") + adjacent)

    def test_malformed_or_unsupported_transfers_keep_provenance(self):
        for transfer in ("jmp 71", "jne nowhere", "jmp rax", "call 11", "ret 8", "loop 40", "syscall"):
            output = "10 <cfg_nested_exits>:\n" + NESTED.replace("40: je 80", "40: " + transfer)
            with self.subTest(transfer=transfer), patch("build.subprocess.check_output", return_value=output):
                with self.assertRaises(ValueError) as failure:
                    check_leaf(Path("cfg_nested_exits.exe"))
                self.assertIn("cfg_nested_exits.exe", str(failure.exception))
                self.assertIn(output, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
