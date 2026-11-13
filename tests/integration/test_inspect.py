"""Black-box checks against the CLI and independent LLVM fixture metadata."""
import json
import os
from pathlib import Path
import re
import struct
import sys
import unittest

from pe_layout import Layout
from cli_case import Case, FIXTURES, SUITE


class Metadata(Case):
    def test_minimal(self):
        r = self.report(self.copy("minimal.exe"), "--strict")
        m, = r["modules"]
        self.assertEqual((m["machine"], m["pe_type"], m["image_kind"]), ("AMD64", "PE32+", "exe"))
        text, = m["sections"]
        self.assertEqual((text["name"], text["permissions"], text["rva"]), (".text", "r-x", m["entry_point_rva"]))
        for key in ("imports", "exports", "relocations"):
            self.assertEqual(m[key], [])
        self.assertIsNone(m["tls"])
        self.assertIsNone(m["exceptions"])
        self.assertEqual(r["diagnostics"], [])

    def test_linked_metadata(self):
        exe = self.copy("metadata.exe")
        self.copy("Physics.DLL")
        r = self.report(exe, "--strict")
        m, dll = r["modules"]
        oracle = self.readobj("metadata.exe", "--file-headers", "--sections", "--coff-imports",
                              "--coff-basereloc", "--coff-tls-directory", "--unwind")
        def address(field):
            return int(re.search(r"^\s*" + field + r": \(?(0x[0-9a-fA-F]+)", oracle, re.M)[1], 16)
        self.assertEqual(int(m["image_base_va"], 16), address("ImageBase"))
        self.assertEqual(int(m["entry_point_rva"], 16), address("AddressOfEntryPoint"))
        physics = next(i for i in m["imports"] if i["normalized_name"] == "physics.dll")
        self.assertEqual(physics["name"], "Physics.DLL")
        self.assertCountEqual(physics["symbols"], [{"name": "Named"}, {"ordinal": 7}])
        self.assertIn("Symbol: Named (1)", oracle)
        self.assertIn("Symbol:  (7)", oracle)
        addresses = [int(e["rva"], 16) for b in m["relocations"] for e in b["entries"] if e["type"] == 10]
        self.assertEqual(addresses, [int(x, 16) for x in re.findall(r"Type: DIR64\s+Address: (0x\w+)", oracle)])
        self.assertTrue(addresses)
        t = m["tls"]
        for key, label in [("raw_data_start_va", "StartAddressOfRawData"), ("raw_data_end_va", "EndAddressOfRawData"),
                           ("index_va", "AddressOfIndex"), ("callbacks_va", "AddressOfCallBacks")]:
            self.assertEqual(int(t[key], 16), address(label))
        self.assertEqual(t["zero_fill_size"], 4)
        f, = m["exceptions"]["functions"]
        base = int(m["image_base_va"], 16)
        for key, label in [("begin_rva", "StartAddress"), ("end_rva", "EndAddress"), ("unwind_info_rva", "UnwindInfoAddress")]:
            self.assertEqual(base + int(f[key], 16), address(label))
        self.assertEqual(t["callback_vas"], [hex(address("StartAddress"))])
        self.assertEqual(m["exceptions"]["size"], 12)
        self.assertEqual([e["ordinal"] for e in dll["exports"]], [1, 7, 8])
        self.assertEqual([e["names"] for e in dll["exports"]], [["Named"], [], ["Forward"]])
        self.assertEqual(dll["exports"][-1]["forwarder"], "KERNEL32.Sleep")
        self.assertIn("Name: Named", self.readobj("Physics.DLL", "--coff-exports"))
        for s in m["sections"]:
            self.assertLessEqual(s["file_offset"] + s["raw_size"], exe.stat().st_size)
        self.assertEqual({d["status"] for d in r["dependencies"]}, {"resolved", "external_api"})

    def test_delay_symbols(self):
        m = self.report(self.copy("delay.exe"), "--strict")["modules"][0]
        delay, = m["imports"]
        self.assertEqual(delay["load_type"], "delay")
        self.assertCountEqual(delay["symbols"], [{"ordinal": 7}, {"name": "Named"}])

    def test_original_first_thunk_fallback(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        struct.pack_into("<I", data, info.file_offset(info.directory(1)[0]), 0)
        path = self.dir / "iat.exe"
        path.write_bytes(data)
        imports = self.report(path)["modules"][0]["imports"]
        self.assertCountEqual(imports[0]["symbols"], [{"ordinal": 7}, {"name": "Named"}])


class Dependencies(Case):
    def test_order_and_case(self):
        exe = self.copy("metadata.exe", "app/game.exe")
        first = self.copy("Physics.DLL", "one/pHYsics.dll")
        second = self.copy("Physics.DLL", "two/Physics.dll")
        def selected():
            r = self.report(exe, "--dll-path", first.parent, "--dll-path", second.parent, "--strict")
            d = next(d for d in r["dependencies"] if d["kind"] == "application")
            self.assertEqual(d["search_directory"], str(Path(d["path"]).parent))
            return d
        self.assertEqual(selected()["path"], str(first))
        local = self.copy("Physics.DLL", "app/physics.DLL")
        self.assertEqual(selected()["path"], str(local))

    def test_no_ambient_search(self):
        exe = self.copy("metadata.exe", "app/game.exe")
        self.copy("Physics.DLL", "app/sub/Physics.DLL")
        self.copy("Physics.DLL")
        p = self.invoke("inspect", exe, "--format", "json", cwd=self.dir,
                        env=dict(os.environ, PATH=str(self.dir)))
        r = json.loads(p.stdout)
        missing, = [d for d in r["dependencies"] if d["status"] == "missing"]
        self.assertEqual(missing["kind"], "unknown")
        self.assertEqual(missing["searched_paths"], [str(exe.parent)])
        self.assertEqual(r["diagnostics"][0]["code"], "DLL_NOT_FOUND")
        strict = self.report(exe, "--strict", code=3)
        self.assertEqual(strict, r)

    def test_importer_directory_precedes_explicit_paths(self):
        exe = self.copy("graph.exe")
        first = self.copy("i386.exe", "first/Middle.dll").parent
        second = self.copy("Bridge.dll", "second/Bridge.dll").parent
        middle = self.copy("Middle.dll", second / "Middle.dll")
        self.copy("Late.dll", second / "Late.dll")
        r = self.report(exe, "--dll-path", first, "--dll-path", second)
        edge, = [d for d in r["dependencies"] if d["name"] == "Middle.dll"]
        self.assertEqual(edge["path"], str(middle))
        self.assertEqual(edge["searched_paths"], [str(second)])

    def test_system_name_and_file_identity(self):
        exe = self.copy("graph.exe")
        bridge = self.copy("Bridge.dll")
        self.copy("Middle.dll")
        # Two requested names refer to one physical module in a cycle.
        os.link(bridge, self.dir / "Late.dll")
        r = self.report(exe, "--strict")
        self.assertEqual(len(r["modules"]), 3)
        direct, delay = [d for d in r["dependencies"] if d["importer"] == 0]
        self.assertEqual(direct["target_module"], delay["target_module"])
        self.assertEqual(sum(d["name"] == "Middle.dll" for d in r["dependencies"]), 1)
        self.copy("i386.exe", "KERNEL32.dll")
        self.copy("Physics.DLL")
        r = self.report(self.copy("metadata.exe"), "--strict")
        self.assertEqual(r["summary"], {"resolved": 1, "external_api": 1})

    def test_hard_links_resolve_from_each_importing_directory(self):
        exe = self.copy("graph.exe")
        direct = self.copy("Bridge.dll", "direct/Bridge.dll").parent
        delay_alias = self.copy("Late.dll", "delay/Late.dll")
        delayed = delay_alias.parent
        os.link(delay_alias, direct / "Middle.dll")
        args = ("inspect", exe, "--dll-path", direct, "--dll-path", delayed, "--strict", "--format", "json")
        for incompatible, compatible, code in [(direct, delayed, 3), (delayed, direct, 0)]:
            with self.subTest(code=code):
                self.copy("i386.exe", incompatible / "MissingLeaf.dll")
                self.copy("Physics.DLL", compatible / "MissingLeaf.dll")
                p = self.invoke(*args, code=code)
                self.assertEqual(p.stdout, self.invoke(*args, code=code).stdout)
                r = json.loads(p.stdout)
                self.assertEqual(len(r["modules"]), 4)
                leaves = [d for d in r["dependencies"] if d["name"] == "MissingLeaf.dll"]
                self.assertEqual(len(leaves), 2)
                self.assertEqual({Path(d["importer_directory"]) for d in leaves}, {direct, delayed})
                self.assertEqual(leaves[0]["importer"], leaves[1]["importer"])
                self.assertEqual(r["diagnostics"][0]["code"], "DLL_ARCH_MISMATCH")
                for edge in leaves:
                    parent = Path(edge["importer_directory"])
                    self.assertEqual(edge["path"], str(parent / "MissingLeaf.dll"))
                    self.assertEqual(edge["required"], parent == direct)
                    if parent == incompatible:
                        self.assertEqual(edge["status"], "incompatible")
                        self.assertNotIn("target_directory", edge)
                        self.assertEqual(r["dependencies"][r["diagnostics"][0]["dependency"]], edge)
                    else:
                        self.assertEqual(edge["status"], "resolved")
                        self.assertEqual(edge["target_directory"], str(parent))
                aliases = [d for d in r["dependencies"] if d.get("target_module") == leaves[0]["importer"]]
                self.assertEqual({d["target_directory"] for d in aliases}, {str(direct), str(delayed)})

    def test_symlink_uses_target_directory(self):
        exe = self.copy("graph.exe")
        bridge = self.copy("Bridge.dll", "lib/Bridge.dll")
        (exe.parent / bridge.name).symlink_to(bridge)
        middle = self.copy("Middle.dll", "lib/Middle.dll")
        r = self.report(exe)
        edge, = [d for d in r["dependencies"] if d["name"] == "Bridge.dll"]
        self.assertEqual(edge["search_directory"], str(exe.parent))
        self.assertEqual(edge["target_directory"], str(bridge.parent))
        child, = [d for d in r["dependencies"] if d["name"] == "Middle.dll"]
        self.assertEqual(child["importer_directory"], str(bridge.parent))
        self.assertEqual(child["path"], str(middle))

    def test_classification_and_strict(self):
        for filename, code in [("contract.exe", 3), ("delay-contract.exe", 0)]:
            with self.subTest(filename=filename):
                exe = self.copy(filename)
                self.copy("Physics.DLL", "api-ms-win-core-file-l1-2-0.dll")
                r = self.report(exe, "--strict", code=code)
                d, = r["dependencies"]
                self.assertEqual((d["kind"], d["status"]), ("api_set", "unresolved_contract"))
                self.assertEqual(r["diagnostics"][0]["code"], "API_SET_MAPPING_UNAVAILABLE")
                self.assertEqual(d["required"], bool(code))
                self.assertEqual(r, self.report(exe))
        exe = self.copy("runtime.exe")
        d, = self.report(exe, "--strict", code=3)["dependencies"]
        self.assertEqual((d["kind"], d["status"]), ("third_party_runtime", "missing"))
        self.copy("Physics.DLL", "vcruntime140.dll")
        d, = self.report(exe, "--strict")["dependencies"]
        self.assertEqual((d["kind"], d["status"]), ("third_party_runtime", "resolved"))

    def test_incompatible_candidate_shadows_later_dll(self):
        exe = self.copy("metadata.exe")
        fallback = self.copy("Physics.DLL", "fallback/Physics.DLL").parent
        for name, expected in [("i386.exe", "DLL_ARCH_MISMATCH"), ("minimal.exe", "DLL_INVALID_IMAGE")]:
            self.copy(name, "physics.dll")
            r = self.report(exe, "--dll-path", fallback, "--strict", code=3)
            d = next(d for d in r["dependencies"] if d["status"] == "incompatible")
            self.assertEqual(d["search_directory"], str(self.dir))
            self.assertEqual(r["diagnostics"][0]["code"], expected)
            if name == "i386.exe":
                self.assertEqual(d["detected_architecture"], "i386")
        (self.dir / "physics.dll").write_bytes(b"truncated")
        self.assertEqual(self.report(exe)["summary"]["incompatible"], 1)

    def test_unreadable_target_keeps_report(self):
        exe = self.copy("metadata.exe")
        (self.dir / "Physics.DLL").symlink_to("absent-target")
        r = self.report(exe, "--strict", code=3)
        self.assertEqual(r["summary"], {"inaccessible": 1, "external_api": 1})
        self.assertEqual(r["diagnostics"][0]["code"], "DLL_READ_ERROR")

    def test_cycle_transitive_search_and_promotion(self):
        child = self.dir / "lib"
        for name in ["Bridge.dll", "Middle.dll", "Late.dll"]:
            self.copy(name, child / name)
        for name, code in [("graph.exe", 3), ("optional.exe", 0)]:
            exe = self.copy(name)
            r = self.report(exe, "--dll-path", child, "--strict", code=code)
            self.assertEqual(len(r["modules"]), 4)
            leaf, = [d for d in r["dependencies"] if d["name"] == "MissingLeaf.dll"]
            self.assertEqual(leaf["required"], bool(code))
            self.assertEqual(leaf["searched_paths"], [str(child)])
            self.assertTrue(any(d.get("target_module") == 1 for d in r["dependencies"] if d["importer"]))
            self.assertTrue(all(d["import_index"] < len(r["modules"][d["importer"]]["imports"]) for d in r["dependencies"]))

    def test_distinct_files_same_normalized_name(self):
        # Equal names in a lower-priority directory never create ambiguity.
        exe = self.copy("metadata.exe")
        self.copy("Physics.DLL")
        fallback = self.copy("i386.exe", "x/physics.dll").parent
        r = self.report(exe, "--dll-path", fallback, "--strict")
        self.assertEqual(r["summary"], {"resolved": 1, "external_api": 1})

    def test_case_collision(self):
        exe = self.copy("metadata.exe")
        self.copy("Physics.DLL")
        other = self.dir / "physics.dll"
        if other.exists():
            self.skipTest("case-sensitive directory required for same-directory collision")
        self.copy("Physics.DLL", other)
        r = self.report(exe, "--strict", code=3)
        d, = [d for d in r["dependencies"] if d["status"] == "ambiguous"]
        self.assertEqual(d["candidates"], sorted([str(self.dir / "Physics.DLL"), str(other)]))
        self.assertEqual(r["diagnostics"][0]["code"], "DLL_AMBIGUOUS")


class Malformed(Case):
    def invalid(self, data, expected):
        path = self.dir / "bad.exe"
        path.write_bytes(data)
        p = self.invoke("inspect", path, "--format", "json", code=1)
        self.assertEqual(p.stdout, b"")
        self.assertIn(expected.encode(), p.stderr)
        self.assertIn(str(path).encode(), p.stderr)

    def test_truncation_and_architecture(self):
        data = (FIXTURES / "metadata.exe").read_bytes()
        info = Layout(data)
        for length in (0, 2, 63, info.pe, info.opt + 100, info.directories + 10, len(data) - 1):
            with self.subTest(length=length):
                self.invalid(data[:length], "INVALID_PE")
        self.invalid(bytes(100), "MZ")
        self.invalid((FIXTURES / "i386.exe").read_bytes(), "i386")

    def test_invalid_fields(self):
        original = (FIXTURES / "metadata.exe").read_bytes()
        info = Layout(original)
        reloc = info.file_offset(info.directory(5)[0])
        imports = info.file_offset(info.directory(1)[0])
        for offset, value, expected in [
            (0x3c, len(original), "file offset"),
            (info.opt, 0x10b, "expected PE32+"),
            (info.opt + 108, 800, "available bytes"),
            (reloc + 4, 0, "relocation block size"),
            (reloc + 4, 1024, "base relocations"),
            (info.directories + 3 * 8 + 4, 11, "partial AMD64 runtime function"),
            (imports, 0x7fff0000, "import lookup table"),
            (imports + 12, 0x7fff0000, "import DLL name"),
            (info.directories + 8 + 4, 20, "imports"),
        ]:
            with self.subTest(offset=offset, value=value):
                data = bytearray(original)
                struct.pack_into("<I", data, offset, value)
                self.invalid(data, expected)

    def test_analysis_skips_import_and_export_details(self):
        for fixture, directory, field, expected in (
            ("metadata.exe", 1, 12, "import DLL name"),
            ("delay.exe", 13, 4, "import DLL name"),
            ("Physics.DLL", 0, 32, "export name pointers"),
        ):
            with self.subTest(fixture=fixture):
                baseline = self.invoke("analyze", FIXTURES / fixture, "--functions", "--format", "json")
                data = bytearray((FIXTURES / fixture).read_bytes())
                layout = Layout(data)
                offset = layout.file_offset(layout.directory(directory)[0])
                struct.pack_into("<I", data, offset + field, 0x7fff0000)
                self.invalid(data, expected)
                analysis = self.invoke("analyze", self.dir / "bad.exe", "--functions", "--format", "json")
                self.assertEqual(analysis.stdout, baseline.stdout)

    def test_analysis_validates_consumed_directory_extents(self):
        for fixture, directory in (("metadata.exe", 1), ("delay.exe", 13), ("Physics.DLL", 0), ("add.exe", 3)):
            with self.subTest(fixture=fixture):
                data = bytearray((FIXTURES / fixture).read_bytes())
                layout = Layout(data)
                rva, _ = layout.directory(directory)
                limit, = (start + min(size, raw) for size, start, raw, _ in layout.sections
                          if start <= rva < start + min(size, raw))
                struct.pack_into("<I", data, layout.directories + 8 * directory + 4, limit - rva + 1)
                self.invalid(data, "range exceeds available bytes")
                self.invoke("analyze", self.dir / "bad.exe", "--functions", code=1 if directory == 3 else 0)

    def test_names_and_directory_forms(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        pos = info.file_offset(info.directory(1)[0])
        size, start, _, raw = info.sections[1]
        data[raw + size - 1] = ord("X")
        struct.pack_into("<I", data, pos + 12, start + size - 1)
        self.invalid(data, "unterminated name")
        data = bytearray((FIXTURES / "delay.exe").read_bytes())
        info = Layout(data)
        struct.pack_into("<I", data, info.file_offset(info.directory(13)[0]), 0)
        self.invalid(data, "RVA-based")
        data = bytearray((FIXTURES / "Physics.DLL").read_bytes())
        info = Layout(data)
        export = info.file_offset(info.directory(0)[0])
        struct.pack_into("<H", data, info.file_offset(info.u32(export + 36)), 1000)
        self.invalid(data, "export ordinal")

    def test_tls_template_end(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        tls = info.file_offset(info.directory(9)[0])
        start, = struct.unpack_from("<Q", data, tls)
        struct.pack_into("<Q", data, tls + 8, start - 1)
        self.invalid(data, f"INVALID_PE: TLS directory at file offset {tls + 8:#x}")
        struct.pack_into("<Q", data, tls + 8, start)
        path = self.dir / "empty-template.exe"
        path.write_bytes(data)
        template = self.report(path)["modules"][0]["tls"]
        self.assertEqual(template["raw_data_start_va"], template["raw_data_end_va"])

    def test_unterminated_tls_callbacks(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        tls = info.file_offset(info.directory(9)[0])
        size, start, _, offset = info.sections[1]
        struct.pack_into("<Q", data, tls + 24, 0x140000000 + start + size - 8)
        struct.pack_into("<Q", data, offset + size - 8, 0x140001000)
        self.invalid(data, "TLS callback table")


class CLI(Case):
    def test_fifo_root_and_dependency(self):
        fifo = self.dir / "Physics.DLL"
        os.mkfifo(fifo)
        p = self.invoke("inspect", fifo, "--format", "json", code=1)
        self.assertEqual(p.stdout, b"")
        self.assertIn(b"READ_ERROR", p.stderr)
        self.assertIn(b"regular file", p.stderr)
        r = self.report(self.copy("metadata.exe"), "--strict", code=3)
        edge, = [d for d in r["dependencies"] if d["status"] == "inaccessible"]
        self.assertEqual(edge["path"], str(fifo))
        self.assertTrue(edge["required"])
        self.assertEqual(r["diagnostics"][0]["code"], "DLL_READ_ERROR")

    def test_help(self):
        commands = {"inspect": ("--dll-path", "--verbose", "--format", "--strict"),
                    "analyze": ("--functions", "--format", "--strict"),
                    "lift": ("--rva", "--output", "--signature", "--diagnostics-format")}
        for name, expected in [("", commands), *commands.items()]:
            with self.subTest(command=name):
                args = [name] if name else []
                help_text = self.invoke(*args, "--help", "--unused")
                short = self.invoke(*args, "-h")
                self.assertEqual(help_text.stderr, b"")
                self.assertEqual((short.stdout, short.stderr), (help_text.stdout, b""))
                usage = " ".join(["Usage: forge", *args])
                self.assertIn(usage.encode(), help_text.stdout)
                for token in expected:
                    self.assertIn(token.encode(), help_text.stdout)
                if args:
                    for other in {"--dll-path", "--functions", "--rva"}.difference(expected):
                        self.assertNotIn(other.encode(), help_text.stdout)

    def test_usage_and_io_errors(self):
        image = FIXTURES / "minimal.exe"
        for args in [
            (), ("unknown",), ("--", "inspect", image), ("--inspect.verbose", image),
            ("inspect",), ("analyze", "--functions"), ("analyze", image),
            ("lift", image, "--rva", "0"), ("lift", image, "--output", "out.ll"),
            ("lift", "--rva", "0", "--output", "out.ll"), ("inspect", image, "lift"),
            ("inspect", "--unknown", "--help"), ("inspect", "--format", "yaml", "--help"),
            ("inspect", image, "extra", "--help"), ("inspect", "--format", "--help"),
            ("inspect", image, "--", "--help"), ("inspect", "--format=json", image),
            ("inspect", image, "--format=", "json"), ("inspect", "--strict=false", image),
            ("inspect", image, "--strict=true"), ("inspect", "-hello"), ("inspect", "-"),
            ("inspect", "--format", "JSON", image), ("inspect", "--format", "", image),
            ("inspect", image, "--dll-path"), ("inspect", image, "--dll-path", self.dir / "absent"),
            ("inspect", image, "--dll-path", image), ("inspect", image, "--functions"),
            ("analyze", image, "--functions", "--verbose"), ("lift", image, "--strict"),
            ("inspect", image, "--format", "bad", "--format", "text"),
            ("lift", image, "--rva", "0", "--output", "--anything"),
            ("lift", image, "--rva", "0", "--output", ""),
        ]:
            with self.subTest(args=args):
                result = self.invoke(*args, code=2)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr.startswith(b"forge: "))
                self.assertIn(b"Usage: forge", result.stderr)
        missing = self.invoke("inspect", self.dir / "absent", code=1)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"READ_ERROR", missing.stderr)

    def test_complete_reports(self):
        image = self.copy("minimal.exe")
        # Complete pre-migration reports, including whitespace and final LF.
        section = dict(file_offset=512, name=".text", permissions="r-x", raw_size=512,
                       rva="0x1000", virtual_size=1)
        module = dict(entry_point_rva="0x1000", exceptions=None, exports=[], image_base_va="0x140000000",
                      image_kind="exe", imports=[], machine="AMD64", path=str(image), pe_type="PE32+",
                      relocations=[], sections=[section], tls=None)
        inspection = dict(dependencies=[], diagnostics=[], inspection=dict(root_module=0, status="completed"),
                          modules=[module], schema_version=1, summary={})
        analysis = dict(diagnostics=[], functions=[], schema_version=1,
                        unknown_executable_ranges=[dict(end_rva="0x1001", start_rva="0x1000")])
        for args, expected in [
            (("inspect", "--format", "text", "--strict", image, "--strict", "--format", "json"), inspection),
            (("analyze", "--functions", image, "--format", "json", "--functions"), analysis),
        ]:
            result = self.invoke(*args)
            wire = (json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
            self.assertEqual((result.stdout, result.stderr), (wire, b""))

    def test_literal_paths(self):
        for name in ("--help", "--format=json", "-", "--", "++", "[[aa]]", "lift", "name with spaces"):
            with self.subTest(name=name):
                image = self.copy("minimal.exe", name)
                expected = self.invoke("inspect", image, "--format", "json").stdout
                marked = self.invoke("inspect", "--format", "json", "--", name, cwd=self.dir)
                self.assertEqual((marked.stdout, marked.stderr), (expected, b""))
                if not name.startswith("-"):
                    ordinary = self.invoke("inspect", name, "--format", "json", cwd=self.dir)
                    self.assertEqual((ordinary.stdout, ordinary.stderr), (expected, b""))

    def test_lift_outputs_and_repeated_values(self):
        image = self.copy("add.exe")
        output = self.dir / "-h"
        unused = self.dir / "earlier.ll"
        args = ("lift", image, "--output", unused, "--output", "-h")
        first = self.invoke(*args, "--rva", "04096", cwd=self.dir)
        self.assertEqual((first.stdout, first.stderr), (b"", b""))
        module = output.read_bytes()
        self.assertIn(b"forge_lifted_1000", module)
        self.assertFalse(unused.exists())
        output.unlink()
        second = self.invoke(*args, "--rva", "0", "--rva", "0X1000", cwd=self.dir)
        self.assertEqual((second.stdout, second.stderr, output.read_bytes()), (b"", b"", module))

        for invalid in ("", "+4096", "-1", "0x", "0x12z", "4294967296", "0x100000000", "0b1", " 4096"):
            with self.subTest(rva=invalid):
                result = self.invoke(*args, "--rva", invalid, "--rva", "4096", cwd=self.dir, code=2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Usage: forge", result.stderr)
        output.write_bytes(b"keep")
        for tail in (("--unknown",), ("--signature", "i32()"), ("--diagnostics-format", "yaml")):
            failed = self.invoke(*args, "--rva", "0x1000", *tail, cwd=self.dir, code=2)
            self.assertEqual(failed.stdout, b"")
            self.assertEqual(output.read_bytes(), b"keep")

        failure = self.invoke(*args, "--rva", "0x1001", "--diagnostics-format", "text",
                              "--diagnostics-format", "json", cwd=self.dir, code=1)
        diagnostic = dict(category="invalid_input", code="ENTRY_INVALID_START",
                          context=dict(entry_rva="0x1001", input=str(image)),
                          message="0x1001: expected an exact, valid, unambiguous discovered function start",
                          schema_version=1, stage="entry")
        wire = (json.dumps(diagnostic, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n").encode()
        self.assertEqual((failure.stdout, failure.stderr, output.read_bytes()), (b"", wire, b"keep"))

    def test_determinism_and_streams(self):
        exe = self.copy("metadata.exe")
        args = ("inspect", exe, "--format", "json")
        p = self.invoke(*args)
        self.assertIn(b"DLL_NOT_FOUND", p.stderr)
        for _ in range(3):
            self.assertEqual(self.invoke(*args).stdout, p.stdout)
        self.assertEqual(self.invoke(*args, "--strict", code=3).stdout, p.stdout)
        t = self.invoke("inspect", exe)
        self.assertIn(b"PE32+ AMD64", t.stdout)
        self.assertNotIn(b"ordinal 7", t.stdout)
        verbose = self.invoke("inspect", exe, "--verbose")
        self.assertIn(b"ordinal 7", verbose.stdout)
        self.assertIn(b"Relocations at page", verbose.stdout)
        self.assertNotIn(b"Relocations at page", t.stdout)
        self.assertEqual(self.invoke(*args, "--verbose").stdout, p.stdout)
        self.assertEqual(verbose.stderr, t.stderr)
        self.assertIn(b"TLS directory RVA", t.stdout)
        self.assertIn(b"DLL_NOT_FOUND", t.stderr)
        self.assertNotIn(b"DLL_NOT_FOUND", t.stdout)


if __name__ == "__main__":
    suite = {"metadata": Metadata, "dependencies": Dependencies, "malformed": Malformed, "cli": CLI}[SUITE]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite))
    sys.exit(not result.wasSuccessful())
