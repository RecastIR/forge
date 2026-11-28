"""Build SDK-free Windows machine-code fixtures with deterministic timestamps."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def generate(output, mc, link, dlltool, clang):
    output.mkdir(parents=True, exist_ok=True)
    metadata = Path(__file__).with_name("metadata.s").read_text()
    stub = ".text\n.globl entry\nentry:\n  retq\n"
    helper = ".text\n.globl __delayLoadHelper2\n__delayLoadHelper2:\n  retq\n"
    contract = "api-ms-win-core-file-l1-2-0.dll"
    definitions = {
        "Physics.DLL": ["Named=entry @1", "ByOrdinal=entry @7 NONAME", "Forward=KERNEL32.Sleep"],
        "Late.dll": ["Later=entry"],
        "ForgeAbi.dll": ["Pair", "Triple", "Four", "Six", "WriteProbe", "Address", "Handle", "Bad", "TailByte"],
        "Bridge.dll": ["Bridge=entry"],
        "Middle.dll": ["Middle=entry"],
        "MissingLeaf.dll": ["Leaf"],
        "KERNEL32.dll": ["Sleep", "SwitchToThread", "SetLastError", "GetLastError", "lstrlenA",
                         "GetStdHandle", "WriteFile", "ExitProcess", "GetCommandLineA", "GetCommandLineW", "SetStdHandle", "GetFileType", "GetFileSize",
                         "CreateJobObjectA", "SetInformationJobObject", "AssignProcessToJobObject", "GetCurrentProcess",
                         "SetUnhandledExceptionFilter", "__C_specific_handler", "GetStartupInfoA", "GetStartupInfoW"],
        "vcruntime140.dll": ["Runtime"],
        "msvcrt.dll": ["_cexit", "_onexit", "exit", "_errno", "fopen", "fclose", "fputc", "setvbuf",
                       "__set_app_type", "_fileno", "_get_osfhandle", "memset", "fwrite", "__getmainargs", "_amsg_exit", "_initterm", "calloc", "free", "malloc", "strlen",
                       "__C_specific_handler", "_fmode=entry DATA", "_commode=entry DATA",
                       "__initenv=entry DATA", "_acmdln=entry DATA"],
        contract: ["Contract"],
    }
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder)

        def run(*args):
            subprocess.run(args, cwd=work, check=True)

        for dll, exports in definitions.items():
            # Import libraries use the public spelling, including NONAME ordinals.
            public = [line.split("=")[0] + (" " + line.split(" ", 1)[1] if " " in line else "")
                      for line in exports]
            definition = work / (dll + ".def")
            definition.write_text("LIBRARY " + dll + "\nEXPORTS\n" + "\n".join(public) + "\n")
            run(dlltool, "-m", "i386:x86-64", "-d", definition, "-l", dll + ".lib")

        def image(filename, assembly=stub, imports=(), delays=(), exports=(), link_flags=(), entry="entry"):
            assembly += helper if delays else ""
            for _, symbol in imports:
                assembly += "\n.section .rdata,\"dr\"\n.quad __imp_" + symbol + "\n"
            source = work / "image.s"
            source.write_text(assembly)
            run(mc, "-triple=x86_64-pc-windows-msvc", "-filetype=obj", source, "-o", "image.obj")
            flags = ["/entry:" + entry, "/subsystem:console"]
            if filename in definitions:
                definition = work / "exports.def"
                definition.write_text("EXPORTS\n" + "\n".join(definitions[filename]) + "\n")
                flags = ["/dll", "/noentry", "/def:exports.def", "/implib:unused.lib"]
            run(link, "/nodefaultlib", "/timestamp:0", *flags, *link_flags, *("/export:" + name for name in exports), "/out:" + filename, "image.obj",
                *dict.fromkeys(dll + ".lib" for dll, _ in imports),
                *("/delayload:" + dll for dll in delays))
            (output / filename).write_bytes((work / filename).read_bytes())

        sources = Path(__file__).resolve().parent
        for name in ("executable-return", "executable-call", "executable-data", "executable-fault",
                     "executable-tib", "executable-guarded-call", "recursive-continuation"):
            image(f"{name}.exe", (sources / f"{name}.s").read_text())
        protect_def = work / "memory.def"
        protect_def.write_text("LIBRARY KERNEL32.dll\nEXPORTS\nVirtualProtect\nVirtualAlloc\nVirtualFree\nVirtualQuery\nGetSystemInfo\n")
        run(dlltool, "-m", "i386:x86-64", "-d", protect_def, "-l", "memory.lib")
        memory_libraries = ["memory.lib", "KERNEL32.dll.lib"]
        query = (sources / "executable-virtual-query.s").read_text()
        image("executable-virtual-query.exe", query, link_flags=memory_libraries)
        image("executable-virtual-query-transitions.exe", "transitions = 1\n" + query, link_flags=memory_libraries)
        image("executable-virtual-query-address.exe", """.text
.globl entry
.seh_proc entry
entry:
  .seh_endprologue
  movq __imp_VirtualQuery(%rip), %rcx
  testq %rcx, %rcx
  je 1f
  movl $42, %eax
  retq
1: xorl %eax, %eax
  retq
.seh_endproc
""", link_flags=memory_libraries)
        run(clang, "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding", "-fno-stack-protector",
            "-c", sources / "virtual-query-reference.c", "-o", "query.obj")
        run(link, "/nodefaultlib", "/timestamp:0", "/entry:entry", "/subsystem:console",
            "/out:virtual-query-reference.exe", "query.obj", *memory_libraries)
        (output / "virtual-query-reference.exe").write_bytes((work / "virtual-query-reference.exe").read_bytes())
        protect = (sources / "executable-virtual-protect.s").read_text()
        image("executable-virtual-protect.exe", protect, link_flags=memory_libraries)
        image("executable-virtual-protect-denied.exe", "deny_write = 1\n" + protect, link_flags=memory_libraries)
        for case in ("rmw", "atomic", "adapter", "guard", "code", "iat", "executable", "immutable"):
            setup = "bad_target = 1\n" if case in ("code", "iat", "immutable") else ""
            image(f"executable-virtual-protect-{case}.exe", setup + f"deny_{case} = 1\n" + protect,
                  link_flags=memory_libraries)
        image("executable-virtual-protect-origin.exe", "observe_original = 1\n" + protect, link_flags=memory_libraries)
        image("executable-virtual-protect-fresh.exe", "fresh_page = 1\n" + protect, link_flags=memory_libraries)
        image("executable-virtual-protect-errors.exe", (sources / "executable-virtual-protect-errors.s").read_text(),
              link_flags=memory_libraries)
        sections = (sources / "executable-virtual-protect-sections.s").read_text()
        for name, setup in (("sections", ""), ("dynamic", "dynamic_count = 1\n"),
                            ("split", "split_output = 1\n")):
            image(f"executable-virtual-protect-{name}.exe", setup + sections, link_flags=memory_libraries)
        reference = "virtual-protect-reference.exe"
        run(clang, "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding", "-fno-stack-protector",
            "-c", sources / "virtual-protect-reference.c", "-o", "reference.obj")
        run(link, "/nodefaultlib", "/timestamp:0", "/entry:entry", "/subsystem:console",
            "/out:" + reference, "reference.obj", *memory_libraries)
        (output / reference).write_bytes((work / reference).read_bytes())
        stream_def = work / "streams.def"
        stream_def.write_text("LIBRARY msvcrt.dll\nEXPORTS\n__iob_func\n")
        run(dlltool, "-m", "i386:x86-64", "-d", stream_def, "-l", "streams.lib")
        close_def = work / "close.def"
        close_def.write_text("LIBRARY KERNEL32.dll\nEXPORTS\nCloseHandle\n")
        run(dlltool, "-m", "i386:x86-64", "-d", close_def, "-l", "close.lib")
        run(clang, "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding", "-fno-stack-protector",
            "-c", sources / "crt-stream-reference.c", "-o", "streams.obj")
        stream_pe = "crt-stream-reference.exe"
        run(link, "/nodefaultlib", "/timestamp:0", "/entry:entry", "/subsystem:console",
            "/out:" + stream_pe, "streams.obj", "streams.lib", "close.lib", "msvcrt.dll.lib", "KERNEL32.dll.lib")
        (output / stream_pe).write_bytes((work / stream_pe).read_bytes())
        streams = (sources / "crt-streams.s").read_text()
        for name, option in (("return", ""), ("exit", "crt_exit"), ("invalid", "invalid_stream"),
                             ("fault", "bad_source"), ("field", "write_field")):
            setup = (option + " = 1\n") if option else ""
            image("crt-stream-" + name + ".exe", setup + streams,
                  link_flags=["streams.lib", "msvcrt.dll.lib", "KERNEL32.dll.lib"])
        for name in ("state", "sections", "block"):
            image(f"crt-stream-{name}.exe", (sources / f"crt-stream-{name}.s").read_text(),
                  link_flags=["streams.lib", "msvcrt.dll.lib", "KERNEL32.dll.lib"])
        puts_def = work / "puts.def"
        puts_def.write_text("LIBRARY msvcrt.dll\nEXPORTS\nputs\n")
        run(dlltool, "-m", "i386:x86-64", "-d", puts_def, "-l", "puts.lib")
        format_def = work / "format.def"
        format_def.write_text("LIBRARY msvcrt.dll\nEXPORTS\nvfprintf\n")
        run(dlltool, "-m", "i386:x86-64", "-d", format_def, "-l", "format.lib")
        run(clang, "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding",
            "-funwind-tables", "-fno-stack-protector", "-c", sources / "crt-vfprintf.c", "-o", "emit.obj")
        formatter = (sources / "crt-vfprintf.s").read_text()
        variants = ("empty", "mixed", "numbers", "pointer", "boundary", "large",
                    "null_format", "null_string", "unknown", "null_stream", "edges", "mapped",
                    "padding", "sign", "field_body", "trailing", "zero_pad", "precision",
                    "errno_string", "errno_slot", "literal_empty", "literal_text", "eilseq")
        for variant in variants:
            switches = "".join(f"{name} = {int(name == variant)}\n" for name in variants)
            image(f"crt-vfprintf-{variant}.exe", switches + formatter,
                  link_flags=["/dynamicbase:no", "/fixed:no", "emit.obj", "format.lib", "puts.lib",
                              "streams.lib", "msvcrt.dll.lib", "KERNEL32.dll.lib"])
        abort_def = work / "abort.def"
        abort_def.write_text("LIBRARY msvcrt.dll\nEXPORTS\nabort\n")
        run(dlltool, "-m", "i386:x86-64", "-d", abort_def, "-l", "abort.lib")
        abort_probe = (sources / "crt-abort.s").read_text()
        for name, switches in (("direct", ()), ("buffered", ("buffered",)),
                               ("control", ("buffered", "control")), ("initializer", ("initializer",)),
                               ("cleanup", ("cleanup",))):
            options = "".join(f"{flag} = {int(flag in switches)}\n" for flag in ("cleanup", "control", "buffered", "initializer"))
            image(f"crt-abort-{name}.exe", options + abort_probe,
                  link_flags=["/section:.CRT,RW", "abort.lib", "format.lib", "streams.lib",
                              "msvcrt.dll.lib", "KERNEL32.dll.lib"])
        puts = (sources / "crt-puts.s").read_text()
        for name in ("heap", "immutable", "terminators"):
            image(f"crt-puts-{name}.exe", (sources / f"crt-puts-{name}.s").read_text(),
                  link_flags=["puts.lib", "msvcrt.dll.lib"])
        for name, options in (("hello", ["hello"]), ("mixed", ["mixed"]), ("exit", ["mixed", "crt_exit"]),
                              ("exitprocess", ["mixed", "win_exit"]), ("direct", ["direct"]),
                              ("newline", ["newline_flush"]), ("null", ["null_input"]), ("fault", [])):
            setup = "".join(symbol + " = 1\n" for symbol in options)
            image(f"crt-puts-{name}.exe", setup + puts,
                  link_flags=["puts.lib", "streams.lib", "msvcrt.dll.lib", *memory_libraries])
        returns = (sources / "executable-return.s").read_text()
        for dll in ("KERNEL32.dll", "msvcrt.dll"):
            name = dll.split(".")[0].lower()
            image(f"executable-seh-{name}.exe", (sources / "executable-seh.s").read_text(),
                  [(dll, "__C_specific_handler")])
        image("executable-integrity.exe", returns, link_flags=["/integritycheck"])
        image("executable-manifest.exe", returns, link_flags=[
            "/manifest:embed",
            "/manifestdependency:type='win32' name='Forge.Missing' version='1.0.0.0' processorArchitecture='amd64'",
        ])
        image("executable-last-error.exe", (sources / "executable-last-error.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError")])
        image("executable-import-thunk.exe", (sources / "executable-import-thunk.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "ExitProcess")])
        image("executable-import-register.exe", (sources / "executable-import-register.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "Sleep")])
        image("executable-cmp16mi.exe", (sources / "executable-cmp16mi.s").read_text(),
              [("KERNEL32.dll", name) for name in ("GetLastError", "GetStdHandle", "WriteFile")],
              exports=["compare_at"])
        image("executable-forward-call.exe", (sources / "executable-forward-call.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "ExitProcess")],
              exports=["outer", "many_bounds", "many_load", "many_site", "late_edge", "slots",
                       "slots_end", "writer", "single_callback", "tail_callback", "replacement",
                       "bad_return", "bad_save", "terminal", "empty", "tamper_null", "null_only", "null_site"])
        bounded = (sources / "executable-bounded-call.s").read_text()
        image("executable-bounded-cleanup.exe", "with_cleanup = 1\n" + bounded,
              [("msvcrt.dll", "_onexit"), ("msvcrt.dll", "_cexit"), ("KERNEL32.dll", "ExitProcess")],
              exports=["run_count", "count_site", "count_table", "writer"])
        image("executable-bounded-call.exe", bounded,
              [("KERNEL32.dll", "ExitProcess")],
              exports=["entry", "run_count", "run_one", "run_empty", "one", "two", "writer",
                       "count_table", "one_table", "empty_table", "replacement", "after_count",
                       "count_site", "unrelated_cell", "exclusive", "tamper_count", "tamper_scan", "shorten_mixed", "bad_nonvolatile", "bad_return", "terminal", "run_mixed", "mixed_table",
                       "run_switch", "switch_table", "switch_site", "overrun_switch", "mixed_site"])
        image("bounded-budget.exe", bounded + (sources / "bounded-budget.s").read_text(),
              [("KERNEL32.dll", "ExitProcess")], entry="budget_runner",
              exports=["budget_table", "budget_tail", "budget_tail_site"])
        image("executable-tail-jump.exe", (sources / "executable-tail-jump.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "ExitProcess")],
              exports=["bad_register", "nested_clobber", "bad_stack", "bad_memory", "terminal", "pivot"])
        startup_info = (sources / "executable-startup-info.s").read_text()
        for variant in ("a", "w"):
            setup = f"conditional_title = 1\nmeasured_fields = 1\nprobe_{variant} = 1\n"
            image(f"executable-startup-title-{variant}.exe", setup + startup_info,
                  link_flags=["KERNEL32.dll.lib"])
        for variants in ("a", "w", "aw"):
            setup = "".join(f"probe_{variant} = 1\n" for variant in variants)
            image(f"executable-startup-info-{variants}.exe", setup + startup_info,
                  link_flags=["KERNEL32.dll.lib"])
        image("executable-startup-info-fields.exe",
              "probe_a = 1\nprobe_w = 1\nmeasured_fields = 1\n" + startup_info,
              link_flags=["KERNEL32.dll.lib"])
        image("executable-startup-info-w-fault.exe", "probe_w = 1\nfault = 1\n" + startup_info,
              link_flags=["KERNEL32.dll.lib"])
        filter_source = (sources / "executable-top-level-filter.s").read_text()
        filter_imports = [("KERNEL32.dll", name) for name in ("SetUnhandledExceptionFilter", "ExitProcess")]
        image("executable-top-level-filter.exe", filter_source, filter_imports)
        image("executable-top-level-filter-fault.exe", "check_guest_fault = 1\n" + filter_source, filter_imports)
        image("executable-headers.exe", (sources / "executable-headers.s").read_text(),
              [("KERNEL32.dll", "lstrlenA")], link_flags=["/dynamicbase:no", "/fixed:no"])
        console_imports = [("KERNEL32.dll", name) for name in ("GetStdHandle", "WriteFile", "ExitProcess")]
        image("hello.exe", (sources / "hello.s").read_text(), console_imports)
        image("command-line.exe", (sources / "command-line.s").read_text(),
              [("KERNEL32.dll", "GetCommandLineA")])
        image("crt-argv-strlen.exe", (sources / "crt-argv-strlen.s").read_text(),
              [("msvcrt.dll", name) for name in ("__getmainargs", "strlen")])
        image("crt-argument-heap.exe", (sources / "crt-argument-heap.s").read_text(),
              [("msvcrt.dll", name) for name in ("__getmainargs", "calloc", "free", "strlen",
                                                 "_fmode", "_commode", "__initenv", "_acmdln")] +
              [("KERNEL32.dll", "GetCommandLineA")])
        initializer_flags = ["/section:.CRT,RW", "msvcrt.dll.lib", "KERNEL32.dll.lib"]
        app_type = (sources / "crt-app-type.s").read_text()
        for name, setup, subsystem in (("console", "", "console"), ("gui", "", "windows"),
                                       ("fatal-console", "fatal_type = 1", "console"),
                                       ("fatal-conflict", "fatal_type = 2", "console"),
                                       ("fatal-unusual", "fatal_type = -7", "console"),
                                       ("fatal-gui", "fatal_type = 1", "windows"),
                                       ("fatal-gui-unknown", "fatal_type = 2\nfatal_error = -1", "windows"),
                                       ("fatal-gui-newline", "fatal_type = 2\nfatal_error = 252", "windows")):
            image(f"crt-app-type-{name}.exe", setup + "\n" + app_type,
                  link_flags=[*initializer_flags, "/subsystem:" + subsystem])
        image("crt-app-type-argument.exe", "caller_argument = 1\nfatal_type = 0\n" + app_type,
              link_flags=initializer_flags)
        image("crt-initterm.exe", (sources / "crt-initterm.s").read_text(), link_flags=initializer_flags)
        image("crt-initterm-spill.exe", (sources / "crt-initterm-spill.s").read_text(),
              link_flags=[*initializer_flags, "/base:0x400000"])
        initializer_probe = (sources / "crt-initterm-probe.s").read_text()
        for variant in ("terminal", "guest_fault", "unknown_target", "data_target", "other_function",
                        "other_initializer", "clobber", "bad_rsp", "read_return", "before_return", "write_return",
                        "service_return", "register_arg", "nonvolatile_arg", "stack_arg", "stack_alias",
                        "service_alias", "tail_alias", "nested_table", "stack_exhaustion"):
            image(f"crt-initterm-{variant}.exe", f"{variant} = 1\n" + initializer_probe, link_flags=initializer_flags)
        termination = (sources / "crt-termination.s").read_text()
        null_registration = (sources / "crt-termination-null.s").read_text()
        image("crt-term-null.exe", null_registration, link_flags=initializer_flags)
        for count in (16, 17):
            image(f"crt-term-depth-{count}.exe", f"finite_depth = {count}\n" + termination,
                  link_flags=initializer_flags)
        for name, switches in (
            ("cexit", ()), ("tail-registration", ("tail_registration",)), ("exit", ("normal_exit",)), ("nested-exit", ("normal_exit", "terminal")),
            ("register", ("add_during",)), ("recursive", ("add_during", "recurse")),
            ("recursive-order", ("add_during", "recurse", "trace_recursive_return")),
            ("recursive-limit", ("recurse_forever",)), ("recursive-exit", ("add_during", "recursive_exit")),
            ("fault", ("fault",)), ("nested-fault", ("add_during", "recurse", "nested_fault")),
            ("stdio", ("crt_stream",)),
            ("return-slot", ("corrupt_return",)), ("stack-above", ("stack_above",)),
            ("wrong-origin", ("changed_target", "needs_evidence")),
            ("unmapped", ("unmapped_target", "needs_evidence")), ("data", ("data_target", "needs_evidence"))):
            setup = "".join(f"{switch} = 1\n" for switch in switches)
            image(f"crt-term-{name}.exe", setup + termination, link_flags=initializer_flags)
        for name in ("startup", "stream", "stream_exit", "registration", "pressure"):
            run(clang, "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding",
                "-fno-stack-protector", "-D" + name.upper(), "-c", sources / "crt-termination-reference.c",
                "-o", "reference.obj")
            filename = f"crt-observe-{name}.exe"
            run(link, "/nodefaultlib", "/timestamp:0", "/entry:entry", "/subsystem:console",
                "/out:" + filename, "reference.obj", "msvcrt.dll.lib", "KERNEL32.dll.lib")
            (output / filename).write_bytes((work / filename).read_bytes())
        fatal = (sources / "crt-amsg-exit.s").read_text()
        for number in (31, 8, -1, -2147483648):
            image(f"crt-amsg-exit-{number}.exe", f"error_number = {number}\n" + fatal,
                  link_flags=["msvcrt.dll.lib"])
        image("crt-amsg-exit-unused.exe", fatal, link_flags=["msvcrt.dll.lib"])
        marker = "observe_continuation = 1\n" + fatal
        for variant, setup in (("fatal", "error_number = 31\n"), ("control", "")):
            image(f"crt-amsg-marker-{variant}.exe", setup + marker,
                  link_flags=["msvcrt.dll.lib", "KERNEL32.dll.lib"])
        # Retain the compiler's instructions after the call to a non-returning guest helper.
        run(clang, "--target=x86_64-pc-windows-msvc", "-O2", "-fno-stack-protector", "-c",
            sources / "executable-noreturn.c", "-o", "noreturn.obj")
        run(link, "/nodefaultlib", "/timestamp:0", "/entry:entry", "/subsystem:console",
            "noreturn.obj", "KERNEL32.dll.lib", "/out:executable-noreturn.exe")
        (output / "executable-noreturn.exe").write_bytes((work / "executable-noreturn.exe").read_bytes())
        console_cases = (sources / "console-cases.s").read_text()
        console_imports += [("KERNEL32.dll", name) for name in ("GetLastError", "SetLastError")]
        for entry in ("binary_stdout", "binary_stderr", "bad_handle", "stdin_write", "bad_selector",
                      "stdin_handle", "bad_buffer", "bad_count", "null_count", "overlapped",
                      "zero_length", "host_failure", "direct_exit", "nested_exit", "alternate_edge",
                      "isolation", "large_output", "limited_file", "stderr_failure",
                      "zero_stdout_failure", "zero_stderr_failure", "call_at_end", "branch_past_call",
                      "recursive_return", "recursive_exit"):
            image(f"console-{entry}.exe", console_cases, console_imports, entry=entry)
        # Remap debug paths so builds in different source directories produce identical PEs.
        for name in ("add", "inlined"):
            run(clang, "--target=x86_64-windows-msvc", "-O2", "-fwrapv", "-gdwarf-4", "-g",
                "-fdebug-compilation-dir=.", f"-ffile-prefix-map={sources}=.", "-S",
                sources / f"{name}.c", "-o", f"{name}.s")
            with (work / f"{name}.s").open("a") as assembly:
                assembly.write((sources / "leaf-range.s").read_text())
            run(mc, "-triple=x86_64-windows-msvc", "-filetype=obj", f"{name}.s", "-o", f"{name}.obj")
            run(link, "/nodefaultlib", "/timestamp:0", "/debug:dwarf", "/entry:entry", "/subsystem:console",
                f"/out:{name}.exe", f"{name}.obj")
            (output / f"{name}.exe").write_bytes((work / f"{name}.exe").read_bytes())
        cfg_leaves = sources.parent / "differential/fixtures/control_flow/cfg_cases.S"
        image("cfg.exe", (sources / "cfg.s").read_text() + cfg_leaves.read_text())
        jump_table = cfg_leaves.with_name("jump_table.S")
        image("jump.exe", (sources / "jump.s").read_text() + jump_table.read_text(),
              exports=["entry", "two_tables", "table_budget", "width_paths", "table_caller", "case_caller"])
        image("jump-dvrt.exe", (sources / "jump-dvrt.s").read_text(), exports=["entry", "direct_only"])
        image_assembly = (sources / "image.s").read_text()
        image("image.exe", image_assembly)
        image("image-fixed.exe", image_assembly, link_flags=["/fixed"])
        ranges = (sources / "image-ranges.s").read_text()
        for fields in (8, 64, 512):
            image(f"image-ranges-{fields}.exe", f".set fields, {fields}\n" + ranges,
                  exports=["entry"], link_flags=["/base:0x10000000"])
        leaf_calls = sources.parent / "differential/fixtures/functions/call_leaves.S"
        indirect = leaf_calls.with_name("call_indirect.S")
        image("indirect.exe", metadata + indirect.read_text(),
              exports=["indirect_preserve", "indirect_leaf", "indirect_recurse"])
        image("stack.exe", (sources / "stack.s").read_text())
        # A separate file-backed section lets CLI tests exercise both limits and boundary types.
        probe = ('.section .probe,"xr"\n.space 65568, 0xcc\n.quad entry\n.space 12, 0xcc\n'
                 '.seh_proc leaf_fence\nleaf_fence:\n.seh_endprologue\nret\n.seh_endproc\n.byte 0x0f\n')
        image("leaves.exe", stub + leaf_calls.read_text() + probe)
        last_error = (sources.parent / "differential/fixtures/imports/last_error.S").read_text()
        imports = [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "SwitchToThread")]
        image("last-error.exe", stub + ".globl last_error_set\n" + last_error, imports + [("Physics.DLL", "Named")], exports=["last_error_set"])
        image("last-error-delay.exe", stub + last_error, imports, delays=["KERNEL32.dll"])
        string_length = (sources.parent / "differential/fixtures/imports/lstrlen.S").read_text()
        image("lstrlen.exe", stub + string_length,
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "lstrlenA")])
        abi_imports = [("ForgeAbi.dll", name) for name in definitions["ForgeAbi.dll"]]
        image("service-abi.exe", (sources / "service-abi.s").read_text(),
              abi_imports + [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "lstrlenA")],
              exports=["pair", "triple", "four", "echo_bits", "six", "bad_stack", "bad_sig", "void_result", "repeat_after_void",
                       "write_call", "write_nested", "disjoint_record", "nested_disjoint", "nested_overlap", "nested_optional",
                       "unmapped", "stale_spill", "disjoint_spill", "image_output", "readonly_output",
                       "counted_boundary", "counted_with_load", "fixed_boundary", "counted_gap", "stack_count", "zero_count"])
        image("checked-memory.exe", (sources / "checked-memory.s").read_text(), [("KERNEL32.dll", "GetLastError")],
              exports=["entry", "guard_then_service", "bridge_value,data", "bridge_constant,data"])
        image("import-call.exe", (sources / "import-call.s").read_text(), [("Physics.DLL", "Named")])
        image("chained.exe", (sources / "chained.s").read_text())
        image("unicode.exe", stub + '.section ".donnée","dr"\n.byte 1\n.section ".界区","dr"\n.byte 1\n')
        image("arithmetic.exe", (sources / "arithmetic.s").read_text(),
              exports=["entry", "product", "expr", "low_product", "select_signed", "select_unsigned",
                       "equal", "immediates", "zero64", "zero32"])
        image("minimal.exe")
        image("Physics.DLL")
        image("metadata.exe", metadata, [("Physics.DLL", "Named"), ("Physics.DLL", "ByOrdinal"),
                                         ("KERNEL32.dll", "Sleep")])
        image("delay.exe", imports=[("Physics.DLL", "Named"), ("Physics.DLL", "ByOrdinal")],
              delays=["Physics.DLL"])
        image("delay-contract.exe", imports=[(contract, "Contract")], delays=[contract])
        image("contract.exe", imports=[(contract, "Contract")])
        image("runtime.exe", imports=[("vcruntime140.dll", "Runtime")])
        image("Bridge.dll", imports=[("Middle.dll", "Middle")])
        image("Middle.dll", imports=[("Late.dll", "Later")])
        image("Late.dll", imports=[("Bridge.dll", "Bridge"), ("MissingLeaf.dll", "Leaf")])
        image("graph.exe", imports=[("Bridge.dll", "Bridge"), ("Late.dll", "Later")], delays=["Late.dll"])
        image("optional.exe", imports=[("Late.dll", "Later")], delays=["Late.dll"])
        (work / "x86.s").write_text(".text\n.globl _entry\n_entry:\n  retl\n")
        run(mc, "-triple=i686-pc-windows-msvc", "-filetype=obj", "x86.s", "-o", "x86.obj")
        run(link, "/machine:x86", "/safeseh:no", "/nodefaultlib", "/entry:entry",
            "/subsystem:console", "/timestamp:0", "/out:i386.exe", "x86.obj")
        (output / "i386.exe").write_bytes((work / "i386.exe").read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mc", default="llvm-mc")
    parser.add_argument("--link", default="lld-link")
    parser.add_argument("--dlltool", default="llvm-dlltool")
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    generate(args.output, args.mc, args.link, args.dlltool, args.clang)
