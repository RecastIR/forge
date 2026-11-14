# Should Forge replace its x86-64 lifter?

**Recommendation, 12 November 2026. Keep Forge’s LLVM lifter.** Use upstream work to design tests and improve function recovery. Remill is the strongest candidate for instruction semantics, especially as Forge approaches floating point and SIMD. Its instruction semantics do not supply the guest memory, Windows call, and exception-delivery contracts. Those boundaries currently limit which programs Forge can translate. One carry fixture runs correctly with a small adapter. A second fixture exposes a conflict in Remill’s shift semantics. [Fixture evidence](#fit-against-forges-enabled-fixtures) · [Remill experiment](#remill-experiment)

This assessment uses Forge at `ea79a6862f6329a452659a4fac94b90ffcfb06c8`. **Local** means a command ran for this evaluation. **Upstream** means a published run at the cited revision completed. **Source** means an implementation, test, or build target exists at the pin. **Unverified** means the reviewed evidence does not establish the behavior. A selector, a passing compiler build, and a matching native execution answer different questions. [Forge revision][forge-rev]

## What Forge already does

| Stage | Following the exported `arithmetic/flag_adc` function |
| --- | --- |
| Inspect the file | Forge reads PE32+ AMD64 headers, sections, imports and delay imports, exports, relocations, TLS, and exception-directory records. The test resolves the named export to an RVA. The dependency report classifies DLLs and records resolution evidence. It does not bind callable host symbols. [PE reader](../src/pe/pe.cpp) · [Dependency resolver](../src/pe/dependencies.cpp) |
| Establish the range | The Debug PE has a 13-byte function at `[0x17f5, 0x1802)` with unwind RVA `0xc0bc`. Release has the same bytes at `[0x1595, 0x15a2)`. Discovery checks file-backed executable bounds and unwind metadata. It preserves duplicate indices, overlap diagnostics, and unknown ranges. A valid chained fragment can count as covered code without qualifying as an entry. DWARF can enrich a range with a name or source line. [Discovery](../src/analysis/analysis.cpp) · [Export resolution](../tests/differential/differential.py) |
| Decode and lift | At an exact eligible EXE function start, Forge rejects overlapping relocations and decodes the bounded range with LLVM 17 MC. It lowers reachable instructions. Here `cmpq` produces carry, `adcb` consumes it, `seto` writes AL, `lahf` packs five flags into AH, `movzwl` defines EAX and clears the upper half of RAX, and `ret` ends the leaf. Diagnostics identify the offending RVA, opcode and bytes for unsupported decoded forms. [Translator](../src/lift/lift.cpp) · [Integer and flag semantics](../src/lift/integer.cpp) |
| Cross the ABI and emit code | The internal RVA-named function takes a pointer to seven 64-bit slots in the order RAX, RCX, RDX, R8, R9, R10, R11. The `i64(i64,i64)` wrapper puts native arguments in RCX/RDX and returns RAX. The signatureless interface accepts incoming register contents. The wrapper checks that every observed bit, including the full return value, is defined. Forge verifies the module and publishes IR with the ARM64 Darwin triple. The test verifies the IR, uses `llc` to emit a Mach-O object, and links the existing decimal-pairs harness. [Lift interfaces](../src/lift/lift.cpp) · [Native build](../tests/CMakeLists.txt) · [Harness](../tests/support/decimal_pairs.cpp) |

**Control flow and undefined values.** Direct forward jumps and conditional branches must land on decoded boundaries within the function. At a join, Forge intersects defined register bits across predecessors and creates flag PHIs where incoming values differ. CF, PF, AF, ZF, SF, and OF begin undefined and have independent lifetimes. A consumed undefined flag fails lifting, even when a concrete bit pattern could make one test pass. A zero effective shift preserves flags. Counts exceeding one can invalidate OF. This distinction matters to any replacement that emits an unspecified value for the optimizer to consume. [Flag joins and instruction lowering](../src/lift/lift.cpp) · [Shift semantics](../src/lift/integer.cpp) · [Negative lift tests](../tests/integration/test_functions.py)

**The next boundaries.** LEA computes an address but provides no guest load/store contract. A stack access or real return needs an address space, RSP and a rule for invalid access. Inter-function calls need a continuation, caller/callee state, Windows stack and register conventions, and eventually import binding. An indirect jump needs evidence for its target set or an explicit unresolved outcome. COM calls add interface layout, pointer-sized vtable slots, and a method ABI. Unwind records currently authorize or qualify ranges. Delivering an exception would require restoring guest frames and selecting a compatible handler. Forge has no general guest runtime, application entry/loader path, x87/SSE/AVX lowering, or atomic memory model at this revision. [Supported forms and interface](../README.md#lift-and-run-a-native-function) · [Analysis model](../src/analysis/analysis.h)

## What the tests establish

The Windows catalog contains 29 fixtures. Each of the 19 enabled exports below has a Debug and Release obligation on `macos-arm64`, for **38 required case/configuration pairs**. Each pair needs *two* matching native executions, baseline IR and LLVM `default<O2>`, for 76 comparisons. The other ten include memory, calls, imports, C++ lifetime, and process behavior. Eight are reference-only and two have declared harness limitations. [Case definitions](../tests/differential/cases.json) · [Reviewed coverage baseline](../tests/differential/coverage-baseline.json) · [Fixture guide](../tests/differential/README.md)

| Enabled exports under `arithmetic/` | Observable behavior |
| --- | --- |
| `add_i64`, `weighted_pair_i64`, `integer_mix` | Compiler-generated addition, signed 64-bit branch with low-32-bit arithmetic on both paths, and shift/XOR/low multiply across the two-argument ABI. |
| `flag_add`, `flag_sub`, `flag_adc`, `flag_sbb` | Defined arithmetic flags via SETO and LAHF. ADC consumes a carry from CMP. SBB also tests a first-use self-compare and a self-subtract with borrow. |
| `carry_chain`, `neg_flags`, `logic_flags`, `multiply_flags` | CF across INC/DEC and NOT, NEG at zero and the sign boundary, defined logical flags, and signed word IMUL overflow and low product. |
| `mixed_widths`, `extensions` | High-byte aliasing, preserved bits on 8/16-bit writes, cleared upper halves on 32-bit writes, and signed/unsigned extensions from narrow sources. |
| `predicates`, `conditional_moves`, `joined_flags` | All sixteen conditions, CMOV at three widths, and flag values arriving at a common block from different arithmetic operations. |
| `shift_flags`, `shift_widths`, `shift_one` | Masked CL counts, byte/word/qword results, preservation at effective zero, and defined CF/OF for a one-bit shift. |

The assembly fixes the instruction forms at the PE input. The C cases also check what the compiler actually emitted. The Unicorn CTest executes original x86 bytes with a Windows call frame and compares RAX with native output. Separately, Wine runs the **whole Windows fixture** and captures exit status, stdout and stderr. The native comparator calls only the lifted export. The gate validates artifact identity, checks both IR variants and compares observed streams again. Application startup and translated whole-program execution are outside that comparison. [Assembly fixtures](../tests/differential/fixtures/arithmetic/integer_cases.S) · [Unicorn oracle](../tests/integration/test_native.py) · [Wine artifact validation](../tests/differential/reference/artifacts.py) · [Coverage gate](../tests/differential/coverage_report.py)

**Local validation at the Forge pin.** A fresh checkout on macOS 26.7.2 ARM64 used LLVM 17.0.6 and Unicorn 2.1.4. `./tools/test-forge.sh --native` passed formatting, clang-tidy, and all 17 CTests in both Debug and ASan/UBSan builds, including the native and Unicorn oracles. The initial sandbox run stopped with an illegal instruction in Unicorn. The full native rerun on the host passed. `./tools/test-forge.sh --differential` ran against the saved PE exports and revalidated Wine captures. Each configuration recorded 19 passing functions, 8 reference-only and 2 blocked. All 76 native variant comparisons matched, the eight differential integration checks passed, and the local coverage gate reported zero errors at this commit. Windows fixture compilation, Wine capture and hosted CI were not rerun.

## Candidate comparison

Dates below are the committer dates of the examined revisions. Integration cost is an engineering judgment for Forge’s PE64-to-Mach-O objective. Cost is lower for studying a technique than for adopting a runtime. Forge itself is [Apache-2.0](../LICENSE).

| Project and revision | Translation and platform evidence | Maintenance, license and cost to Forge |
| --- | --- | --- |
| [Remill, 66c488c][remill-rev] | XED → semantics bitcode → LLVM with guest state and memory/control hooks. **Upstream:** Linux and macOS LLVM 17 builds passed, alongside newer LLVM jobs. | 2026-11-10 rotate-flag fix. Apache-2.0. Medium/high integration cost for matching LLVM/bitcode, state, diagnostics and host ABI. [Build results][remill-run] · [Build inputs][remill-build] · [License][remill-license] |
| [McSema, 2636805][mcsema-rev] | Disassembler CFG → pinned Remill → LLVM and architecture-specific glue. Historical Linux AMD64 integration suite and PE64 x86 assembly runtime. Native macOS ARM64 unverified. | 2022-04-26, repository archived. AGPLv3-or-later source and a commonly used proprietary IDA workflow. Very high cost to own an old toolchain and recoverer. [Archive][mcsema-home] · [CMake][mcsema-build] · [Tests][mcsema-tests] · [License][mcsema-license] |
| [pcrecomp, 93a7432][pc-rev] | Python/Capstone PE64 recovery and generated C over a guest CPU. Title-oriented ports, Windows-specific EH and an x86-64 hardware oracle. General Darwin ARM64 PE64 execution unverified. | 2026-11-11. MIT with separate third-party notices. Low cost to study discovery cases, high to adopt its guest memory and C runtime. [Build template][pc-build] · [Tests][pc-tests] · [License][pc-license] · [Notices][pc-notice] |
| [SwARc, 6399a54][sw-rev] | Zydis 4.1.1 → C++ with a guest context, dispatch and native API shims. Linux and Apple Silicon hosts are documented. The x64 instruction oracle runs on x86-64. | 2026-11-09. MIT with third-party notices. CMake pulls in runtime components including SDL3 and SoftFloat. High cost to adopt the execution layer. [Decoder build][sw-decoder] · [Runtime build][sw-build] · [Hosts][sw-host] · [License][sw-license] · [Notices][sw-notice] |
| [FEX, ab135df][fex-rev] | Custom IR → ARM64 JIT. The offline compiler writes a cache for its runtime. Linux and Windows host paths, including ARM64EC. **Upstream:** tests passed on three Arm architecture levels. | 2026-11-12. MIT core with separately licensed dependencies including VIXL. Integration would require a new backend or FEX’s dispatcher and runtime. [Platform/build checks][fex-build] · [Build and test results][fex-run] · [Core license][fex-license] |
| [M-HT/SR, ac690dd][sr-rev] | SRW consumes i386 PE32. Its Septerra Core build can target ARM64 Darwin through LLVM with per-title inputs. No matching PE32+ test path. | 2026-08-27. Own code under MIT, also offered under GPLv2+ and LGPLv2.1+. Third-party terms vary. udis86, SCons, D and title shims. Very high cost for a new guest ISA and ABI. [Loader][sr-loader] · [Darwin target][sr-game] · [SRW build][sr-build] · [Licensing][sr-license] |

### Remill and McSema

Remill can replace a decoder and an instruction emitter. XED selects an instruction form. The lifter binds its operands to registers, memory and PC and calls the corresponding bitcode semantics. Its state layout includes GPRs, segment bases, flags, x87 and vector registers. The pinned source asserts a 3,504-byte x86 state layout. The amount of memory traffic that survives optimization depends on which state escapes the lifted function. Remill distinguishes an invalid decode and an unimplemented instruction. A consumer that accepted fallback IR without checking the lift status could publish an unsupported function as a success. [XED decoder][remill-xed] · [Instruction lifter][remill-lifter] · [State layout][remill-state]

There are concrete selectors for ADC/SBB, partial-register moves, CMOV, shifts, x87, SSE and AVX operations, and compare/exchange. The x86 tests compare native and lifted state. Two examples qualify those coverage claims. The x87 FBLD implementation records a precision limitation. Shift handlers can produce an unspecified flag value. Forge must still reject a later observable read if any incoming path leaves that flag undefined. Lock-prefixed read/modify/write also needs host atomicity and appropriate memory ordering from the consumer. An instruction count alone cannot settle any of these questions. [ADC and SBB][remill-adc] · [Shifts][remill-shift] · [SIMD arithmetic][remill-simd] · [x87 precision][remill-x87] · [Atomic operations][remill-atomic] · [Upstream test harness][remill-tests]

Remill’s trace takes a state pointer, guest PC and memory token, and returns the updated token. Its RET pops a guest address and its trace lifter calls a return hook. Indirect transfers likewise need a destination or a handler. The source builds guest-layout IR and inlines semantics. Getting standalone native code requires a host data layout, an ABI bridge, and definitions for live helpers. None of these supplies PE bounds, Win64 import/COM dispatch, or a Windows unwinder. The full build also couples LLVM and matching semantics bitcode with XED, glog, gflags and Sleigh. The matching LLVM 17 upstream build makes a same-version evaluation feasible. [Guest target][remill-target] · [RET semantics][remill-ret] · [Trace dispatch][remill-trace] · [Intrinsic contract][remill-hooks] · [Optimizer][remill-opt] · [Build][remill-build]

McSema illustrates the integration work above the instruction layer. Its schema separates code and data references, block successors, exception frames and externals. IDA-based table recovery supplies inferred targets. An instruction adapter invokes its older pinned Remill, then an optimizer rewrites memory intrinsics and removes redundant state operations. Its PE64 runtime generator emits x86-64 assembly and TLS, and its IDA exception collector reads DWARF exception frames. A Darwin ARM64 Windows unwinder remains separate work. Its documented LLVM 9–11 era, Remill/Anvill/Protobuf dependencies, archived status and AGPL terms weigh against importing that pipeline. The transferable idea is to retain the origin of each recovered successor and keep external declarations distinct from a resolved implementation. [CFG schema][mcsema-cfg] · [Jump tables][mcsema-tables] · [Remill pin][mcsema-remill] · [IR cleanup][mcsema-opt] · [PE64 runtime][mcsema-abi] · [Exception collection][mcsema-eh] · [Toolchain][mcsema-host]

### pcrecomp and SwARc

pcrecomp’s standalone x64 recovery starts from primary unwind entries, Guard CF targets and exports, follows direct edges, and recognizes bounded jump-table patterns. Its synthetic PE distinguishes a chained fragment from a function and exercises switch recovery. That is a concrete test design for Forge. The C generator consumes a function catalog and can identify selected FH3/FH4 metadata targets. Its runtime goes further for selected FH3 catches, restoring guest state and calling catch funclets. Windows TLS and port-specific callbacks appear in that implementation. Discovering an FH4 funclet address establishes neither its calling convention nor the ability to deliver a catch. [PE64 discovery and self-test][pc-recovery] · [Catalog and EH discovery][pc-gen] · [Exception runtime][pc-eh]

The 64-bit C emitter has partial-register operations, arithmetic flags, conditionals and SSE operations. Its CPU exposes sixteen GPRs, sixteen 128-bit XMM registers and directly dereferences mapped guest addresses. Its 64-bit path excludes x87/MMX and lacks upper YMM state. Dedicated atomic helpers exist, but the generic emitter strips LOCK before ordinary arithmetic lowering. An emitted ADD therefore cannot establish locked ADD correctness. The example CMake template configures fixed-base mapping for generated code. Its hardware differential tool constrains the sampled instructions to register/immediate forms and excludes control transfers and RSP. This is a useful oracle design within its stated domain. A Darwin LLVM backend, a portable guest address space and a Win64 COM bridge would still need independent evidence. [C emitter][pc-lift] · [CPU and memory][pc-state] · [Hardware oracle][pc-tests]

SwARc distinguishes a recognized table, an indirect tail dispatch and an unmapped target. Generated C++ can dispatch to a statically lifted entry or an import thunk, and the runtime reports an unresolved address. Its Win64 integer argument reader accounts for the four register arguments and 32-byte shadow space. Only shims marked as audited for x64 may enter that path. The shared COM vtable builder nevertheless allocates four bytes per entry and writes 32-bit thunk addresses. A 64-bit guest method load needs an eight-byte slot and the right interface/argument layout. Its SEH64 code does implement guest virtual unwinding. Assess each ABI path separately. [PE unwinds][sw-pe] · [Control-flow classifications][sw-flow] · [Dispatch][sw-dispatch] · [Win64 arguments][sw-abi] · [COM slots][sw-com] · [SEH64][sw-eh]

SwARc’s context includes x87, XMM, YMM upper halves, MXCSR and arithmetic flags. A C++ emitter can keep register values in locals until they must be committed. The x64 oracle runs original bytes on hardware and compares defined flags, registers and selected memory/FP state. It is a model for testing MXCSR and defined flag masks as Forge grows. Its wide atomic helper is evidence for a specific operation. Adopting its entire emitter would make Forge responsible for another CPU layout, dispatch runtime and C++ compilation pipeline. [Emitter][sw-emit] · [CPU context][sw-state] · [x64 oracle][sw-tests] · [Wide atomic helper][sw-atomic]

### FEX and M-HT/SR

FEX connects its x86 decoder and custom IR to an Arm JIT and per-thread CPU frame. Its offline compiler serializes blocks and relocations for the FEX code cache. The output needs FEX’s dispatcher. ARM64EC exception handling calls Windows/Wine services, and the root build admits Linux and Windows hosts. One SBB regression records incoming and outgoing carry while memory-fed operands keep the host register allocator from folding away a case where its destination aliases its first input. The flag code handles carry inversion, narrow widths and deferred materialization. x87 and AVX have distinct paths, and LOCKed arithmetic reaches atomic IR with Arm-specific lowering. Those examples can inform correctness tests and, once measured, flag liveness. They do not supply a PE-to-Mach-O linker, Win64 COM layer or LLVM AOT backend. [CPU frame][fex-state] · [JIT][fex-jit] · [Offline cache][fex-cache] · [ARM64EC exceptions][fex-eh] · [Flags][fex-flags] · [SBB regression][fex-test] · [x87][fex-x87] · [AVX][fex-avx] · [Locked arithmetic][fex-locked] · [Arm atomic backend][fex-atomic]

In M-HT/SR’s native Darwin build for Septerra Core, the scripts combine per-title labels, external procedures and instruction replacements with generated code and native shims. Its Windows loader checks for i386 PE32. Its D translator emits LLVM functions with a CPU pointer, `fastcc` and `nounwind`, and can dispatch using a 32-bit guest stack. ADC and x87 handlers exist. The game sidecar skips MMX detection and bypasses selected MMX regions. General SSE/AVX, atomics, PE64 exception handling and x64 COM are unverified. The useful convention is to keep user-supplied hints traceable beside the binary. Running its bundled decoder tests or selecting its arm64 target would not test Forge’s AMD64 fixture. [Game inputs][sr-script] · [Metadata reader][sr-hints] · [IR and return ABI][sr-ir] · [x87][sr-x87] · [Title-specific replacements][sr-mmx] · [Bundled decoder tests][sr-tests]

**Licensing and maintenance.** The permissive projects have separate dependency and notice files. Before copying any implementation, identify the license of the actual file and generated or linked runtime code. McSema’s AGPL headers, IDA dependency and frozen dependency set make source integration a separate licensing and maintenance decision for Apache-licensed Forge. Studying the behavior and writing a Forge fixture from a documented ISA rule requires no third-party code in the tree. The commit dates and CI runs above establish activity at the pin. Future support remains unverified.

### Fit against Forge’s enabled fixtures

| Candidate | What the reviewed evidence predicts for the fixture groups |
| --- | --- |
| Remill | The arithmetic, data-transfer, shift, CMOV and branch selectors cover the central operations in all six groups. CMOV selects the source or the old destination, then applies the zero-extending write, consistent with Forge’s 32-bit false-path rule. The SAR/SETC case below exposes a divergence. High-byte aliases and definedness at joins still need candidate fixture runs. Only `flag_adc` was run locally. [Arithmetic][remill-adc] · [Data transfer][remill-mov] · [CMOV][remill-cmov] · [Shifts][remill-shift] |
| pcrecomp / SwARc | Candidates for the integer and flag leaves. pcrecomp implements ADC/SBB, LAHF and shifts, and explicitly clears the upper half of a 32-bit CMOV destination even on the false path. SwARc supplies an original-byte x64 oracle and an argument bridge. Both would need their own state initialization and result extraction. Exact behavior on the 19 exports and Forge’s undefined-read diagnostics is unverified. [pcrecomp emitter][pc-lift] · [SwARc oracle][sw-tests] |
| McSema / FEX / SR | McSema inherits coverage from a historical Remill revision and requires recovered CFG and runtime inputs. FEX can exercise many equivalent guest operations under its emulator, which supplies no native LLVM comparison. SRW rejects the fixtures’ AMD64 PE headers before lifting. No local fixture pass is attributed to these projects. [McSema dependency pin][mcsema-remill] · [FEX runtime][fex-jit] · [SRW input check][sr-loader] |

**A source-level conflict in an enabled case.** `arithmetic/shift_flags` executes `sarb %cl, %dl` and observes CF with SETC. At counts 8 and 9, the validated Wine output has the carry bit set for low byte `0x81` and clear for `0x01`. Forge models the final bit shifted out. At the reviewed Remill commit, the SAR handler assigns `BUndefined()` to CF once the masked count reaches the operand width. That loses a bit the fixture observes. A constant implementation of undefined CF would fail one of those inputs. This finding comes from comparing the pinned source to validated fixture observations. Remill executed only the ADC experiment below. [Remill SAR][remill-sar] · [Forge lowering](../src/lift/integer.cpp) · [Assembly](../tests/differential/fixtures/arithmetic/integer_cases.S) · [Shift inputs and expected output](../tests/differential/manifests/arithmetic_shift_flags.json)

## Remill experiment

**Local result.** Remill lifted all 13 bytes, including RET. Both original modules passed LLVM 19 verification. Forge’s LLVM 17 rejected the untouched Release module. With a fixture-specific adapter, **all four ARM64 runs matched Wine** across 21 input pairs per run. This establishes that the carry calculation, six observed flags, register aliases and a checked one-word return work for this leaf. No guest instruction was removed.

The source survey used the November commit. The executable experiment used the official Linux/amd64 LLVM 19 image for **Remill v6.0.1**, source `0e324aee8c67a63ec759ef379dcfafa0b3cb1448`. The experiment used that image only to emit and verify IR. Apple Silicon running macOS 26.7.2 and Homebrew LLVM 17.0.6 built and executed the native results. Forge validated existing x86-64 Linux Wine 8.0 captures and each PE’s hash against its configuration. Wine was not recaptured. The manifest SHA-256 was `6346df4611b4e1fe8ee0b328caf5cee96e7733f6d4963f2489a4562c2fed94d4`. [Release CLI][release-cli] · [Fixture manifest](../tests/differential/manifests/arithmetic_flag_adc.json)

| Stage | Observation |
| --- | --- |
| Input | Both PEs contain `48 39 d1 10 d1 0f 90 c0 9f 0f b7 c0 c3`. The 21 pairs include carry into an 8-bit addition, overflow, and half-carry visible through LAHF. |
| Unmodified IR | The CLI produced the `RAX(RCX,RDX)` wrapper with Windows x86-64 triple and layout. `opt-19 -passes=verify` passed. Repeating the Release lift produced identical IR. LLVM 17.0.6 rejected the first `call range(i8 0, 9)` return annotation. The module also uses `or disjoint` and references nine Remill helpers. |
| Adapter | A temporary copy dropped two range annotations and five disjoint hints, set the ARM64 Darwin triple/layout, and named the wrapper `forge_lifted`. Four flag hooks return the bit already computed by the lifted instruction, following upstream’s own x86 test runtime. The other helpers set FSBASE/GSBASE to zero and RSP to 4096, read one 64-bit stack cell, and check the return. The memory hook traps on the wrong token or address. The return hook checks the token, sentinel PC `0x12345678`, guest RIP and final RSP of 4104. [Upstream flag-hook definitions][release-hooks] |
| Native execution | Both adapted modules passed LLVM 17 verification, compiled and linked as Mach-O arm64, and ran through Forge’s decimal-pairs harness before and after O2. Every run exited 0, wrote 119 bytes to stdout with SHA-256 `9c8724617f55cf32d98625acc7380183187f23a7f392155a27ee772410fb7213`, and wrote zero bytes to stderr. The comparator found zero mismatches. |
| Code quality | After O2 the adapted wrapper contains scalar SSA, a population-count intrinsic, and no state accesses or calls to Remill helpers. On the Debug PE, LLVM 17 produced 32 ARM64 instructions in its O2 `_forge_lifted` symbol and 30 in Forge’s. Counted with `llvm-objdump -d --disassemble-symbols=_forge_lifted`. Neither count measures execution time, and the fixture exercises only a fixed return slot. |

| SHA-256 | Debug | Release |
| --- | --- | --- |
| Input PE | `de1cfe45d6ce9d9a51ed89459a124a2504f9a4433fdff4bc448d306e08ec30f2` | `a2aba91db38337c9087fa2b5275192faec63f3f0e51f4b5b839caeef856a6dff` |
| Validated Wine result JSON | `fa10f90747ead16f2385273efdefac48904c0180869cefc7b75a69b0fc46b3fc` | `d56abd6e7b693bc890df3b4552da87c41d5c73e58ab183dca320fdb13517d078` |
| Untouched Remill IR | `e033713206329bd2d361ed59378733f1315a8b3301d0484fd4e36f0d174f71ec` | `c8d1e6c92877373be9a46f64f84be9e9f78e0396b1c386fecea7008e6dd9d742` |

<details>
<summary>Reproduce the lift, adapter, native builds and comparisons</summary>

From the Forge root on Apple Silicon, prepare `build/dev/forge`, both fixture exports and their matching validated Wine references as described in the [regression guide](../tests/differential/README.md#regression-ci-and-local-reproduction). Use the following blocks in the same shell. Only the temporary working directory is mounted into the upstream tool.

```sh
work=$(mktemp -d)
image=ghcr.io/lifting-bits/remill/llvm19-ubuntu24.04@sha256:41c768db853e328ae433643fc71f88f123ed1f747a8bb7378c95a799f7a81340
for config in debug release; do
    va=0x1400017f5
    if [ "$config" = release ]; then va=0x140001595; fi
    mkdir "$work/$config"
    docker run --rm --network none --platform linux/amd64 \
        --mount "type=bind,src=$work/$config,dst=/out" "$image" \
        --arch amd64 --os windows --address "$va" --bytes 4839d110d10f90c09f0fb7c0c3 \
        --signature 'RAX(RCX,RDX)' --ir_out /out/raw.ll
    docker run --rm --network none --platform linux/amd64 \
        --mount "type=bind,src=$work/$config,dst=/out,readonly" \
        --entrypoint /usr/bin/opt-19 "$image" -passes=verify -disable-output /out/raw.ll
done
```

To observe the producer/consumer version boundary, run `"$(brew --prefix llvm@17)/bin/opt" -passes=verify -disable-output "$work/release/raw.ll"`. The adapter below matches the pinned IR. Its state indices 13 and 33 address the RSP and RIP fields in that layout. The return check runs before the wrapper reads RAX.

```sh
python3 -E -B - "$work" <<'PY'
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import re, sys
sys.path.insert(0, str(Path("tests/differential").resolve()))
import differential as d

def adapt(raw, va):
    ir = raw
    def edit(pattern, replacement, count=1):
        nonlocal ir
        ir, actual = re.subn(pattern, lambda _: replacement, ir, flags=re.M)
        assert actual == count, (pattern, actual)
    edit(r"range\(i8 0, 9\) ", "", 2)
    edit(r"or disjoint i8", "or i8", 5)
    edit('^target triple = ".*"$', 'target triple = "arm64-apple-macosx11.0.0"')
    edit('^target datalayout = ".*"$', 'target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"')
    edit(f"@call_sub_{va:x}\\(", "@forge_lifted(")
    edit("store ptr undef, ptr %MEMORY.i", "store ptr @slot, ptr %MEMORY.i")
    ir += "\n@slot = internal constant i64 305419896, align 8\ndeclare void @llvm.trap()\n"
    def helper(suffix, result_type, args, body):
        symbol = "@__remill_" + suffix
        edit(r"^declare [^\n@]*" + symbol + r"\([^\n]*$", f"define {result_type} {symbol}({args}) {{\n{body}\n}}")
    for flag in ("carry", "sign", "zero", "overflow"):
        helper("flag_computation_" + flag, "zeroext i1", "i1 zeroext %bit, ...", "ret i1 %bit")
    for reg, value in (("STACK", 4096), ("GSBASE", 0), ("FSBASE", 0)):
        helper("symbolic_" + reg, "i64", "", f"ret i64 {value}")
    checked = "br i1 %ok, label %valid, label %bad\nbad:\ncall void @llvm.trap()\nunreachable\nvalid:\n"
    token = "%own = icmp eq ptr %mem, @slot\n"
    helper("read_memory_64", "i64", "ptr %mem, i64 %addr", token +
           "%top = icmp eq i64 %addr, 4096\n%ok = and i1 %own, %top\n" + checked +
           "%word = load i64, ptr %mem, align 8\nret i64 %word")
    def register(name, index):
        return (f"%{name}_p = getelementptr inbounds %struct.State, ptr %s, i32 0, i32 0, i32 6, "
                f"i32 {index}, i32 0, i32 0\n%{name} = load i64, ptr %{name}_p, align 8\n")
    helper("function_return", "ptr", "ptr %s, i64 %pc, ptr %mem", token +
           register("rsp", 13) + register("rip", 33) +
           "%target = icmp eq i64 %pc, 305419896\n%popped = icmp eq i64 %rsp, 4104\n%atpc = icmp eq i64 %rip, %pc\n"
           "%a = and i1 %own, %target\n%b = and i1 %popped, %atpc\n%ok = and i1 %a, %b\n" + checked + "ret ptr %mem")
    return ir

root = Path(sys.argv[1]).resolve()
manifest = next(m for m in d.load_catalog() if m.case["id"] == "arithmetic/flag_adc")
for config in ("debug", "release"):
    raw = (root / config / "raw.ll").read_bytes()
    expected_ir = {
        "debug": "e033713206329bd2d361ed59378733f1315a8b3301d0484fd4e36f0d174f71ec",
        "release": "c8d1e6c92877373be9a46f64f84be9e9f78e0396b1c386fecea7008e6dd9d742",
    }
    assert sha256(raw).hexdigest() == expected_ir[config]
    with TemporaryDirectory(dir=root) as tmp:
        job = Path(tmp)
        pe, digest = d.snapshot(d.BINARIES, config, manifest.case["binary"], job)
        wanted, _ = d.reference(d.REFERENCES, manifest, config, digest)
        start = d.analyze(Path("build/dev/forge").resolve(), pe, "flag_adc", job).start
        module = d.read_json(job / "inspect.json")["modules"][0]
        row, = [r for r in d.read_json(job / "analysis.json")["functions"] if int(r["start_rva"], 16) == start]
        stop = int(row["end_rva"], 16)
        sec, = [s for s in module["sections"] if int(s["rva"], 16) <= start and
                stop <= int(s["rva"], 16) + min(s["virtual_size"], s["raw_size"])]
        off = sec["file_offset"] + start - int(sec["rva"], 16)
        assert pe.read_bytes()[off:off + stop - start].hex() == "4839d110d10f90c09f0fb7c0c3"
        ir = job / "adapted.ll"
        ir.write_text(adapt(raw.decode(), int(module["image_base_va"], 16) + start))
        for variant in ("baseline", "o2"):
            out = job / variant
            out.mkdir()
            exe, _ = d.native.build(ir, "decimal_pairs", out, config, variant)
            actual = d.native.execute(exe, manifest.case["args"], out)
            assert not d.native_differences(wanted, actual, "decimal_pairs", manifest.case["args"])
            print(config, variant, actual.exit_code, len(actual.stdout), len(actual.stderr), sha256(actual.stdout).hexdigest())
PY
```

</details>

## Decision and integration boundaries

| Strategy | Correctness and ownership | Performance evidence | Cost and long-term flexibility |
| --- | --- | --- | --- |
| **A. Extend Forge** | LLVM MC owns decode, Forge owns semantics, definedness, state and CFG. Forge’s eventual runtime owns guest memory, imports and ABI transitions. Small changes can be reviewed against independent observations. Every new ISA form needs implementation and testing. | Current O2 leaf is small. Throughput for applications, SIMD and guest memory is unknown. | Smallest build and maintenance surface. Highest ongoing cost to cover the long tail of x86 semantics. |
| **B. Adopt Remill** | XED/Remill would own decode, instruction effects and architectural state. Forge would own PE ranges, CFG policy, diagnostics, all-path read eligibility, guest memory/return hooks, Win64 host bridges and LLVM AOT output. Budget for replacing the old semantic path and mapping public state interfaces at the boundary. | Inlining removed all helper calls from the adapted O2 leaf. Memory, indirect flow and FP may retain calls/state traffic. Benchmark representative workloads before predicting a speedup. | Gains implementations for difficult instructions and upstream fixes. Costs include dependencies, matching LLVM majors, a wider state ABI, upgrade/retest work, and diagnostics at two boundaries. Matching LLVM majors may remove the textual IR workaround. The runtime contract still needs an implementation. |
| **C. Keep Forge and adopt selected techniques** | Same owners as A. Extend the existing discovery model with evidence and the existing tests with independently derived examples. Each opcode has one emitter and one analysis model owns the evidence, including conflicting records at one address. | The selection introduces no runtime machinery. Measure any later lazy-flag or dispatch change against the existing emitter. | Low immediate integration cost and incremental review. Forge still bears the cost of upstream research and implementing new semantics itself. A later engine decision remains possible. |

**Choose C. Do not adopt Remill as a production dependency at this milestone.** The ADC experiment demonstrates reusable semantics and effective inlining. The SAR discrepancy already requires an upstream fix or a maintained semantic change before Remill can meet the present gate. Forge would still have to implement the target ABI, address-space model, undefined-input policy and control transfers. A mixed per-opcode fallback would create two decoders, two interpretations of flags, and repeated state conversions on a single path. No evidence here justifies that cost.

Keep PE inspection, unwind-backed range discovery and its diagnostics, the two existing lift interfaces, LLVM IR verification and Mach-O code generation, and the independent Unicorn/Wine coverage gates. Derive Forge recovery fixtures from pcrecomp’s chained-fragment and bounded-switch examples. Use SwARc’s distinction between a known entry, an import thunk and an unresolved jump, and FEX’s practice of observing carry on each side of SBB. The gain is more targeted development and independently testable coverage. Forge gives up the immediate instruction breadth and shared maintenance of an external semantics engine.

### Proposed next work, in order

1. When choosing the next arithmetic regression, compare `flag_sbb` and `carry_chain` with FEX’s observations of incoming and outgoing CF on independently supplied operands. Add a fixture only for an observable gap. FEX’s host register allocation failure is specific to its backend.
2. When a real input needs an indirect jump, exercise one bounded jump-table pattern and a conflicting or out-of-range target in analysis fixtures. Record why each target was inferred. Preserve unresolved outcomes and keep unwind evidence authoritative for its recorded range.
3. Revisit Remill when a concrete FP/SIMD or memory-heavy feature reaches the front of the roadmap. First resolve the SAR carry discrepancy against the existing Wine evidence. Compare a version-matched build on that fixture and the existing 38 obligations, including undefined-read rejection and baseline/O2 behavior. Measure helper calls, object code, compile time and execution time. Adopt an engine only if the added verified coverage outweighs the adapter and maintenance costs under those measurements.

[forge-rev]: https://github.com/mac-n-forge/forge/commit/ea79a6862f6329a452659a4fac94b90ffcfb06c8
[remill-run]: https://github.com/lifting-bits/remill/actions/runs/42891107672
[mcsema-home]: https://github.com/lifting-bits/mcsema
[fex-run]: https://github.com/FEX-Emu/FEX/actions/runs/43133820275
[release-cli]: https://github.com/lifting-bits/remill/blob/0e324aee8c67a63ec759ef379dcfafa0b3cb1448/bin/lift/Lift.cpp
[release-hooks]: https://github.com/lifting-bits/remill/blob/0e324aee8c67a63ec759ef379dcfafa0b3cb1448/tests/X86/Run.cpp#L498-L512
[remill-rev]: https://github.com/lifting-bits/remill/commit/66c488c9911fd9b368e4d0c9647d74239f8bba8b
[remill-build]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/CMakeLists.txt
[remill-license]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/LICENSE
[remill-xed]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Arch.cpp#L370-L387
[remill-lifter]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/BC/InstructionLifter.cpp#L104-L203
[remill-state]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/include/remill/Arch/X86/Runtime/State.h#L751-L776
[remill-adc]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/BINARY.cpp#L648-L718
[remill-shift]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/SHIFT.cpp
[remill-sar]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/SHIFT.cpp#L64-L109
[remill-simd]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/BINARY.cpp#L99-L121
[remill-x87]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/X87.cpp#L64-L83
[remill-atomic]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/SEMAPHORE.cpp
[remill-tests]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/tests/X86/Run.cpp#L884-L945
[remill-target]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Base.cpp#L57-L146
[remill-ret]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/CALL_RET.cpp#L34-L50
[remill-trace]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/BC/TraceLifter.cpp
[remill-hooks]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/docs/INTRINSICS.md
[remill-opt]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/BC/Optimizer.cpp#L60-L83
[remill-mov]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/DATAXFER.cpp
[remill-cmov]: https://github.com/lifting-bits/remill/blob/66c488c9911fd9b368e4d0c9647d74239f8bba8b/lib/Arch/X86/Semantics/CMOV.cpp
[mcsema-rev]: https://github.com/lifting-bits/mcsema/commit/26368053f761be05dab708bc28fb97090c64b2be
[mcsema-build]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/CMakeLists.txt
[mcsema-tests]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/tests/integration_tests/run_tests.py
[mcsema-license]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/LICENSE
[mcsema-cfg]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/mcsema/CFG/CFG.proto
[mcsema-tables]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/tools/mcsema_disass/ida7/table.py
[mcsema-remill]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/.remill_commit_id
[mcsema-opt]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/mcsema/BC/Optimize.cpp
[mcsema-abi]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/mcsema/Arch/X86/Runtime/print_PE_64_windows.cpp
[mcsema-eh]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/tools/mcsema_disass/ida7/exception.py
[mcsema-host]: https://github.com/lifting-bits/mcsema/blob/26368053f761be05dab708bc28fb97090c64b2be/README.md
[pc-rev]: https://github.com/sp00nznet/pcrecomp/commit/93a74327f33d399d2bf4ee606c7a72388c193617
[pc-gen]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/tools/lift/generate64.py
[pc-build]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/templates/CMakeLists.txt.template
[pc-tests]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/tools/lift/difftest64.py
[pc-license]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/LICENSE
[pc-notice]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/NOTICE
[pc-recovery]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/tools/disasm/disasm64.py
[pc-eh]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/runtime/recomp64_cpu/eh64.c
[pc-lift]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/tools/lift/lift64_cpu.py
[pc-state]: https://github.com/sp00nznet/pcrecomp/blob/93a74327f33d399d2bf4ee606c7a72388c193617/runtime/recomp64_cpu/cpu64.h
[sw-rev]: https://github.com/JTM-rootstorm/SwARc/commit/6399a549b5108983970d937dd90aa4e303b07e08
[sw-decoder]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/tools/lifter_x86/CMakeLists.txt
[sw-build]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/CMakeLists.txt
[sw-host]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/README.md
[sw-license]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/LICENSE
[sw-notice]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/NOTICE
[sw-pe]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/platforms/win32/lifter/pe_reader.cpp
[sw-flow]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/tools/lifter_x86/function.h
[sw-dispatch]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/src/x86/dispatch.cpp
[sw-abi]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/src/x86/hle.h
[sw-com]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/platforms/win32/src/win32/com.cpp
[sw-eh]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/platforms/win32/src/win32/seh64.cpp
[sw-emit]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/tools/lifter_x86/emit.h
[sw-state]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/src/x86/ctx.h
[sw-tests]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/tests/x86/lift_x64_test.cpp
[sw-atomic]: https://github.com/JTM-rootstorm/SwARc/blob/6399a549b5108983970d937dd90aa4e303b07e08/src/x86/atomic128.cpp
[fex-rev]: https://github.com/FEX-Emu/FEX/commit/ab135df091d005cc98dfddc56c3dc9c9e4bd501d
[fex-build]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/CMakeLists.txt#L85-L99
[fex-license]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/LICENSE
[fex-state]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/include/FEXCore/Core/CoreState.h#L80-L137
[fex-jit]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/JIT/JIT.cpp
[fex-cache]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/Source/Tools/FEXOfflineCompiler/Main.cpp#L512-L546
[fex-eh]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/Source/Windows/ARM64EC/Module.cpp
[fex-flags]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/OpcodeDispatcher/Flags.cpp#L254-L335
[fex-test]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/unittests/ASM/FEX_bugs/sbbNZCVBug.asm
[fex-x87]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/OpcodeDispatcher/X87.cpp
[fex-avx]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/OpcodeDispatcher/AVX_128.cpp
[fex-locked]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp#L232-L299
[fex-atomic]: https://github.com/FEX-Emu/FEX/blob/ab135df091d005cc98dfddc56c3dc9c9e4bd501d/FEXCore/Source/Interface/Core/JIT/AtomicOps.cpp
[sr-rev]: https://github.com/M-HT/SR/commit/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3
[sr-loader]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW/SRW_loader.c#L641-L647
[sr-game]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/games/Septerra%20Core/SR-Septerra/SConstruct#L254-L281
[sr-build]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW/SConstruct
[sr-license]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/README.md#L15-L18
[sr-script]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW-games/Septerra%20Core/SRW/build-llasm.sh
[sr-hints]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW/SR_source_code_information.c#L584-L599
[sr-ir]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/llasm/llasm.d#L5197-L5240
[sr-x87]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW/SR_full_llasm_instr.c#L6991-L7015
[sr-mmx]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW-games/Septerra%20Core/SRW/llasm/instruction_replacements_FPU.sci#L1-L10
[sr-tests]: https://github.com/M-HT/SR/blob/ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3/SRW/udis86-1.7.2/tests/asm/64/reljmp.asm
