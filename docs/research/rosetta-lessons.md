# Rosetta-informed architecture and optimization review

Reviewed 2026-11-17 against `RecastIR/forge`, branch `feat/guest-mem-bridge`, commit
[`c355c9d0619f6f95b2b50b243b2bd26ec8aba111`](https://github.com/RecastIR/forge/tree/c355c9d0619f6f95b2b50b243b2bd26ec8aba111).
This is a source review and implementation backlog, not a measured performance study or an
implementation of the proposals. No Apple binaries were downloaded, disassembled or decompiled;
no implementation code was copied and no dependencies were added.

## Recommendation and evidence rules

Retain Forge's LLVM-based AOT pipeline, explicit guest state, checked address translation and
native C runtime boundary. The most useful lesson is to specify observable guest behavior before
optimizing its representation. Do not adopt Rosetta's execution architecture wholesale.

Forge currently publishes IR for a selected function and its recovered call group. Its native
harness is not a complete Windows executable loader. Windows x64 CLI compatibility remains the
next consumer; arbitrary x86 execution, recoverable Windows exceptions and guest concurrency
are not established by these function-level tests. Preserve the possibility of x86-32 by keeping
decoder mode, guest address width and guest calling convention separate from ARM64 layout.

Evidence labels used below:

- **F — Forge fact:** directly inspected source at the revision above. Existing tests are
  evidence of intended coverage, not a claim that they were executed in this review.
- **D — documented:** a public ISA, ABI or LLVM contract. Living documentation must be checked
  against the deployed toolchain; Forge selects stable LLVM 23.x and quality tools 23.1.5.
- **R — reported observation:** an author's published Rosetta investigation, verified here as
  a statement in that publication, not independently reproduced or guaranteed for current Rosetta.
- **H — hypothesis:** a possible Forge benefit requiring measurements. It is not a defect or
  authorization to implement an optimization.

No supported-input miscompilation was reproduced in this documentation-only review. The
verified architectural risks below are limits of the current contracts and hazards when
extending them, not claims that every existing fixture is incorrect.

## Public research and transferable lessons

| Source and status | Finding | Implication for Forge |
| --- | --- | --- |
| **R**, Nakagawa, [Champollion Part 1][c1], 2021-02-19; calling conventions and address resolution sections | Describes AOT artifacts used with a runtime, fixed guest GPR/SIMD-to-host register mappings, retained original image references, lazy guest address resolution and JIT fallback. The observed calling convention preserves guest System V AMD64 argument locations through that mapping. | Keep guest addresses and native entry points distinct. A translated artifact need not be a self-contained replacement executable. The observed System V mapping is not the Windows x64 ABI or Darwin native ABI. |
| **R**, Nakagawa, [Champollion Part 2][c2], 2021-03-04, corrected 2021-05-16; metadata, diagnostics and shared-cache sections | Describes runtime/daemon communication, AOT metadata, diagnostic output containing CFG/flag information and a translated shared cache. Some metadata fields and flag annotations are explicitly unresolved or inferred by the author. | Keep artifact identity and diagnostic provenance. Do not infer a fully specified flags algorithm from the log labels, or introduce a daemon/cache format without a Forge consumer. |
| **D**, [Apple Platform Security][apple-security] | Apple documents both JIT and AOT translation. | AOT alone does not imply that all possible dynamic targets are known. Forge must continue to reject unresolved execution rather than assume it has Rosetta's fallback. |
| **R**, Johnson, [Why is Rosetta 2 fast?][dj], 2022-11-09, with corrections/updates | Reports canonical guest state and reverse instruction mapping, unused-flag elimination, checked return prediction, prologue combining and SIMD translation. The corrected account says AOT lookup tables do **not** expose every instruction as an indirect entry. It also reports FlagM/FlagM2 use, Apple hardware TSO and special parity/adjust/FP support. | Consider liveness, code size and call costs within Forge's existing IR. Canonical state and precise fault mapping are a deliberate tradeoff, not free properties of AOT. Hardware observations are not portable user-space capabilities. |

These reports concern particular historical implementations. Neither publication establishes
that Rosetta uses LLVM, that Forge should pin registers, or that a given Forge optimization will
help. The article's explanations of some runtime behavior are inferences. None supplies a
current, complete Rosetta specification. The source summaries above deliberately exclude
proprietary instruction sequences and recovered implementation code.

General compiler mechanisms have independent sources: LLVM documents [SSA/IR semantics][lang],
[optimization passes][passes] and [instruction selection and register allocation][codegen]. Arm's
[Memory Systems, Ordering, and Barriers guide][arm-memory] distinguishes ordering instructions
and their scope. These are the basis for Forge requirements, not evidence that Apple implements
the same algorithms.

## Comparison with the current code

### 1. Architectural state and flags

**F:** [operands.cpp][operands] models sixteen GPRs and their overlapping views, including high
bytes. `Translator::storeView` in [lift.cpp][lift] preserves other bits for 8/16-bit writes and
zero-extends 32-bit writes. [ContextLayout][context] holds registers, optional byte origins,
six arithmetic flags and optional stack/runtime fields. It is private invocation storage,
not a complete x86 CPU context: there is no architectural RIP slot, full RFLAGS, XMM/MXCSR,
x87 or segment-base state. Locations exist in recovered steps/CFGs instead.

[IntegerSemantics][integer] computes CF/PF/AF/ZF/SF/OF explicitly, uses `ctpop` for low-byte
parity and `smul.with.overflow` for IMUL. INC/DEC preserve CF. Shifts mask counts, operate in
safe i64 widths and preserve available flags for zero counts. [call_flow.cpp][flow] proves
definitions across joins/calls; flag availability is distinct from bit value. Undefined flag
consumption is rejected. Opaque incoming nonvolatiles use stable `freeze` backing plus origins;
this does not permit arbitrary guest reads of undefined state.

**LLVM:** unused pure flag computations can disappear; scalar replacement/promotion can expose
context fields to SSA when escapes and calls permit it. LLVM cannot infer an omitted x86 flag
rule. A pointer argument shared by bodies is not automatically promoted merely by running
`mem2reg`; inlining, alias visibility and aggregate analysis matter.

**Gap/opportunity:** definition analysis is not backward flag-demand analysis. `storeFlags`
materializes available flags at guest calls/returns; whether O2 removes their cost is **H**.
Keep the current explicit bits. Do not introduce lazy-flag thunks or an NZCV-shaped public ABI.
Any future SIMD/FP capability needs guest rounding, NaN, denormal and exception behavior as well
as Windows nonvolatile XMM rules; it is compatibility work, not just vectorization.

### 2. Instruction lowering and IR

**F:** [cfg.cpp][cfg] decodes with LLVM MC and restricts prefixes; [integer.cpp][integer] and
[operands.cpp][operands] admit specific operand forms. [lift.cpp][lift] emits arithmetic,
selects, PHIs and guards, then verifies a module with the
`arm64-apple-macosx11.0.0` triple/data layout. General DIV/IDIV, SIMD, string operations and
segment accesses are outside the inspected scalar model.

**LLVM:** instruction selection, scheduling, register allocation, native calling convention
lowering and legal machine peepholes belong to the backend. These are not guest semantic
recovery. The verifier checks well-formed IR, not x86 equivalence.

**Risk:** ordinary modular guest arithmetic must not acquire unjustified `nsw`/`nuw`, pointer
`inbounds`, alignment or alias assertions. Future division must check guest divide faults
before emitting LLVM operations with undefined exceptional cases. These are extension rules,
not identified defects in the existing safe shift implementation. See [LangRef][lang].

### 3. Direct and indirect control flow

**F:** [recovery.cpp][recovery], [leaf_recovery.cpp][leaf] and [cfg.cpp][cfg] recover reachable
groups, including bounded inferred leaves and recursive callees. [jump_table.cpp][jump]
recognizes constrained relative tables with validated bounds and entries. Register calls
require a local RIP-relative LEA proof; emission checks the actual guest target. Computed
table targets feed an LLVM switch with a trapping default. Unresolved transfers fail recovery.
Guest calls emit ordinary LLVM calls to shared-context bodies. [memory.cpp][memory] installs
guest continuation VAs, protects return slots and checks the expected RSP/return on completion.

**LLVM:** can lower the switch, inline calls and exploit native call/return instructions. It
does not discover valid binary targets or validate guest return addresses. Machine call/return
prediction is already available through ordinary generated calls; a second return stack is
not justified for these structured calls.

**Gap:** arbitrary function pointers, callbacks, nonlocal transfers, dynamic code and general
indirect dispatch have no execution fallback. Later dispatch work must first define a closed
set of valid AOT entry points and failure behavior; never cast a guest VA to a native pointer.
That is a compatibility boundary, not a reason to add JIT now.

### 4. Guest memory and addresses

**F:** [group_analysis.cpp][group] and [address_fact.cpp][facts] plan selected image spans and
stack routes. [image_memory.cpp][image] applies supported relocations, preserves writable
aliases and binary-searches sorted intervals. The resolver checks the entire scalar access
and permission before deriving a native pointer. [memory.cpp][memory] uses `Align(1)` native
accesses and a checked 4 KiB invocation stack with byte marks. Guest VAs remain integers;
they are not host pointers.

With checked memory, [execution_context.cpp][context] publishes the generated image and active
stack. [runtime/src/core/guest_memory.cpp][bridge] preflights the entire copy, traverses adjacent
intervals and commits bytes/marks only on success. The bridge and generated instructions
borrow the **same backing**; it is not a second memory store. Scalar accesses still require
one interval; bridge copies can span several. [registration.cpp][registration] manages
reservations, claims and lifecycle, not per-instruction translation.

**LLVM:** may fold immutable loads and eliminate checks when it can prove them redundant. It
does not establish PE permissions, relocation validity, mark provenance or guest VA lifetimes.

**Risks:** widening an access or crossing an excluded hole changes fault behavior. Bypassing
resolution must preserve width, permissions, aliases and storage lifetime. Independent lifted
modules do not automatically share writable globals. Runtime registration cannot turn every
registered mapping into a generated-code access route. Keep the current mapping model; measure
residual lookup cost before adding caches or specialized direct paths.

### 5. Runtime ABI and call boundaries

**F:** [runtime.h][rt-header] exposes versioned, native C functions with explicit instance,
thread and invocation identities. Implemented imported services are GetLastError/SetLastError;
[lowerService/lowerCall][lift] use typed native calls, validate status and preserve guest frame
checks. The public typed lifted entry accepts two i64 guest arguments, not arbitrary Windows
function signatures. The seven-slot adapter is also not a full CPU-state ABI.

**LLVM:** arranges the native Darwin call once the correct type is supplied. Forge must choose
the guest arguments, widths, stack layout, results, clobbers and memory effects. Windows x64
uses RCX/RDX/R8/R9 and shadow space; the [Windows ABI][win-abi] differs from the
[Apple ARM64 ABI][apple-abi], including platform-specific native rules. Rosetta's observed
System V mapping cannot substitute for either contract.

**Gap:** pointer-taking service execution, general varargs/aggregates, FP arguments and guest
callbacks need explicit signatures and ownership. The memory bridge is useful preparation,
not evidence those services are already supported. Preserve guest/native separation when the
first required CLI service is added. Do not design a general FFI or adopt ARM64EC for a Darwin
standalone target.

### 6. Exceptions and faults

**F:** `GuestMemory::guard`, the image resolver and indirect-dispatch defaults emit
`llvm.trap`/`unreachable`. Runtime checked copies return a fault address/access/reason through
[runtime.h][rt-header]; they do not dispatch Windows exceptions. Parsed unwind records support
function discovery. They are not translated SEH or C++ exception handling. Generated context
state is not materialized at every guest instruction, and O2 may remove or merge operations.

**LLVM:** can preserve explicit control dependencies and generate native unwind information
when requested appropriately; neither LLVM debug locations nor native unwind tables reconstruct
an x86 exception context automatically.

**Risk:** native trap recovery via signals/longjmp can skip `forge_rt_leave`, leaving borrowed
stack registrations stale. Current documentation correctly disallows this. A future precise
fault contract must identify guest PC, pre/post-instruction state, partial effects and cleanup
before permitting recovery. A PC map alone is insufficient. Retain terminal guards now; do not
force canonical state after every instruction or restrict O2 without a real exception consumer.

### 7. Atomics and ordering

**F:** LOCK prefixes are rejected by [cfg.cpp][cfg]; guest atomic RMW/fence semantics are not
implemented by the scalar instruction model. `GuestMemory::modify` is a load followed by a
store, which is appropriate only for the supported **unlocked** operations. Ordinary generated
accesses are non-atomic. There **are** implementation atomics: checked image initialization uses
acquire/release and compare-exchange in [image_memory.cpp][image], and runtime bookkeeping uses
locks/atomic ownership machinery. These do not implement x86 guest ordering.

The process mutex protects bridge transfers and registrations, while guest bodies execute
outside it. Stack publication prevents overlapping checked stacks in one process, but does not
serialize all stackless entries, plain entries, or generated image accesses with bridge copies.
The existing host synchronization precondition must cover those paths too.

**D:** LLVM's [atomic guide][atomics] distinguishes atomic from volatile and gives racing
non-atomic accesses semantics unsuitable for faithful machine-level shared memory. Arm's
[ordering guide][arm-memory] provides scoped barriers and acquire/release operations; it does
not promise ordinary ARM64 accesses have x86 ordering. A hardware TSO mode would not repair
IR-level transformations or a C++ runtime data race.

**Requirement now:** do not claim concurrent x86 shared-memory compatibility. Host callers must
prevent unsynchronized conflicting generated/bridge accesses. Before adding guest threads or
atomics, specify both compiler and hardware ordering, mixed-width overlap, alignment, atomicity,
and synchronization with native services. Blanket `volatile`, a DMB after every access, or
marking every unaligned load `seq_cst` is not a justified implementation plan.

### 8. Optimization pipeline

**F:** production `generateIR` verifies and returns canonical IR; it does not run an O2 pass
manager. [tests/CMakeLists.txt][test-cmake] and [native.py][native] build independently verified
baseline and `default<O2>` variants using the same code-generation/link settings. Baseline
still uses LLVM backend code generation; it does not mean every machine optimization is off.
Forge's recovery, definition and address analyses already perform domain-specific work.

**LLVM:** constant folding, dead computation/store elimination, scalar replacement, inlining,
CFG simplification and loop transforms are existing capabilities, subject to profitability and
proof. They are not guarantees that all context traffic, flag work or checks disappear.
Target features control instruction availability; an ARM64 triple alone does not establish a
specific FlagM/LSE/FP extension baseline. See [passes][passes] and [code generation][codegen].

**H:** residual cross-call flags, resolver calls, byte-mark traffic or stack initialization may
dominate a workload. Inspect optimized IR and the **Forge-generated** object and measure them
before changing IR. No Rosetta performance ratio is a useful acceptance threshold for Forge.

## Prioritized opportunity matrix

Task IDs refer to the reviewable work packages below. “Now” can mean preserving a contract;
it does not imply implementing a missing execution subsystem.

| Priority | Finding / opportunity | Evidence and affected components | Action / gate |
| --- | --- | --- | --- |
| **Now** | Preserve guest state semantics independently of host registers | F/D: [integer][integer], [operands][operands], [flow][flow], [context][context] | T1: extend only missing semantic regressions; retain per-bit proofs and private layout. |
| **Now** | Shared guest memory is not covered by runtime locks alone | F/D: [memory][memory], [image][image], [bridge][bridge], [registration][registration] | T2: explicit scope restriction now; concurrency design before guest thread support. |
| **Now** | A trap is not a recoverable guest exception | F: [memory][memory], [lift][lift], [context][context], [runtime ABI][rt-header] | T2: retain terminal behavior and cleanup restriction; recovery protocol first if scope changes. |
| **Now** | Guest/native addresses, state ownership and ABI must remain separate | F/D: [operands][operands], [image][image], [context][context], [runtime ABI][rt-header] | T1/T2: preserve alias/lifetime tests and typed boundaries; no guest-pointer casts or frozen full CPU ABI. |
| **Soon** | Measure existing O2 and native code before adding passes | F/H: [test build][test-cmake], [native runner][native], [runtime benchmark][runtime-bench] | T3: reproducible cost/size baseline with correctness gates. |
| **Soon, conditional** | Avoid residual unused flag materialization | H: `storeFlags`, [integer][integer], [flow][flow] | T4 only if T3 finds material surviving cost; no lazy-state redesign. |
| **Soon, conditional** | Reduce proven constant-address resolution overhead | H: [group][group], [facts][facts], [image][image], [memory][memory] | T5 only if T3 shows missed folding and material cost. Preserve checked fallback. |
| **Later** | Broader indirect dispatch and callbacks | F gap: [recovery][recovery], [jump][jump], [lift][lift], [context][context] | T6 only for a concrete CLI fixture requiring an unresolved transfer. |
| **Later** | Guest threads/atomics or recoverable exceptions | F gap: [memory][memory], [bridge][bridge], [context][context], [runtime ABI][rt-header] | Separate execution contracts and tests under T2 gates; no implementation scheduled here. |
| **Later** | SIMD/FP and profile-driven layout/inlining | F gap/H: [operands][operands], [integer][integer], [lift][lift], [test build][test-cmake] | Require a real compatibility blocker or representative profile; preserve FP controls before speed work. |
| **Not applicable** | Apple TSO/PF/AF/private FP modes as a Forge requirement | R, no supported portable runtime contract | No private controls or Rosetta dependency. Standard target features may be evaluated separately. |
| **Not applicable** | Copy Rosetta register assignments, shared cache, daemon or JIT fallback | R, mismatched execution/ABI model | Keep LLVM allocation, native runtime and offline artifacts. No Apple cache parser or new dispatcher architecture. |

## Concrete risks and their limits

| Trigger | Consequence | Status / containment |
| --- | --- | --- |
| A stackless generated entry writes image bytes while another entry or native bridge reads them without host synchronization | Non-atomic compiler/runtime races; stale or otherwise non-x86 observations | Verified architectural exposure, not a supported-concurrency regression. Runtime record locking alone is insufficient; T2 states the host precondition. |
| A host catches a generated guard trap and nonlocally resumes without leaving the checked invocation | Runtime may retain references to expired activation storage | Verified missing recovery protocol. Keep recovery unsupported; terminal subprocess fault tests remain appropriate. |
| A new optimization drops a carried flag because one caller cannot consume it | Another caller can lose a defined CF or other flag across the same helper | Extension risk, not an observed defect. Preserve the existing availability/value distinction and shared-callee tests in T1/T4. |
| An address fast path assumes a selected backing allocation makes every byte accessible | Access may bypass a protected hole, relocation exclusion or width check | Extension risk. Mapping intervals, not allocated size alone, grant access; T5 must prove the complete access. |
| Flags/contexts or lookup checks remain after O2 | Extra instructions and memory traffic may hurt small CLI kernels | Performance hypothesis only. T3 determines whether the cost exists and matters. |
| Aggressive inlining or specialized lookup code reduces calls but expands text | Instruction-cache pressure and translation time may outweigh a local speedup | Performance hypothesis. T3–T5 measure text size and compile cost alongside execution time. |

## Recommended work packages and acceptance criteria

### T1 — Close demonstrated semantic test gaps (Now)

**Why:** flags, partial registers, aliasing and calls are foundational; an optimization must
not turn undefined guest observations into defined behavior or lose preserved state.
**Components:** [integer.cpp][integer], [lift.cpp][lift], [call_flow.cpp][flow],
[memory.cpp][memory], [image_memory.cpp][image]. Start from
[integer unit tests](../../tests/unit/integer.cpp),
[arithmetic fixtures](../../tests/differential/fixtures/arithmetic/integer_cases.S),
[call flag fixture](../../tests/differential/fixtures/functions/call_flags.S), and the existing
[stack](../../tests/integration/test_stack.py), [image](../../tests/integration/test_image.py),
[indirect](../../tests/integration/test_indirect.py) and [bridge](../../tests/unit/runtime_memory.cpp)
suites. Much of this is already covered; first record the uncovered combinations, not a
duplicate suite.

**Acceptance/correctness:** add only missing cases from the differential matrix below, with
independent expected behavior. Check defined flags only; check rejection separately for
undefined consumers. Exercise both PE build configurations and both native IR variants.
Retain existing enabled coverage and stage-specific failure reporting. Do not change production
semantics unless a counterexample establishes a defect.
**Performance measurement:** run T3's arithmetic/call/memory kernels before and after any
resulting fix; record translation time, native time and text size. Tests alone should not change
generated artifacts. Report a necessary correctness cost rather than hiding it.

### T2 — Make extension gates explicit (Now)

**Why:** admitting guest threads or recovering traps without changing the present memory/state
contract can cause silent misexecution or stale borrowed storage. The narrow concurrency
clarification in [runtime architecture](../runtime-architecture.md#guest-memory-concurrency-boundary)
is part of this review; the existing nonlocal-recovery prohibition remains unchanged.
**Components:** [memory][memory], [context][context], [image][image], [bridge][bridge],
[registration][registration], [runtime ABI][rt-header].

**Acceptance/correctness:** document direct-access/bridge synchronization and distinguish
runtime thread records from x86 thread execution. Retain negative LOCK/unmodeled instruction
tests, entry collision tests and failed-copy no-mutation tests. Before broadening scope, require
a design specifying guest atomic/fault observations and state/registration cleanup, plus the
concurrency/fault tests below. Do not add per-access synchronization or fault maps in this task.
**Performance measurement:** documentation has no runtime cost. Any later enforcement proposal
must separately measure ordinary entries, checked entries and shared-memory throughput against
T3; do not charge unrelated registration costs to instruction ordering.

### T3 — Establish optimized cost and code-size baselines (Soon)

**Why:** a raw IR count cannot establish a runtime bottleneck. Existing O2 differential and
image-scaling infrastructure makes this contained work possible without a new dependency.
**Components:** [native.py][native], [tests/CMakeLists.txt][test-cmake],
[image_scaling.py](../../tests/integration/image_scaling.py),
[runtime_calls.cpp][runtime-bench], [runtime_pairs.cpp](../../tests/support/runtime_pairs.cpp).

**Acceptance/correctness:** retain canonical and verified optimized IR, exact tool versions,
target CPU/features, hashes and compiled objects. Run independent result/checksum comparisons
before timing. Report per-kernel residual flag computations, context accesses, resolver calls,
guards, text/data/zero-fill sizes, lifting time, O2 time and native execution distributions.
Inspection is limited to Forge-generated artifacts and owned fixtures.
**Performance measurement:** use the protocol below, baseline versus O2 and before/after on the
same host. Produce a bottleneck report or an explicit “no material residual cost” result;
do not require a speedup to complete a measurement task. No production pass registry is needed.

### T4 — Prune proven unused flags only if O2 leaves a measured cost (Soon, gated)

**Why:** only surviving, costly materialization warrants Forge-specific work.
**Components:** [flow][flow], [integer][integer], `Translator::storeFlags` in [lift][lift].
**Entry gate:** T3 identifies the specific flag, call/CFG pattern and residual machine operations.
Try an existing LLVM pipeline/visibility improvement first. If insufficient, compute backward
per-flag demand over the existing recovered group, separate from definition availability;
unknown consumers remain conservative. No public state layout change.

**Acceptance/correctness:** T1 passes, including a shared callee with different incoming flag
availability, flag-preserving calls, loops, LAHF, ADC/SBB and zero shifts. Compare optimized and
baseline defined results with the same reference. Reject if the proof needs a guessed edge.
**Performance measurement:** compare flag-live and flag-dead kernels, nested calls and overall
CLI-fixture work, including compile time and text size. Ship only a reproducible benefit above
noise without unexplained regressions; otherwise retain existing code and record the result.

### T5 — Specialize a demonstrated constant-address bottleneck (Soon, gated)

**Why:** repeated interval resolution may survive optimization, but the current resolver is
already logarithmic and constant accesses may fold.
**Components:** [group][group], [facts][facts], [image][image], [memory][memory].
**Entry gate:** T3 shows repeated cost at an address already proved exact and a safe immutable
mapping/lifetime. Prefer making existing proof visible to LLVM over introducing an address cache.

**Acceptance/correctness:** retain identical full-width, permission, relocation and origin
checks wherever not proved; verify rebasing, overlapping aliases, protected holes, interval
ends and dynamic-address fallback with both IR variants. Do not promote a stack-routing hint
to a stronger address/alias guarantee.
**Performance measurement:** use constant versus dynamic addresses over 8/64/512 intervals,
stack/image mixes and repeated entries. Report runtime, text size and lifting/O2 cost. Abandon
the change if LLVM already removes the lookup or code growth outweighs the measured benefit.

### T6 — Extend AOT target coverage for one proven CLI blocker (Later, gated)

**Why:** broader function-pointer support matters only when a required binary demonstrates it.
**Components:** [recovery][recovery], [cfg][cfg], [jump][jump], [lift][lift], [context][context].
**Entry gate:** preserve a minimal Windows x64 fixture, its failing diagnostic and the finite
target/signature evidence. If evidence is insufficient, continue reporting unsupported.

**Acceptance/correctness:** define admissible entry boundaries, guest target comparison,
continuations, clobbers and unknown-target failure before emission. Compare valid targets,
repeated targets and nested returns; reject middle-of-instruction and unknown targets. A native
callback additionally needs explicit re-entry and lifetime rules. No JIT fallback is implied.
**Performance measurement:** compare direct calls with the admitted indirect case across target
counts and distributions, measuring steady-state time and code size. Do not add a lookup cache
until repeated resolution is a measured bottleneck.

## Differential tests and benchmarks

Reuse [the existing reference and artifact protocol](../../tests/differential/README.md).
The current `differential` CTest uses Unicorn for function-level comparison; the Windows fixture
pipeline uses pinned Wine references and native ARM64 harnesses. Neither is a complete hardware
ordering oracle. For architectural edge cases, add native Windows x64 observations where
available and consult the [Intel SDM][intel]; mask architecturally undefined results.

| Area | Proposed observations / edge cases | Oracle and performance companion |
| --- | --- | --- |
| Flags/registers | ADD/SUB/ADC/SBB carry and overflow boundaries; INC/DEC preserving CF; AF/PF through LAHF; high-byte writes; 32-bit zero extension; shifts at 0, 1, width−1, width, 31/32/63/64/255; preserved flags across joins/calls | Existing arithmetic oracle plus deterministic generated cases; separate live-flags and overwritten-flags kernels. Never assert undefined shift flags. |
| Control flow | Recursive/shared callees, duplicate switch entries, default path, valid/invalid computed target, guest return-slot reads and rejected writes, guard-created PHI predecessors | Existing function/jump/indirect suites; compare direct call depth, branch and switch throughput after correctness. |
| Memory | Widths 1/2/4/8 bytes at unaligned offsets and interval ends; holes, rebasing, aliases, stack origins, overflow, zero-length bridge requests, adjacent noncontiguous host backing, no partial mutation on bridge failure | Existing image/stack/bridge suites; separate scalar resolution from bridge copy size/interval-count costs. Cross-interval scalar rejection is a current limitation, not an x86 architectural fault. |
| Native boundary | Last-error roundtrips, invalid identities, preserved output on failure, repeated entry persistence, first registration versus re-entry; future fifth argument at guest entry RSP+40 and callback re-entry only when supported | C and hand-authored IR ABI tests plus lifted last-error fixture; direct native ABI and complete lifted-entry benchmarks remain distinct. |
| Faults | Terminal guard on invalid memory/return; no continued guest service side effect after the guard; later recoverable tests need exact guest PC/state, partial effects and cleanup | Subprocess negative tests now. Windows SEH/FP/divide cases remain blocked until implemented; a generic host signal does not count as an equivalent Windows exception. |
| Future concurrency | Message passing, store buffering, load buffering and IRIW; locked RMW contention; mixed-size overlap; alignment/cache-line/page boundaries; native-service sharing | Instruction-level fixtures and a justified memory-model mapping, then native x86/ARM64 stress tests. Store-buffering 0/0 can be allowed on x86; do not require identical outcome frequencies or treat non-observation as proof. Measure throughput/contention only after correctness. |

Benchmark protocol:

1. Use existing supported fixtures first: arithmetic flags/shifts, `functions/flags`, nested
   calls, image access and `imports/last_error`. Keep a representative input loop with changing
   values and checked output to prevent constant folding of the whole benchmark.
2. Record revision, PE compiler/options, LLVM version, IR/object hashes, CPU features, host/OS,
   optimization/link flags and whether checks/runtime registration are enabled. Compare PE Debug
   and Release and both baseline/O2 native variants independently.
3. Separate lifting, optimization, code generation, link, cold process startup, first entry and
   steady-state execution. The CLI currently ends at IR; do not label lifting time as application
   startup. Exclude console formatting and instance creation from steady-state kernels.
4. Follow existing runtime measurements: warm up, alternate A/B order, run at least nine batches,
   retain checksums and report median plus range. Repeat on another session/host before accepting
   small gains. Keep timing observational in CI; correctness and structural size checks can gate.
5. Record object text size and backing/zero-fill separately from raw IR size. For resolver scaling,
   reuse `FORGE_IMAGE_METRICS=1 ctest --test-dir build/dev -R '^guest_image$' -V` on a built
   Apple Silicon checkout. Instrumentation measures lookup work, not production latency.

Existing timings in [runtime architecture](../runtime-architecture.md#native-linkage-and-performance)
are historical measurements of distinct paths. They were not rerun here and must not be combined
into a Rosetta comparison or extrapolated to whole Windows programs.

## Complexity to avoid

- No custom host register allocator, pinned guest register convention or replacement instruction
  IR. Keep the private context flexible and let LLVM allocate the native machine state.
- No lazy flags merely because eager raw IR looks large. Preserve explicit undefinedness and
  first inspect O2. Do not replace semantic validation with matching one expected instruction.
- No blanket barriers, volatile memory or global lock presented as x86 TSO support. Conversely,
  no removal of checks based on anticipated Apple hardware behavior.
- No per-instruction state spills or mandatory native-PC maps without a defined exception or
  debugger consumer. Metadata alone does not make optimized state recoverable.
- No speculative dispatcher cache, JIT, self-modifying-code support, AOT daemon or shared cache.
  Unknown code remains unsupported under the standalone AOT goal.
- No relocation of guest storage to match Rosetta's layout. Forge's checked VA-to-backing mapping
  supports host independence and should survive future x86-32 address-width rules.
- No general CPU/ABI abstraction until a second implemented consumer needs it. Future x86-32
  needs separate decode/address/stack/calling rules; do not conflate an EAX write in long mode
  with a 32-bit execution mode.

## Review validation and limitations

Inspected source, existing test definitions and architecture documents at the pinned commit;
cross-checked public research and official documentation. This change adds the report and one
concurrency-contract clarification. It does not alter generated code or runtime behavior.
No new performance numbers or execution-equivalence results are claimed. LLVM 23 and the
Darwin ARM64 execution environment are not installed in this Linux review workspace; native
differential, C++ build and performance runs must use the repository's configured environment.
Validation performed here: `git diff --check` passed; a Python standard-library check passed
for local links, referenced headings, reference definitions and whitespace in both changed
documents. `make format-check` could not run because CMake is absent. `make lint` stopped
because its preset is not provisioned. No dependency provisioning was attempted for this
documentation-only change.

## Sources

Accessed 2026-11-17. Section names above identify the relevant passages; the historical research
dates delimit the observations. The Apple security page's search-index text confirmed AOT/JIT;
direct page retrieval was rate-limited, so no additional implementation details depend on it.

- [C1: Project Champollion, Part 1][c1] — Koh M. Nakagawa, FFRI Security, 2021.
- [C2: Project Champollion, Part 2][c2] — Koh M. Nakagawa, FFRI Security, 2021, corrected edition.
- [R3: Why is Rosetta 2 fast?][dj] — Dougall Johnson, 2022, including corrections/updates.
- [D1: Rosetta 2 on a Mac with Apple silicon][apple-security] — Apple Platform Security.
- [D2: LLVM Language Reference][lang] — integer/shift/poison semantics, memory, atomics, attributes.
- [D3: LLVM Atomic Instructions and Concurrency Guide][atomics] — compiler memory semantics.
- [D4: LLVM Analysis and Transform Passes][passes] — promotion, SROA, dead code, inlining, verifier.
- [D5: LLVM Target-Independent Code Generator][codegen] — instruction selection and allocation.
- [D6: Arm Memory Systems, Ordering, and Barriers][arm-memory] — document 102336, version 1.0, 2022;
  sections on DMB, observers and acquire/release. Later target extensions require separate checks.
- [D7: Windows x64 calling convention][win-abi] and [Apple ARM64 ABI][apple-abi].
- [D8: Intel 64 and IA-32 Software Developer's Manuals][intel] — instruction-defined flags,
  faults and memory-ordering rules; normative reference for future test cases.

[c1]: https://ffri.github.io/ProjectChampollion/part1/
[c2]: https://ffri.github.io/ProjectChampollion/part2/
[dj]: https://dougallj.wordpress.com/2022/11/09/why-is-rosetta-2-fast/
[apple-security]: https://support.apple.com/guide/security/rosetta-2-on-a-mac-with-apple-silicon-secebb113be1/web
[lang]: https://llvm.org/docs/LangRef.html
[atomics]: https://llvm.org/docs/Atomics.html
[passes]: https://llvm.org/docs/Passes.html
[codegen]: https://llvm.org/docs/CodeGenerator.html
[arm-memory]: https://documentation-service.arm.com/static/62a304f231ea212bb662321d
[win-abi]: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
[apple-abi]: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
[intel]: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[operands]: ../../compiler/src/lift/operands.cpp
[lift]: ../../compiler/src/lift/lift.cpp
[context]: ../../compiler/src/lift/execution_context.cpp
[integer]: ../../compiler/src/lift/integer.cpp
[flow]: ../../compiler/src/lift/call_flow.cpp
[cfg]: ../../compiler/src/lift/cfg.cpp
[recovery]: ../../compiler/src/lift/recovery.cpp
[leaf]: ../../compiler/src/lift/leaf_recovery.cpp
[jump]: ../../compiler/src/lift/jump_table.cpp
[memory]: ../../compiler/src/lift/memory.cpp
[group]: ../../compiler/src/lift/group_analysis.cpp
[facts]: ../../compiler/src/lift/address_fact.cpp
[image]: ../../compiler/src/lift/image_memory.cpp
[bridge]: ../../runtime/src/core/guest_memory.cpp
[registration]: ../../runtime/src/core/registration.cpp
[rt-header]: ../../runtime/include/forge/runtime.h
[test-cmake]: ../../tests/CMakeLists.txt
[native]: ../../tests/differential/native.py
[runtime-bench]: ../../tests/benchmarks/runtime_calls.cpp
