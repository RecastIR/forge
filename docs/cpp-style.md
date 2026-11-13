# C++ style in Forge

Forge uses C++20 and the LLVM formatting preset with four-space indentation, a 100-column limit, attached braces, case-sensitive include sorting, and right-aligned pointers and references (`Type *Value`, `Type &Value`). Use braces for every `if`, `else`, `for`, `while`, and `do` body, including early returns. Write consecutive alternatives as `else if` chains. [LLVM coding standards](https://llvm.org/docs/CodingStandards.html)

## Naming

| Kind | Form | Example |
| --- | --- | --- |
| Types, classes, enums, and aliases | PascalCase | `IntegerInstruction` |
| Functions and methods | camelCase | `resultFlags` |
| Local variables, parameters, and data members | PascalCase | `OperandWidth` |
| Constants and enumerators | PascalCase | `MaxOperandWidth` |
| Macros | Uppercase with underscores | `FORGE_TEST_CASE` |

Use `.cpp` for C++ implementations and `.h` for headers. Spell out names unless a term such as `IR`, `RVA`, or `CF` is established in the surrounding domain. Follow the required spelling for LLVM overrides, C linkage, ABI entry points, and other integration contracts. Preserve existing public and widely used names during migration. C fixtures share formatting and brace rules. Their C identifiers retain their own conventions.

## Ownership and borrowed storage

Choose the owner at the boundary where a resource is created, transferred, or retained. Document non-obvious lifetimes there. Never use shared ownership to defer that decision. Use standard and LLVM facilities directly. Avoid custom smart pointers, generic resource frameworks, and blanket LLVM wrappers. [C++ Core Guidelines on resource management](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#r-resource-management)

| Situation | Convention |
| --- | --- |
| An object fits directly in a local, member, or container | Store it by value. |
| One owner needs dynamic storage | Use `std::unique_ptr<T>`. Do not introduce raw owning allocation in ordinary application code. |
| Several parties must keep an object alive independently | Use `std::shared_ptr<T>` and explain who shares ownership and why. |
| A caller grants access | Borrow by reference for required objects or by pointer when appropriate. Make nullability and any retention clear. |
| A file, mapping, or handle needs cleanup | Reuse a suitable RAII owner. Check release on early returns, exceptions, and failed construction. |
| A dependency transfers ownership | Follow the specific API contract. Make the handoff and cleanup explicit, including on failure. |

`llvm::StringRef`, `llvm::ArrayRef`, `llvm::MemoryBufferRef`, `std::string_view`, and `std::span` borrow storage. Copying a view copies the borrow. Keep the backing characters or elements valid through the last use, including the buffer identifier if it is read from a `MemoryBufferRef`. Before retaining a view, check whether a temporary expires, a move changes the backing storage, or a container operation reallocates or erases its elements. Copy into owning storage when the result must survive those events.

In Forge, `InputFile` closes its descriptor. Its `read()` transfers a `unique_ptr<MemoryBuffer>` to the caller. The CLI keeps that buffer alive across analysis and lifting. The parser owns its `COFFObjectFile`, which still borrows the input bytes. A `MappedRange` returned by `mapRva` borrows a section from the supplied section table and bytes from the input buffer. Both must stay valid while used. [Input reader](../src/pe/input.cpp) · [CLI](../src/cli/main.cpp) · [PE parser](../src/pe/pe.cpp)

### LLVM IR and temporary strings

Keep the `LLVMContext` alive through the use and destruction of its IR. Forge's `lift()` declares the context before the module, so the module is destroyed first. A module owns its attached functions, each function owns its attached basic blocks, and each block owns its attached instructions. For example, the translator borrows the `Function *` returned by `Function::Create` with a module argument. Check the individual factory and insertion point to establish ownership. An `IRBuilder` can also return a folded constant. Keep parent-owned nodes as borrows and use LLVM's existing lifetime mechanisms. [Forge lifter](../src/lift/lift.cpp) · [LLVM Programmer’s Manual](https://llvm.org/docs/ProgrammersManual.html)

`Instruction::removeFromParent()` detaches a live instruction. The caller must arrange reinsertion or eventual destruction on every path. LLVM 23 provides `deleteValue()` for destroying a detached generic instruction once its uses have been handled. `eraseFromParent()` removes **and destroys** the instruction and returns the next iterator. Review cached pointers, iterators, and builder insertion points around either operation. After detachment, assumptions about the old block can already be wrong. After erasure, every pointer to the erased instruction dangles, even if a smart pointer keeps the module alive. [LLVM Instruction API](https://llvm.org/doxygen/classllvm_1_1Instruction.html)

Pass `llvm::Twine` compositions directly to a synchronous consumer. Never retain the expression or a reference to it for later evaluation. Its operands can expire at the end of the full expression. To keep the text, materialize an owning `std::string` while those operands are live. In the lifter, `Step::reject` passes the composed message to `fail`, which calls `.str()` while constructing the exception. [Forge diagnostic path](../src/lift/lift.cpp) · [LLVM Programmer’s Manual on Twine](https://llvm.org/docs/ProgrammersManual.html#the-twine-class)

## Reviewing a function

Give each function one clear responsibility. Focused functions often fit in 20–40 lines. Around 40 substantive lines or more than three levels of nesting merits a second look in review. Prefer early returns and extract helpers when the operation has a meaningful name. Read the result from the caller's perspective before accepting a new abstraction.

Clang-tidy flags cognitive complexity above **25** and explains which branches and nesting levels contribute to the score. It also flags functions longer than **80 lines**, including comments and blank lines, or nested more than **3 levels** deep. These thresholds prompt inspection. A readable instruction dispatcher can justify its length, and a short opaque expression can deserve a rewrite even when lint is quiet. Preserve useful blank lines and statement boundaries.

Every new abstraction, ownership relationship, cache, or parallel representation must solve a concrete current problem. Keep one authoritative representation of state. If a derived representation earns its place, identify its source and when it is updated or invalidated. Name a helper for the operation it performs or the invariant it establishes. Keep steps together when splitting them would force the reader to chase trivial helpers. Logical phases can be visible within one function.

Keep related statements together and separate distinct phases with a blank line. Name intermediate values that clarify a decision, width conversion, or chain of calls. Leave simple predicates together. Avoid nested ternaries, assignments hidden in conditions, unrelated operations in one expression, and template machinery that obscures the algorithm. A comment should explain an invariant or a design choice that the code alone cannot convey.

### Preserving behavior during cleanup

Readability changes must preserve validation order, short-circuit behavior, side effects, resource lifetimes, and error propagation. Keep pointer dereferences, operand access, buffer indexing, and extraction from fallible results behind the guards that make them safe. When extracting a helper, narrowing a scope, or introducing an early return, trace when each owner is destroyed and whether any borrow or side effect crosses that point.

For example, the first guard in `Image::directory` treats a missing PE data directory and an all-zero entry as absent.

```cpp
if (!dir || (!dir->RelativeVirtualAddress && !dir->Size)) {
    return std::nullopt;
}
```

Splitting the guard makes the pointer check visible.

```cpp
if (!dir) {
    return std::nullopt;
}
const bool EmptyEntry = !dir->RelativeVirtualAddress && !dir->Size;
if (EmptyEntry) {
    return std::nullopt;
}
```

Computing `EmptyEntry` before the null check would dereference a missing directory. With either form, exactly one zero field reaches the existing incomplete-entry error. Two populated fields proceed to the checked RVA mapping and slice. [PE parser](../src/pe/pe.cpp)

In a lifter, distinguish guest instruction semantics, LLVM IR construction, state and control flow, and diagnostics. Review integer widths, signedness, truncation, extension, and updates to guest registers and flags. For example, a 32-bit register write zeroes the upper half, while a 16-bit write preserves the surrounding bits. Explain non-obvious memory behavior and flag availability at control-flow joins.

For example, this expression constructs the masked shift count for an x86 integer shift:

```cpp
auto *N = IR.CreateAnd(IR.CreateZExt(Count, IR.getInt64Ty()), Width == 64 ? 63 : 31);
```

Naming the x86 rule makes it easier to review the IR operands. Both forms zero-extend the count and emit the same mask operation.

```cpp
// x86 uses six count bits for 64-bit operands and five for the other supported widths.
const unsigned CountMask = Width == 64 ? 63 : 31;
auto *WideCount = IR.CreateZExt(Count, IR.getInt64Ty());
auto *MaskedCount = IR.CreateAnd(WideCount, CountMask);
```

## Running the checks

Select the checksum-verified LLVM **23.1.5** package described in the [build instructions](../README.md#build-and-run). The quality commands verify the actual clang-format or clang-tidy executable. Ordinary builds support stable LLVM 23.x.

```sh
make format         # Format all project-owned C, C++, and headers
make format-check   # Check formatting and fixture braces across the tree
make format-audit   # Run the same read-only whole-tree check
make lint           # Run native safety, maintainability, and changed-line style checks
```

After configuring a build, `cmake --build build --target format` and `cmake --build build --target format-check` use the same commands as Make. In CLion or VS Code, select the release's clang-format binary and repository style for document formatting. For clangd or IDE linting, use the matching tools and `compile_commands.json` from the lint build. IDEs may display diagnostics throughout an open file.

| Enforcement | Coverage |
| --- | --- |
| Formatting fails CI | All owned `.c`, `.cpp`, and `.h` files in Forge source, unit tests, harnesses, fixtures, and reference helpers. Local commands include untracked source files and exclude generated, vendored, third-party, and build directories. |
| Braces fail CI | `readability-braces-around-statements` checks every native C++ translation unit and its included project headers. The formatting check probes all fixtures outside the native database for missing braces. Add missing braces manually. |
| Other blocking lint | The full native analyzer and selected dangling-handle, undefined-memory-manipulation, and use-after-move checks run with the project's compilation database, even when a finding points outside the diff. |
| Tooling failures | Missing or mismatched tools, invalid lint configuration, missing first-party compilation commands, and failed analysis stop the lint stage. |
| Whole-function advisories | `readability-function-cognitive-complexity`, `readability-function-size`, `readability-else-after-return`, and `readability-redundant-control-flow` run on all native translation units and included project headers. `llvm-twine-local` flags a local `llvm::Twine` that can retain references to expired temporaries. Findings appear with locations and available notes and permit a successful lint run. |
| Other advisory diagnostics | Naming and nested ternaries on edited native C++ lines. Existing bug-prone, modernization, misleading indentation, portability, and performance diagnostics retain their configured severity. The compiler also checks conversions with `-Wconversion`. |
| Tests and sanitizers | Unit, integration, and differential cases check the behavior they exercise. ASan and UBSan can diagnose lifetime and other memory or undefined-behavior errors on instrumented, executed paths. |
| Review | Establish owners, borrow validity, and cleanup paths. Trace guard order, side effects, destruction, error propagation, and guest-state updates. Judge whether names, logical phases, helper boundaries, and derived state make the code easier to follow. Check externally required spellings and control flow in macros, preprocessor branches, and code the native compilation database does not instantiate. A clean tool run still requires this review. |

LLVM 23.1.5 supports `InsertBraces`. It lacks semantic information for some rewrites and skips macro definitions and bodies spanning preprocessor directives. Forge keeps it disabled for edits. The fixture probe examines proposed insertions without applying them. [LLVM formatter options](https://clang.llvm.org/docs/ClangFormatStyleOptions.html#insertbraces)

Forge defers `cppcoreguidelines-pro-type-member-init`. A trial flagged five initialization sites, including `MappedRange::fileOffset`, which `mapRva` supplies during aggregate construction, and `View::read`, which copies all `sizeof(T)` bytes into its result before returning it. The other records also receive their values before use. Forge does not use the `gsl::owner` convention that `cppcoreguidelines-owning-memory` checks.

## Comparing advisory lint findings

Review findings relevant to your changes and leave unrelated complexity for separate work. Inspect each suggested control-flow simplification in context. Whole-function advisories include declarations outside the diff. Native lint covers `src`, `tests/support`, and `tests/unit`, excluding generated and third-party headers. Windows fixture sources use their own toolchain.

Naming and nested-ternary diagnostics use the working-tree diff against the merge base of `HEAD` and `origin/main`, including branch commits, staged and unstaged edits, and untracked sources. Set `FORGE_STYLE_BASE` to an available commit to reproduce a specific comparison. CI uses the PR base SHA or the previous SHA of a push. Whole-tree formatting requires no comparison commit.
