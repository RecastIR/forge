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

## Reviewing a function

Give each function one clear responsibility. Around 40 lines of substantive code or more than three levels of nesting merits a second look. Prefer early returns and extract helpers when the operation has a meaningful name. Read the result from the caller's perspective before accepting a new abstraction.

Keep related statements together and separate distinct phases with a blank line. Name intermediate values that clarify a decision, width conversion, or chain of calls. Leave simple predicates together. Avoid nested ternaries, assignments hidden in conditions, unrelated operations in one expression, and template machinery that obscures the algorithm. A comment should explain an invariant or a design choice that the code alone cannot convey.

In a lifter, distinguish guest instruction semantics, LLVM IR construction, state and control flow, and diagnostics. Explain non-obvious width and sign-extension rules, memory behavior, flag lifetimes, and assumptions at control-flow joins. Preserve the guest semantics when simplifying any of these operations.

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
make lint           # Check native C++ braces, run analysis, and report changed-line advisories
```

After configuring a build, `cmake --build build --target format` and `cmake --build build --target format-check` use the same commands as Make. In CLion or VS Code, select the release's clang-format binary and repository style for document formatting. For clangd or IDE linting, use the matching tools and `compile_commands.json` from the lint build. IDEs may display diagnostics throughout an open file.

| Enforcement | Coverage |
| --- | --- |
| Formatting fails CI | All owned `.c`, `.cpp`, and `.h` files in Forge source, unit tests, harnesses, fixtures, and reference helpers. Local commands include untracked source files and exclude generated, vendored, third-party, and build directories. |
| Braces fail CI | `readability-braces-around-statements` checks every native C++ translation unit and its included project headers. The formatting check probes all fixtures outside the native database for missing braces. Add missing braces manually. |
| Other blocking lint | The full native analyzer and selected dangling-handle, undefined-memory-manipulation, and use-after-move checks run with the project's compilation database, even when a finding points outside the diff. |
| Advisory diagnostics | Naming and nested ternaries on edited native C++ lines. Existing bug-prone, modernization, misleading indentation, portability, and performance diagnostics retain their configured severity. The compiler also checks conversions with `-Wconversion`. |
| Human review | Function responsibility, nesting, expression clarity, domain naming, ownership, lifetimes, error paths, semantic fidelity, and externally required spellings. Review control flow in macros, around preprocessor branches, and in code the native compilation database does not instantiate. |

LLVM 23.1.5 supports `InsertBraces`. It lacks semantic information for some rewrites and skips macro definitions and bodies spanning preprocessor directives. Forge keeps it disabled for edits. The fixture probe examines proposed insertions without applying them. [LLVM formatter options](https://clang.llvm.org/docs/ClangFormatStyleOptions.html#insertbraces)

## Comparing advisory lint findings

Naming and nested-ternary diagnostics use the working-tree diff against the merge base of `HEAD` and `origin/main`, including branch commits, staged and unstaged edits, and untracked sources. Set `FORGE_STYLE_BASE` to an available commit to reproduce a specific comparison. CI uses the PR base SHA or the previous SHA of a push. Whole-tree formatting requires no comparison commit.
