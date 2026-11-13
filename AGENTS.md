# Forge — Agent Engineering Instructions

This file governs all AI-assisted changes in the Forge repository. Follow the repository's actual build configuration, conventions, and documentation when they are more specific than examples here. Do not invent commands, paths, supported features, or test results.

## Mission and priorities

Forge is a toolchain for analyzing and translating Windows binaries into native macOS-compatible programs. Work incrementally toward a reliable, inspectable, reproducible pipeline. Correctness, semantic fidelity, debuggability, and maintainability take precedence over feature count or cleverness.

Priority order: **correctness and safety → architectural consistency → testability and diagnostics → simplicity → performance**. Optimize only when measurements justify it, without weakening correctness.

## Before changing code

1. Read relevant code, tests, documentation, build files, and recent adjacent implementations. Identify the existing ownership boundaries and patterns. Before introducing a component or making a cross-stage change, read the [component design guide](docs/design-guide.md).
2. State the intended behavior, invariants, and scope. For nontrivial changes, sketch the data flow and interfaces before implementation.
3. Search for reusable components and existing representations. Do not introduce a second source of truth.
4. Identify the smallest independently verifiable change. Keep unrelated cleanup separate.
5. If the task conflicts with existing design or requires a significant architectural decision, surface the tradeoff rather than silently choosing a new architecture.

## Design and architecture

- Respect boundaries between binary/container parsing, analysis, intermediate representations, lifting, code generation, linking/packaging, runtime support, and validation. Use the actual repository module structure as the authority.
- Keep guest instruction semantics and calling conventions distinct from the generated-code target and data layout. Introduce architecture abstractions only for a current consumer.
- Each stage must have clear inputs, outputs, invariants, error behavior, and ownership. Avoid hidden cross-stage state and implicit coupling.
- Prefer explicit typed models and stable interfaces to stringly typed conventions, ad hoc maps, magic values, and global mutable state.
- Preserve provenance where needed for diagnostics: input file, address/range, symbol, transformation stage, and relevant source metadata.
- Separate facts observed in an input binary from inferred facts and user-supplied overrides. Make conflicts visible; do not silently overwrite evidence.
- Treat malformed, ambiguous, unsupported, and contradictory inputs as distinct cases with actionable diagnostics. Never report partial or guessed results as verified success.
- Do not assume all Windows binaries are alike: account explicitly for architecture, calling convention, object format, dynamic loading, imports, relocations, exception handling, TLS, and platform APIs when relevant to the task.
- Keep policy separate from mechanism. Do not hardcode game-specific, distribution-specific, or toolchain-specific assumptions into generic stages.
- Favor composition and straightforward data flow. Introduce interfaces or abstraction layers only when they remove demonstrated duplication, isolate a real boundary, or support a current requirement.
- Avoid premature generalization, speculative compatibility layers, unnecessary factories, parallel implementations, and broad rewrites.
- Make deterministic output the default where feasible: stable ordering, reproducible fixtures, and explicit configuration.

## Implementation quality

- Follow existing repository conventions for C++ language level, naming, file layout, ownership, error handling, and dependency management.
- Prefer RAII, value semantics, explicit lifetimes, const correctness, and standard-library facilities. Avoid raw owning pointers, undefined behavior, unchecked narrowing, and unsafe casts.
- Validate untrusted binary inputs before using lengths, offsets, pointers, ranges, or indices. Use overflow-safe arithmetic and bounds checks.
- Return structured errors with enough context to diagnose failures. Do not swallow errors, invent success defaults, or hide unsupported cases behind empty results.
- Keep functions focused and names descriptive. Comments should explain non-obvious invariants, constraints, and reasons—not narrate code.
- Avoid duplicate parsing, configuration, state, or logic. Extend existing components when appropriate.
- Do not introduce dependencies or modify toolchain/build configuration without explaining the necessity and impact.
- Use the repository's configured formatter, linter, static analyzer, compiler warnings, and sanitizers. Do not guess their command names; inspect the build/CI definitions.
- Never silence a meaningful error, suppress a warning, or weaken a check merely to satisfy tooling. Justify any narrow, documented exception.
- Apply the [C++ style guide](docs/cpp-style.md) to new and substantially modified C++. Run `make format-check`, `make lint`, and the relevant tests, then review the changed functions even when all checks pass.

## Testing and validation

Every behavior change requires tests at the lowest useful level and, where cross-stage behavior is involved, at the relevant integration level.

### Test layers

1. **Unit tests:** parsing, models, ranges, transformations, ABI rules, error handling, and deterministic output.
2. **Stage/contract tests:** verify invariants and data exchanged between adjacent pipeline stages.
3. **Integration tests:** exercise the actual analysis → lifting → generation → build/runtime path as far as supported.
4. **Differential tests:** compile small, focused reference programs for Windows, execute them in a controlled reference environment, translate them with Forge, execute the translated result, and compare defined observable behavior.
5. **Regression tests:** every fixed defect should gain a minimal fixture that fails before the fix and passes after it.

### Differential test requirements

- Keep reference source, compiler/toolchain identity, build flags, input fixtures, expected observations, and comparison rules versioned and reproducible.
- Compare exit status, stdout/stderr where applicable, structured results, and relevant file or process effects. Normalize only known nondeterministic differences; document each normalization.
- Distinguish compilation failure, reference execution failure, translation failure, native build failure, runtime failure, timeout, and semantic mismatch.
- Do not weaken assertions or update expected outputs solely to make a test pass. Investigate mismatches and establish which behavior is authoritative.
- Cover edge cases, negative paths, malformed inputs, ABI boundaries, calling conventions, memory/layout behavior, exceptions, imports, and dynamic loading as those features are implemented.
- Tests must not depend on undocumented host state, network availability, or an unpinned toolchain. If Windows execution is unavailable locally, report the limitation and rely on the designated CI/reference environment; never claim an unrun comparison passed.

### Validation discipline

- Run the smallest relevant tests during development, then the appropriate broader suite before completion.
- Run formatting, linting/static analysis, and build checks required by the repository. Use sanitizers when appropriate and supported.
- Report exact commands executed and their results. Clearly distinguish **passed**, **failed**, and **not run** with reasons.
- Never claim a stage, platform, binary, or feature is supported merely because it compiles or a smoke test passes.

### Coverage obligations

- Add differential coverage for new lifting capabilities whenever practical. Incorrect lifting fixes require regression coverage.
- Verify generated output against an independent observation. Preserve fixture expectations and run the relevant quality and correctness checks before completing changes.
- Keep enabled cases and the reviewed coverage baseline in sync. Explain reductions in the PR and obtain code-owner review. Never disable a case or weaken an expectation to obtain a passing result.
- Review test infrastructure for false passes from stale inputs, skipped execution, or incomplete configuration coverage. Use the [regression guide](tests/differential/README.md#regression-ci-and-local-reproduction) to exercise these paths.

## Documentation

Documentation is part of the change, not follow-up work.

- Update the relevant architecture, CLI/API, pipeline, runtime, developer, and test documentation whenever behavior or contracts change.
- Document public inputs/outputs, invariants, supported and unsupported cases, diagnostics, and reproducibility requirements.
- Keep examples executable and consistent with current CLI flags and actual implementation.
- Record significant design decisions and rejected alternatives in the repository's established decision-record format, if one exists. Do not create a parallel documentation system.
- Prefer one canonical explanation and link to it instead of duplicating specifications across README files, code comments, and tests.
- Do not describe planned behavior as implemented. Label experimental and incomplete capabilities explicitly.

## Task execution workflow

1. **Inspect:** establish current behavior, conventions, and available tests.
2. **Design:** define scope, invariants, integration points, and failure modes; seek clarification for material ambiguities.
3. **Implement:** make a minimal coherent change, using existing infrastructure.
4. **Verify:** add/run focused tests, then broader checks; inspect failures rather than bypassing them.
5. **Document:** update affected documentation and examples in the same change.
6. **Self-review:** critically assess the final diff, not just the intended design.
7. **Report:** summarize what changed, why, validation results, limitations, and follow-ups.

## Mandatory self-review

Before declaring work complete, inspect the diff as though reviewing someone else's pull request. Ask:

- **Correctness:** Are all success, failure, edge, and unsupported paths handled? Are assumptions and invariants enforced? Any undefined behavior, overflow, lifetime, or bounds risks?
- **Semantic fidelity:** Could the transformation silently change program behavior? Are source facts, inferences, and overrides distinguishable?
- **Architecture:** Check conformance with the [component design guide](docs/design-guide.md) and repository conventions. Explain meaningful architectural deviations in the change summary. Update the guide in the same change when intentionally revising a boundary or contract.
- **Readability:** Can a reader follow the logical phases without unpacking dense expressions or jumping through trivial helpers?
- Review vertical spacing explicitly. Separate independent control-flow statements and logical phases according to the C++ style guide. A successful formatter run does not establish that function bodies have readable paragraph structure. [Indentation and vertical spacing](docs/cpp-style.md#indentation-and-vertical-spacing)
- Never remove useful blank lines, compress statements, or introduce trivial helpers merely to reduce function-length metrics. Function length is a review signal, not a reason to make code denser.
- For changes affecting host memory or resources, follow the [ownership guide](docs/cpp-style.md#ownership-and-borrowed-storage). Trace each acquisition, transfer and release for lost or duplicated ownership. Check retained borrows across moves, mutations, callbacks and IR transformations. Inspect destruction order and cleanup on every relevant exit, including failed construction. Verify bounds, arithmetic, initialization and guards before access. Identify the tests that exercise each relationship and any paths still unverified.
- **Behavior preservation:** Did cleanup change a guard, evaluation order, side effect, destruction point, or error path? In lifting code, did it change a width, conversion, register, or flag update?
- **Complexity and reuse:** What current problem does each new abstraction or stored value solve? Could an existing representation or mechanism serve it? How is derived state kept valid?
- **Diagnostics:** Did you inspect maintainability warnings relevant to changed code and justify each remaining exception?
- **Tests:** Do tests assert behavior rather than implementation details? Would they catch a realistic regression? Are negative and conflicting inputs covered?
- **Docs:** Do user-facing and developer-facing descriptions match the actual implementation?
- **Scope:** Did unrelated changes, generated files, temporary artifacts, or accidental dependency changes slip in?

Fix issues found during self-review and rerun affected checks. Report meaningful remaining risks or exceptions briefly. A trivial change needs no checklist recital. Credit independent review only when someone else performed it.

For changes affecting these lifetimes or access guarantees, include a brief **Memory and Resource Safety** section in the completion report. For each area reviewed, identify the owner and borrowers, the finding and fix or reason the existing behavior is sound, and the test evidence and limitations. For sanitizer runs, identify the components both instrumented and exercised.

## Change boundaries and communication

- Never silently broaden scope. Separate prerequisite refactors from feature behavior when possible.
- Do not delete tests, relax validation, change reference expectations, or disable quality gates to achieve a green build without explicit justification.
- Do not modify unrelated code or reformat entire modules unless required and agreed.
- Prefer small, reviewable changes with independently verifiable outcomes. If the repository requires one PR, keep commits or logical steps separable within it.
- When blocked, explain the exact missing dependency or unresolved decision and propose the smallest next action.
- In the final report, include: **summary; design decisions; tests/checks run (with results); documentation updated; known limitations and follow-ups**.

## Repository-specific instructions

- Follow the [repository layout](README.md#repository-layout) when adding production code, test support, and suites. Keep one root CMake project and register tests in `tests/CMakeLists.txt`.
- Follow [Adding a CLI command](docs/design-guide.md#adding-a-cli-command) for typed options, final callbacks, shared renderers, and command tests. Keep CLI11 private to the `forge` executable.
- From the root, use `make` to build and `make test CONFIG=Debug` to build and run CTest. Use `make format-check`, `make lint`, and `make sanitize` for the other CI checks. Keep moved C++ sources and headers covered by the quality tools.
- Preserve the function-level Unicorn test under its existing CTest name, `differential`. Follow the [whole-executable test design](tests/differential/README.md) when adding Windows reference cases.

More specific `AGENTS.md` files in subdirectories may refine these rules for a component but must not silently weaken correctness, testing, documentation, or self-review requirements. The repository's actual build scripts and CI configuration are authoritative for command names and supported environments.
