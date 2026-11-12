# Whole-executable differential tests

The planned suite will run a Windows fixture and its Forge-generated native executable with the same inputs, then compare their observable behavior. Today Forge lifts individual functions. The existing CTest entry named `differential` uses Unicorn to execute a function's original x86-64 instructions and compares its return value with the ARM64 harness. Whole-executable translation, Windows process execution, capture, and comparison are future work.

## Ownership

Add these directories under `tests/differential/` as their first cases are implemented.

| Directory | Responsibility |
| --- | --- |
| `fixtures/` | Small C or C++ programs and input files. Keep the existing SDK-free PE inspection and lifting fixtures in `tests/fixtures/`. |
| `manifests/` | Record each case's compiler and flags, invocation, inputs, expected successes or failures, and which observations to compare. |
| `reference/` | Run the compiled PE in the designated Windows environment. Capture stdout, stderr, exit status, and declared filesystem effects alongside the fixture and toolchain identity. |
| `harness/` | Run Forge analysis and lifting on the same PE, build and execute the native output, capture the same observations, and report differences. |

## CMake and CTest integration

Register executable cases in `tests/CMakeLists.txt` under `BUILD_TESTING`. The planned Windows job will compile the fixture, run it with the manifest's inputs, and publish the PE and reference observations together. On the native host, a CTest setup fixture will prepare those artifacts in the build tree. Comparison tests will declare that fixture with `FIXTURES_REQUIRED` so selecting a case also runs its setup. CTest dependencies apply within one host's test run. CI transfers artifacts between hosts.

Each run should start in a fresh working directory with the same input files. Compare stdout and stderr separately, check exit status, and compare declared file creations, changes, and deletions. For structured output, name the fields or values that define equality. Record any normalization in the case. Report an expected failure at its declared stage, and distinguish setup, translation, build, and execution failures from a mismatch between completed runs.
