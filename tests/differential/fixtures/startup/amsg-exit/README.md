# Original MSVCRT fatal-error observations

These captures use the same seven AMD64 console PEs on Windows Server 2022 and pinned Wine 8. The four fatal probes call an ordinary linker thunk for `msvcrt.dll!_amsg_exit` and contain a return of 42 immediately afterwards. An unused import control returns 42. A second pair puts a one-byte stdout write after the fatal call and exercises that write in the control. On both references the control wrote `M` and returned 42. The fatal variant produced no marker and exited 255. [PE source](../../../../fixtures/crt-amsg-exit.s) · [Fixture generator](../../../../fixtures/generate.py)

## Windows Server 2022

The reference ran on Microsoft Windows Server 2022 Datacenter AMD64, build 20348, with English (United States) system MSVCRT version `7.0.20348.5756`, DLL SHA-256 `dde047f12a6b954773284e058631d9939ed1ef1d0f853d4343c320774129ab6e`. The runner image was `win22` version `20261112.366.7`. Forge implements the stderr bytes observed on this backend. [Windows run](https://github.com/RecastIR/forge/actions/runs/44414787210) · [Microsoft CRT contract](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/amsg-exit)

| Argument | Status | Raw stderr with pipe or file redirection |
| --- | ---: | --- |
| 31 | 255 | `b"\r\nruntime error R6031\r\n- Attempt to initialize the CRT more than once.\nThis indicates a bug in your application.\r\n"` (114 bytes) |
| 8 | 255 | `b"\r\nruntime error R6008\r\n- not enough space for arguments\r\n"` (57 bytes) |
| −1 and −2147483648 | 255 | `b"\r\nruntime error "` (16 bytes, final space) |
| Unused import | 42 | Empty |

All four fatal PEs produced empty stdout in redirected runs. Closing both output pipe readers before starting the child and providing invalid output handles also yielded 255. Those two setups have no readable guest output channel. The raw observation files retain the DWORD returned by `GetExitCodeProcess`.

With a real console and separate redirected streams the console cells and cursor stayed unchanged and the diagnostic still went to stderr. With both standard output handles pointing to the console, 31 left the cursor at (0, 4), 8 at (0, 3), and both negative IDs at (14, 1). The observer records twelve rows of UTF-16LE cells before and after each run, together with screen dimensions and exact cursor positions. The independent direct-`CONOUT$` control wrote `CONOUT control!` and moved the cursor to (15, 0) in both attached setups.

The same observer also ran its own child process with an indirect call to the system DLL for every error ID from 0 through 256 and for 32767 and 2147483647. All returned 255 with empty stdout. Each observed stderr is stored under `sweep-<id>-pipe/stderr.bin`. That series includes the extra text for IDs 10, 120–122, 252 and 255, the bare LF inside multi-line messages, and the generic 16-byte output for unrecognized IDs. The archive also contains the original seven-PE observations and OS version records. Its SHA-256 matches the digest published for Actions artifact 14477504752, `d2781aae0442c28d4ea9e2ccb479f19811a28e2090403c35ea7d36b4e6e53379`. [Raw Windows artifact](windows-raw.zip)

## Wine 8

Debian Wine `8.0~repack-4` ran under the repository’s Linux/amd64 reference image on an aarch64 Docker Desktop engine. In detached pipe and file runs, Wine returned 255 with zero bytes on both streams. It also returned 255 with invalid handles or disconnected output pipes. When a controlling terminal was present, it displayed its own shorter `R60` plus the signed numeric argument, including for negative numbers. The terminal received that output with both guest streams redirected to separate pipes. The unused import control returned 42 with an empty terminal. [Wine 8 fatal service](https://github.com/wine-mirror/wine/blob/wine-8.0/dlls/msvcrt/exit.c) · [Wine 8 console writes](https://github.com/wine-mirror/wine/blob/wine-8.0/dlls/msvcrt/console.c)

For 31, both attached configurations produced the same 47 terminal bytes. Linux PTY output translation was disabled. The archive preserves Wine's cursor-control bytes and CRLFs.

```python
b"\r\n\x1b[?25lruntime error R60\x1b[?25h\x1b[?25l31\x1b[?25h\r\n"
```

The direct console control succeeded in both attached setups, including when the guest's own stdout and stderr pipes remained empty. In a detached run it reported the absence of a working console (status 78). The archive's `results.json` records all terminal bytes, exact guest stream bytes when readable, exit status, PE hashes and environment. The archive SHA-256 is `21402d5b79e7ed2d4912a98136583faed89b1fbb02017ad3b0febd255f2acf82`. [Raw Wine captures](wine-raw.zip)

## Standalone ARM64 comparison

On macOS ARM64 the four translated fatal PEs matched the Windows exit code and exact redirected bytes at guest image bases `0x140000000` and `0x170000000`. At both bases the unused import returned 42 with empty streams. The marker control wrote `M` and returned 42. The fatal marker variant exited 255 with the Windows diagnostic and empty stdout. Error 31 also matched Windows with file redirection, invalid handles and a disconnected pipe. The Wine test compares the original PEs with the separate Wine observations above. [Executable tests](../../../../integration/test_executable.py)

The `runtime_contract` test compares the managed process result and both output streams against the raw Windows files for all 259 sweep arguments and the two negative probes. It also exercises a fatal call followed by a fresh process, descriptor lifetime, signal-safety rejection, partial writes and invalid invocations. [CRT process tests](../../../../unit/runtime_console_process.cpp) · [Output and termination contract](../../../../../docs/runtime-architecture.md#fatal-crt-diagnostics)

## Reproduce

Build the PEs from the Forge repository root with the pinned LLVM 23.1.5 tools. The generator uses `llvm-mc` for x86_64-pc-windows-msvc, `llvm-dlltool` for the import library, and `lld-link` with a console entry, `/nodefaultlib` and `/timestamp:0`. For the four direct fatal probes, the import lookup and address tables are at RVAs 0x2028 and 0x2038. Their sole import is `msvcrt.dll!_amsg_exit`. The unused control retains that import at IAT RVA 0x2040. The two marker variants additionally import `KERNEL32.dll!GetStdHandle` and `WriteFile`. Each reference archive contains a `results.json` with the SHA-256 of every original PE and the observer. The executable tests read their expected observations directly from that file. [Observer source](../../../reference/amsg-exit/capture.c) · [Capture script](../../../reference/amsg-exit/observe.py)

```sh
make fixtures
make provision-fixtures
probe_dir=$(mktemp -d)
chmod 755 "$probe_dir"
cp build/dev/fixtures/Debug/crt-amsg-*.exe "$probe_dir/"
cp tests/differential/reference/amsg-exit/{capture.c,observe.py} "$probe_dir/"
toolchain=$(python3 -B tests/differential/fixture_images.py --id toolchain)
docker run --rm --network none --platform linux/amd64 --user "$(id -u):$(id -g)" \
  -v "$probe_dir:/probe" -w /probe \
  "$toolchain" x86_64-w64-mingw32-gcc-win32 -std=c11 -O2 -Wall -Wextra -Werror \
  -static -Wl,--no-insert-timestamp capture.c -o capture.exe
shasum -a 256 "$probe_dir"/*.exe
```

On a Windows AMD64 host, copy that directory and run `python observe.py --sweep` from it. Start in a fresh directory each time. The executable input hashes must match `pe_sha256` in the captured JSON. The file `raw/results.json` describes each invocation. Pipe/file payloads, screen cells and exit observations are stored separately.

For the Wine capture, use the same PE directory and prepared reference image. The startup command warms the Wine prefix before timed observations. The child inherits a controlling PTY only in the two terminal scenarios. Use a fresh container name for each run.

```sh
reference=$(python3 -B tests/differential/fixture_images.py --id reference)
engine_arch=$(docker info --format '{{.Architecture}}')
container=forge-amsg-reference
docker run --name "$container" --network none --platform linux/amd64 \
  -e FORGE_REFERENCE_IMAGE="$reference" -e FORGE_DOCKER_ARCH="$engine_arch" \
  -v "$probe_dir:/probes:ro" --entrypoint /bin/sh "$reference" -c \
  'mkdir /tmp/probes && cd /tmp/probes && cp /probes/*.exe /probes/observe.py . && /usr/lib/wine/wineserver64 -p300 && /usr/lib/wine/wine64 cmd /c ver && python3 observe.py --wine /usr/lib/wine/wine64'
docker cp "$container:/tmp/probes/raw" "$probe_dir/wine-raw"
docker rm "$container"
```

Run `./tools/test-forge.sh --executable-reference` to verify the original PEs under Wine. On Apple Silicon, run `make` followed by `ctest --test-dir build/dev -C Debug -R '^(native_executable|runtime_contract)$' --output-on-failure` for the standalone comparisons and the managed-process sweep.
