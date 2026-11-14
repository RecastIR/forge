"""Resolve Make's output directory and invoke the project presets or explicit Conan provisioning."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


SOURCE = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("BUILD_ROOT") or SOURCE / "build").resolve()
PROFILES = SOURCE / "conan/profiles"
TOOLCHAIN = Path("conan/conan_toolchain.cmake")
ENV = os.environ


def run(*args):
    subprocess.run(args, cwd=SOURCE, check=True)


def output(*args):
    return subprocess.check_output(args, cwd=SOURCE, text=True).strip()


def enabled(value):
    if value.upper() in ("TRUE", "ON", "1", "YES"):
        return True
    if value.upper() in ("FALSE", "OFF", "0", "NO"):
        return False
    raise ValueError(f"Expected a Boolean setting, got {value!r}.")


def preset_settings(name, presets):
    if name not in presets or presets[name].get("hidden"):
        choices = ", ".join(n for n, p in presets.items() if not p.get("hidden"))
        raise ValueError(f"Unknown PRESET={name}. Choose {choices}.")
    chain = []
    while name:
        preset = presets[name]
        chain.append(preset)
        name = preset.get("inherits")
    values = {}
    for item in reversed(chain):
        values.update(item.get("cacheVariables", {}))
    generator = next(item["generator"] for item in chain if "generator" in item)
    return generator, values


def same_directory(left, right):
    return left == right or (left.is_dir() and right.is_dir() and left.samefile(right))


def read_identity(directory):
    cache = directory / "CMakeCache.txt"
    configured = {}
    toolchain = directory / TOOLCHAIN
    folder = toolchain.parent
    if cache.is_symlink() or folder.is_symlink() or toolchain.is_symlink():
        raise ValueError(f"Expected a configuration-owned cache and toolchain in {directory}. Use a fresh BUILD_DIR.")
    if folder.exists() and not folder.is_dir():
        raise ValueError(f"Expected a configuration-owned Conan directory at {folder}. Use a fresh BUILD_DIR.")
    if cache.exists():
        configured = dict(re.findall(r"^(\w+):\w+=(.*)$", cache.read_text(), re.M))
        for key, location in (("CMAKE_HOME_DIRECTORY", SOURCE), ("CMAKE_CACHEFILE_DIR", directory)):
            recorded = Path(configured.get(key, ""))
            if not recorded.is_absolute() or not same_directory(recorded, location):
                raise ValueError(f"{cache} records {key}={recorded}, expected {location}. "
                                 "Use the original build directory or a fresh BUILD_DIR.")
        if not (configured.get("FORGE_CONFIGURED_PRESET") or configured.get("FORGE_CONAN_PRESET") or
                (configured.get("FORGE_PRESET") and not configured.get("CMAKE_PROJECT_NAME"))):
            raise ValueError(f"{cache} lacks a recorded workflow. Select a fresh BUILD_DIR.")
        cached_toolchain = directory / configured.get("CMAKE_TOOLCHAIN_FILE", "")
        if cached_toolchain.resolve() != toolchain.resolve():
            raise ValueError(f"{cache} selects an unrelated toolchain {cached_toolchain}. Use a fresh BUILD_DIR.")

    if toolchain.exists():
        identity = {key: value.strip('"') for key, value in
                    re.findall(r'^set\(FORGE_CONAN_(\w+) ("[^"\n]*"|[^\s)]+) CACHE ', toolchain.read_text(), re.M)}
        if not all(identity.get(key) for key in ("PRESET", "PROFILE_ID", "WITH_CLI", "GENERATOR", "BUILD_TYPE")):
            raise ValueError(f"Incomplete Conan workflow information in {toolchain}. Provision a fresh BUILD_DIR.")
    elif all(configured.get(key) for key in ("FORGE_CONFIGURED_PRESET", "FORGE_CONFIGURED_PROFILE_ID",
                                             "FORGE_CONAN_WITH_CLI")):
        # A successfully configured cache can identify its missing toolchain for reprovisioning.
        identity = dict(PRESET=configured["FORGE_CONFIGURED_PRESET"], PROFILE_ID=configured["FORGE_CONFIGURED_PROFILE_ID"],
                        WITH_CLI=configured["FORGE_CONAN_WITH_CLI"])
    else:
        if folder.exists() and any(folder.iterdir()):
            raise ValueError(f"Cannot establish ownership of existing files in {folder}. Use a fresh BUILD_DIR.")
        identity = {}
        if configured:
            # A preset stopped before project() records the requested name only.
            if configured.get("CMAKE_PROJECT_NAME") or not configured.get("FORGE_PRESET"):
                raise ValueError(f"Incomplete workflow information in {cache}. Select a fresh BUILD_DIR.")
            identity["PRESET"] = configured["FORGE_PRESET"]
    return identity, configured


def validate_identity(directory, identity, cache, name, generator, configs):
    if not identity:
        return
    if identity["PRESET"] != name:
        raise ValueError(f"{directory} belongs to PRESET={identity['PRESET']}, requested {name}. "
                         "Select a matching preset or a different BUILD_DIR.")
    if identity.get("GENERATOR", generator) != generator or identity.get("BUILD_TYPE", configs[0]) not in configs:
        raise ValueError(f"The Conan toolchain in {directory} disagrees with PRESET={name}. Select a fresh BUILD_DIR.")
    if not cache:
        return

    completed = bool(cache.get("FORGE_CONFIGURED_PRESET"))
    expected = {"CMAKE_GENERATOR": generator}
    if len(configs) == 1:
        expected["CMAKE_BUILD_TYPE"] = configs[0]
    elif set(cache.get("CMAKE_CONFIGURATION_TYPES", "").split(";")) != set(configs):
        raise ValueError(f"CMAKE_CONFIGURATION_TYPES in {directory} disagrees with PRESET={name}. Use a fresh BUILD_DIR.")

    for key in ("FORGE_PRESET", "FORGE_CONFIGURED_PRESET", "FORGE_CONAN_PRESET"):
        if key in cache:
            expected[key] = name
    for key in ("FORGE_CONFIGURED_PROFILE_ID", "FORGE_CONAN_PROFILE_ID"):
        if completed or key in cache:
            expected[key] = identity.get("PROFILE_ID")
    for key, value in expected.items():
        if cache.get(key) != value:
            raise ValueError(f"{key}={cache.get(key)!r} in {directory} conflicts with {value!r}. Use a fresh BUILD_DIR.")

    cli = enabled(identity.get("WITH_CLI") or ENV.get("WITH_CLI") or "ON")
    for key, value in (("FORGE_BUILD_CLI", cli), ("FORGE_CONAN_WITH_CLI", cli),
                       ("FORGE_ENABLE_SANITIZERS", name == "sanitize")):
        if key not in cache and not completed:
            continue
        # Completed caches must have explicit values for all three settings.
        if key not in cache or enabled(cache[key]) != value:
            raise ValueError(f"{key} in {directory} conflicts with its provisioned workflow. Use a fresh BUILD_DIR.")


def requested(action, recorded, presets):
    dedicated = action if action in ("sanitize", "lint") else None
    explicit = ENV.get("PRESET")
    config = ENV.get("CONFIG")
    if dedicated and explicit and explicit != dedicated:
        raise ValueError(f"make {action} requires PRESET={dedicated}, got PRESET={explicit}.")
    name = dedicated or explicit
    if not name and (not config or recorded == "xcode"):
        name = recorded
    if not name:
        if ENV.get("CMAKE_GENERATOR") == "Xcode":
            name = "xcode"
        elif ENV.get("SANITIZE") and enabled(ENV["SANITIZE"]):
            name = "sanitize"
        else:
            name = {"Debug": "dev", "Release": "release"}.get(config or "Debug")
    if not name:
        raise ValueError(f"Use PRESET=xcode for CONFIG={config}, or select Debug or Release.")
    generator, values = preset_settings(name, presets)
    configs = values.get("CMAKE_CONFIGURATION_TYPES", values.get("CMAKE_BUILD_TYPE")).split(";")
    if config and config not in configs:
        raise ValueError(f"PRESET={name} supports CONFIG={' or '.join(configs)}, got {config}. Select a matching preset or BUILD_DIR.")
    if ENV.get("SANITIZE") and enabled(ENV["SANITIZE"]) != bool(values.get("FORGE_ENABLE_SANITIZERS")):
        raise ValueError(f"SANITIZE conflicts with PRESET={name}. Use PRESET=sanitize for instrumentation.")
    return name, generator, configs


def provision(action, name, generator, configs, directory, identity):
    pin = next(s.split("==")[1] for s in (SOURCE / "requirements-build.txt").read_text().splitlines()
               if s.startswith("conan=="))
    if not shutil.which("conan") or output("conan", "--version") != f"Conan version {pin}":
        raise ValueError("Activate the build environment and run python -m pip install -r requirements-build.txt.")
    apple = PROFILES / "macos-arm64-appleclang"
    host = PROFILES / "macos-arm64-llvm" if name == "lint" else apple
    common = ["-pr:b", ENV.get("CONAN_BUILD_PROFILE") or apple, "-pr:h", ENV.get("CONAN_HOST_PROFILE") or host,
              "-c:h", f"tools.cmake.cmaketoolchain:generator={generator}", "-c:h", f"user.forge:preset={name}"]
    cli = enabled(ENV.get("WITH_CLI") or identity.get("WITH_CLI", "ON"))
    if name == "lint" and not cli:
        raise ValueError("Lint checks every CLI translation unit. Provision PRESET=lint WITH_CLI=ON.")
    if name == "lint":
        llvm_bin = Path(output("cmake", "--log-level=ERROR", "-P", SOURCE / "cmake/llvm.cmake"))
        compilers = {"c": str(llvm_bin / "clang"), "cpp": str(llvm_bin / "clang++")}
        common.extend(["-c:h", "tools.build:compiler_executables=" + json.dumps(compilers)])
    common.extend(["-o:h", f"&:with_cli={cli}"])
    if action == "update-lock":
        if not cli:
            raise ValueError("Generate the shared lock with WITH_CLI=ON to include the complete graph.")
        run("conan", "lock", "create", ".", *common, "-s:h", f"build_type={configs[0]}",
            "--lockfile=", "--update", "--lockfile-out=conan.lock")
        return

    profile = output("conan", "profile", "show", *common, "-s:h", f"build_type={configs[0]}", "-f", "json")
    digest = hashlib.sha256(profile.encode()).hexdigest()
    if identity.get("PROFILE_ID") and identity["PROFILE_ID"] != digest:
        raise ValueError(f"The requested Conan profiles or CLI selection differ from {directory}. "
                         "Use the original profiles and WITH_CLI, or choose a fresh BUILD_DIR.")
    common.extend(["-c:h", f"user.forge:profile_id={digest}"])
    flags = ["--build=never", "--lockfile", SOURCE / "conan.lock", "-of", directory]
    if enabled(ENV.get("CACHE_ONLY") or "OFF"):
        flags.append("--no-remote")

    # Generate at the final path because Conan embeds paths in its scripts. On a
    # failed install restore the previous complete set, including all Xcode types.
    folder = directory / "conan"
    with tempfile.TemporaryDirectory(prefix=".conan-", dir=directory) as tmp:
        previous = Path(tmp) / "previous"
        if folder.exists():
            shutil.copytree(folder, previous, symlinks=True)
        try:
            for config in configs:
                run("conan", "install", ".", *common, "-s:h", f"build_type={config}", *flags)
        except BaseException:
            if folder.exists():
                folder.rename(Path(tmp) / "incomplete")
            if previous.exists():
                previous.rename(folder)
            raise


def workflow(action, name, configs, directory, identity):
    config = ENV.get("CONFIG") or configs[0]
    cache = directory / "CMakeCache.txt"
    if name == "lint" and action in ("test", "fixtures"):
        raise ValueError("PRESET=lint checks the compilation database. Run make lint or select a test preset.")
    if action == "clean":
        if cache.exists():
            run("cmake", "--build", directory, "--config", config, "--target", "clean")
        return
    if not (directory / TOOLCHAIN).is_file():
        raise ValueError(f"Dependencies are missing. Run make provision PRESET={name} "
                         f"BUILD_DIR={shlex.quote(str(directory))}.")
    if ENV.get("WITH_CLI") and enabled(ENV["WITH_CLI"]) != enabled(identity["WITH_CLI"]):
        raise ValueError("WITH_CLI conflicts with the provisioned configuration. Provision a fresh BUILD_DIR.")
    args = shlex.split(ENV.get("CMAKE_ARGS", ""))
    if any(arg.startswith(("-B", "-S", "-G", "--preset", "--toolchain", "--fresh", "-U")) for arg in args):
        raise ValueError("CMAKE_ARGS cannot replace the source, binary directory, preset, or cache. "
                         "Use PRESET, BUILD_DIR, or BUILD_ROOT to select a configuration.")
    owned = ("CMAKE_TOOLCHAIN_FILE", "CMAKE_GENERATOR", "CMAKE_BUILD_TYPE", "CMAKE_CONFIGURATION_TYPES",
             "CMAKE_HOME_DIRECTORY", "CMAKE_CACHEFILE_DIR", "FORGE_BUILD_CLI", "FORGE_ENABLE_SANITIZERS",
             "FORGE_PRESET", "FORGE_BUILD_ROOT", "FORGE_CONFIGURED_", "FORGE_CONAN_")
    if any(arg.removeprefix("-D").startswith(owned) for arg in args):
        raise ValueError("Use PRESET or CONFIG to choose the workflow, PRESET=sanitize for sanitizers, "
                         "and WITH_CLI during make provision to select the CLI.")
    for key in ("LLVM_DIR", "LLVM_CONFIG", "BUILD_TESTING"):
        if ENV.get(key):
            args.append(f"-D{key}={ENV[key]}")
    run("cmake", "--preset", name, "-B", directory, *args, f"-DFORGE_BUILD_ROOT={ROOT}")
    if action == "configure":
        return
    standard = directory == SOURCE / "build" / name
    build = ["cmake", "--build", "--preset", name] if standard else ["cmake", "--build", directory]
    if name == "lint" and action in ("build", "lint"):
        run(*build, "--target", "lint")
        return
    if action != "fixtures":
        run(*build, "--config", config, "--parallel")
    if action in ("test", "sanitize", "fixtures"):
        test = ["ctest", "--preset", name] if standard else [
            "ctest", "--test-dir", directory, "--output-on-failure", "--no-tests=error"]
        args = ["-R", "^fixtures$"] if action == "fixtures" else shlex.split(ENV.get("CTEST_ARGS", ""))
        run(*test, "-C", config, *args)


def main(action):
    presets = {p["name"]: p for p in json.loads((SOURCE / "CMakePresets.json").read_text())["configurePresets"]}
    exact = ENV.get("BUILD_DIR")
    selection = None if exact else requested(action, None, presets)
    directory = Path(exact).resolve() if exact else (ROOT / selection[0]).resolve()
    if any(same_directory(directory, root) for root in (SOURCE, SOURCE / "build", ROOT)):
        raise ValueError(f"{directory} is the source or output root. Select a configuration directory, "
                         "for example make provision PRESET=dev followed by make configure PRESET=dev.")
    external_lint = action == "lint" and ENV.get("LINT_DATABASE")
    if external_lint:
        identity, cache = read_identity(directory) if exact else ({}, {})
        selection = selection or requested(action, identity.get("PRESET"), presets)
        validate_identity(directory, identity, cache, *selection)
        run("cmake", "-DACTION=lint", "-DLINT_DATABASE=" + ENV["LINT_DATABASE"], "-P", "cmake/quality.cmake")
        return
    if action == "provision" and (ROOT / "CMakeCache.txt").exists():
        print(f"Legacy cache at {ROOT}/CMakeCache.txt. New configurations use subdirectories. "
              "Preserve any needed artifacts before deliberately retiring the old cache.", file=sys.stderr)
    if action == "clean" and not directory.exists():
        if exact:
            requested(action, None, presets)
        return
    if action == "update-lock":
        name, generator, configs = selection or requested(action, None, presets)
        provision(action, name, generator, configs, directory, {})
        return
    if action == "provision":
        directory.mkdir(parents=True, exist_ok=True)
    if not directory.is_dir():
        name = (selection or requested(action, None, presets))[0]
        raise ValueError(f"Run make provision PRESET={name} BUILD_DIR={shlex.quote(str(directory))} first.")
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        # Serialize selection with generation/configuration at this exact location.
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        identity, cache = read_identity(directory)
        name, generator, configs = selection or requested(action, identity.get("PRESET"), presets)
        validate_identity(directory, identity, cache, name, generator, configs)
        if action == "provision":
            provision(action, name, generator, configs, directory, identity)
        else:
            workflow(action, name, configs, directory, identity)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
    except (OSError, ValueError) as error:
        sys.exit(f"Forge: {error}")
