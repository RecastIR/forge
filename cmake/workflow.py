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


def read_identity(directory):
    cache = directory / "CMakeCache.txt"
    configured = {}
    if cache.exists():
        configured = dict(re.findall(r"^(\w+):\w+=(.*)$", cache.read_text(), re.M))
        if Path(configured.get("CMAKE_HOME_DIRECTORY", "")) != SOURCE:
            raise ValueError(f"{directory} has an unmanaged or unrelated CMake cache. Select a fresh BUILD_DIR.")
    generated = {}
    toolchain = directory / TOOLCHAIN
    cached_path = directory / configured.get("CMAKE_TOOLCHAIN_FILE", "")
    if configured and cached_path.resolve() != toolchain.resolve():
        raise ValueError(f"{directory} has an unrelated toolchain or unmanaged CMake cache. Select a fresh BUILD_DIR.")
    recorded = configured.get("FORGE_CONFIGURED_PRESET") or configured.get("FORGE_CONAN_PRESET")
    profile = configured.get("FORGE_CONFIGURED_PROFILE_ID") or configured.get("FORGE_CONAN_PROFILE_ID")
    if toolchain.parent.is_symlink() or toolchain.is_symlink():
        raise ValueError(f"Expected a configuration-owned Conan directory at {toolchain.parent}. Use a fresh BUILD_DIR.")
    if toolchain.exists():
        generated = dict(re.findall(r'^set\(FORGE_CONAN_(\w+) "?([^" ]+)"? CACHE ',
                                    toolchain.read_text(), re.M))
        if not all(generated.get(key) for key in ("PRESET", "PROFILE_ID", "WITH_CLI")):
            raise ValueError(f"Incomplete Conan workflow information in {toolchain}. Provision a fresh BUILD_DIR.")
    if configured and not recorded:
        # A preset invoked before provisioning stops before project() and records
        # just its request. Allow the exact remediation printed by CMake.
        requested_preset = configured.get("FORGE_PRESET")
        if not requested_preset or configured.get("CMAKE_PROJECT_NAME"):
            raise ValueError(f"{directory} lacks a recorded workflow. Select a fresh BUILD_DIR.")
        recorded = requested_preset
    if generated and recorded and (generated["PRESET"] != recorded or
                                   (profile and generated["PROFILE_ID"] != profile)):
        raise ValueError(f"The CMake cache and Conan integration in {directory} disagree. Select a fresh BUILD_DIR.")
    if not generated and recorded:
        generated["PRESET"] = recorded
        if profile:
            generated.update(PROFILE_ID=profile, WITH_CLI=configured.get("FORGE_BUILD_CLI", "ON"))
    if not generated and (directory / "conan").exists():
        raise ValueError(f"Incomplete Conan integration in {directory}. Provision a fresh BUILD_DIR.")
    return generated


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
    if recorded and name != recorded:
        raise ValueError(f"This BUILD_DIR belongs to PRESET={recorded}, requested {name}. Select a different BUILD_DIR.")
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
             "FORGE_PRESET", "FORGE_BUILD_ROOT", "FORGE_CONFIGURED_", "FORGE_CONAN_")
    if any(arg.removeprefix("-D").startswith(owned) for arg in args):
        raise ValueError("Select the workflow and dependency toolchain through PRESET, CONFIG and make provision.")
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
    directory = Path(exact).resolve() if exact else ROOT / requested(action, None, presets)[0]
    if directory in (SOURCE, SOURCE / "build", ROOT):
        raise ValueError(f"{directory} is the source or output root. Select a configuration directory, "
                         "for example make provision PRESET=dev followed by make configure PRESET=dev.")
    if action == "lint" and ENV.get("LINT_DATABASE"):
        requested(action, read_identity(directory).get("PRESET") if exact else None, presets)
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
        name, generator, configs = requested(action, None, presets)
        provision(action, name, generator, configs, directory, {})
        return
    if action == "provision":
        directory.mkdir(parents=True, exist_ok=True)
    if not directory.is_dir():
        name = requested(action, None, presets)[0]
        raise ValueError(f"Run make provision PRESET={name} BUILD_DIR={shlex.quote(str(directory))} first.")
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        # Serialize selection with generation/configuration at this exact location.
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        identity = read_identity(directory)
        name, generator, configs = requested(action, identity.get("PRESET"), presets)
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
