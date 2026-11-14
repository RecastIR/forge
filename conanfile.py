from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.cmake import CMakeDeps, CMakeToolchain


class ForgeDependencies(ConanFile):
    settings = "os", "arch", "compiler", "build_type"
    options = {"with_cli": [True, False]}
    default_options = {"with_cli": True}

    def requirements(self):
        if self.options.with_cli:
            self.requires("cli11/2.7.2", options={"header_only": True})

    def layout(self):
        self.folders.generators = "conan"

    def validate(self):
        if self.settings.os != "Macos" or self.settings.arch != "armv8":
            raise ConanInvalidConfiguration("Forge builds on macOS arm64.")
        if (self.settings.compiler not in ("apple-clang", "clang")
                or self.settings.compiler.libcxx != "libc++" or self.settings.compiler.cppstd != "20"):
            raise ConanInvalidConfiguration("Forge requires Clang with libc++ and C++20.")

    def generate(self):
        CMakeDeps(self).generate()
        toolchain = CMakeToolchain(self)
        toolchain.user_presets_path = False
        # Conan's Apple block force-writes the architecture and SDK even when a
        # developer explicitly selected them. Supply native defaults and let
        # Forge verify the effective selection after CMake identifies the tools.
        toolchain.blocks.remove("apple_system")
        toolchain.variables["CMAKE_OSX_ARCHITECTURES"] = "arm64"
        toolchain.variables["CMAKE_OSX_SYSROOT"] = self.conf.get("tools.apple:sdk_path") or "macosx"
        if self.settings.os.get_safe("version"):
            toolchain.variables["CMAKE_OSX_DEPLOYMENT_TARGET"] = str(self.settings.os.version)
        toolchain.variables["FORGE_CONAN_DIRECTORY"] = "${CMAKE_CURRENT_LIST_DIR}"
        toolchain.variables["FORGE_CONAN_PRESET"] = self.conf.get("user.forge:preset", default="dev")
        toolchain.variables["FORGE_CONAN_PROFILE_ID"] = self.conf.get("user.forge:profile_id", default="")
        toolchain.variables["FORGE_CONAN_WITH_CLI"] = bool(self.options.with_cli)
        toolchain.variables["FORGE_CONAN_GENERATOR"] = toolchain.generator
        toolchain.variables["FORGE_CONAN_BUILD_TYPE"] = str(self.settings.build_type)
        toolchain.variables["FORGE_CONAN_COMPILER"] = (
            "AppleClang" if self.settings.compiler == "apple-clang" else "Clang")
        toolchain.variables["FORGE_CONAN_COMPILER_VERSION"] = str(self.settings.compiler.version)
        toolchain.generate()
