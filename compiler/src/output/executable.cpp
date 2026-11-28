#include "output/executable.h"

#include "diagnostic.h"
#include "output/publication.h"
#include "pe/image.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/Object/MachO.h"
#include "llvm/Support/Program.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <tuple>
#include <unistd.h>

namespace forge {
    namespace {
        using namespace llvm;

        enum class NativeProduct : uint8_t { Object, Executable };

#if defined(__APPLE__) && defined(__aarch64__)
        constexpr bool nativeHost = true;
#else
        constexpr bool nativeHost = false;
#endif

        std::string diagnosticText(const fs::path &path) {
            std::array<char, 8192> bytes{};
            std::ifstream stream(path, std::ios::binary);
            stream.read(bytes.data(), bytes.size());
            return StringRef(bytes.data(), static_cast<size_t>(stream.gcount())).trim().str();
        }

        void runTool(const fs::path &program, const std::vector<std::string> &arguments,
                     const fs::path &log, FailureCode code, StringRef operation) {
            if (program.empty() || !sys::fs::can_execute(program.native())) {
                throw InspectionError(operation.str() + " requires executable tool " +
                                          (program.empty() ? "(unconfigured)" : program.string()),
                                      FailureCode::NativeTool);
            }

            SmallVector<StringRef> argv{program.native()};
            argv.append(arguments.begin(), arguments.end());
            const std::optional<StringRef> redirects[]{StringRef(), StringRef(), log.native()};
            std::string reason;
            const auto status =
                sys::ExecuteAndWait(program.native(), argv, std::nullopt, redirects, 0, 0, &reason);

            if (status != 0) {
                auto detail = diagnosticText(log);

                if (!reason.empty()) {
                    detail = reason + (detail.empty() ? "" : "\n" + detail);
                }

                throw InspectionError(operation.str() + " failed (" + program.string() +
                                          ", status " + std::to_string(status) + ")" +
                                          (detail.empty() ? "" : ": " + detail),
                                      code);
            }
        }

        void checkArchive(const fs::path &archive, const fs::path &output, StringRef name) {
            std::error_code error;

            if (!fs::is_regular_file(archive, error)) {
                throw InspectionError("missing " + name.str() + " archive: " + archive.string(),
                                      FailureCode::NativeTool);
            }

            if (fs::equivalent(archive, output, error)) {
                throw InspectionError("--output aliases the " + name.str() + " archive",
                                      FailureCode::OutputAlias);
            }
        }

        void verifyMachO(const fs::path &path, NativeProduct product) {
            const bool executable = product == NativeProduct::Executable;
            const auto code = executable ? FailureCode::NativeLink : FailureCode::NativeCodegen;
            auto binary = object::createBinary(path.native());

            if (!binary) {
                throw InspectionError("cannot read native output: " + toString(binary.takeError()),
                                      code);
            }

            const auto *mach = dyn_cast<object::MachOObjectFile>(binary->getBinary());
            const auto requiredType = executable ? MachO::MH_EXECUTE : MachO::MH_OBJECT;

            if (!mach || !mach->is64Bit() || mach->getHeader64().cputype != MachO::CPU_TYPE_ARM64 ||
                mach->getHeader64().filetype != requiredType) {
                throw InspectionError(executable
                                          ? "linker output must be a thin ARM64 Mach-O executable"
                                          : "codegen output must be a thin ARM64 Mach-O object",
                                      code);
            }

            const bool macOS = llvm::any_of(mach->load_commands(), [&](const auto &command) {
                return command.C.cmd == MachO::LC_VERSION_MIN_MACOSX ||
                       (command.C.cmd == MachO::LC_BUILD_VERSION &&
                        mach->getBuildVersionLoadCommand(command).platform ==
                            MachO::PLATFORM_MACOS);
            });

            if (!macOS) {
                throw InspectionError("native Mach-O output must target macOS", code);
            }

            if (executable && !sys::fs::can_execute(path.native())) {
                throw InspectionError("linked Mach-O lacks execute permission", code);
            }
        }

        fs::path emitObject(const llvm::Module &module, const ParsedImage &input,
                            const fs::path &directory, const ExecutableToolchain &tools,
                            bool optimize) {
            auto source = directory / "guest.ll";
            const auto object = directory / "guest.o";
            const auto log = directory / "tool.stderr";
            publishIR(module, input, source);

            if (optimize) {
                const auto bitcode = directory / "guest.bc";
                runTool(tools.opt, {"-passes=default<O2>", "-verify-each", source, "-o", bitcode},
                        log, FailureCode::NativeOptimization, "LLVM optimization");
                source = bitcode;
            }

            runTool(tools.llc,
                    {optimize ? "-O2" : "-O0", "-filetype=obj", "-relocation-model=pic", source,
                     "-o", object},
                    log, FailureCode::NativeCodegen, "ARM64 object generation");
            verifyMachO(object, NativeProduct::Object);
            return object;
        }

        fs::path linkExecutable(const fs::path &object, const ExecutableToolchain &tools) {
            const auto directory = object.parent_path();
            const auto executable = directory / "program";
            std::vector<std::string> link{"--sdk", tools.sdk, "clang++", "-arch", "arm64"};
            link.insert(link.end(), tools.linkFlags.begin(), tools.linkFlags.end());
            link.insert(link.end(), {object, fs::absolute(tools.startup),
                                     fs::absolute(tools.runtime), "-o", executable});
            runTool(tools.xcrun, link, directory / "tool.stderr", FailureCode::NativeLink,
                    "macOS link using SDK " + tools.sdk);
            verifyMachO(executable, NativeProduct::Executable);
            return executable;
        }

        void publish(const llvm::Module &module, const ParsedImage &input, const fs::path &output,
                     const ExecutableToolchain &tools, bool optimize, NativeProduct product) try {
            const auto destination = checkedOutputDestination(input, output);

            if (product == NativeProduct::Executable) {
                if (!nativeHost) {
                    throw InspectionError("native executable linking requires macOS ARM64",
                                          FailureCode::NativeHost);
                }

                checkArchive(tools.startup, destination, "Forge startup");
                checkArchive(tools.runtime, destination, "Forge runtime");
            }

            // Private staging on the destination filesystem lets the linker sign the executable
            // in place. The destination becomes visible only after verification.
            const char *prefix = destination.filename().native().starts_with('.')
                                     ? "forge-link-XXXXXX"
                                     : ".forge-link-XXXXXX";
            auto pattern = (destination.parent_path() / prefix).string();

            if (!::mkdtemp(pattern.data())) {
                throw InspectionError("cannot create native build directory: " +
                                          std::error_code(errno, std::generic_category()).message(),
                                      FailureCode::OutputCreate);
            }

            scope_exit cleanup([&] {
                // Keep the original tool or publication error on rollback.
                std::ignore = sys::fs::remove_directories(pattern);
            });
            const fs::path directory(pattern);
            auto native = emitObject(module, input, directory, tools, optimize);

            if (product == NativeProduct::Executable) {
                native = linkExecutable(native, tools);
            }

            if (auto error = sys::fs::rename(
                    native.native(), checkedOutputDestination(input, destination).native())) {
                throw InspectionError(error.message(), FailureCode::OutputReplace);
            }
        } catch (InspectionError &failure) {
            failure.context.input = input.module().path;
            failure.context.output = output;
            throw;
        } catch (const std::exception &error) {
            InspectionError failure(error.what(), FailureCode::PublicationInternal);
            failure.context.input = input.module().path;
            failure.context.output = output;
            throw failure;
        }
    } // namespace

    void publishNativeObject(const llvm::Module &module, const ParsedImage &input,
                             const fs::path &output, const ExecutableToolchain &tools,
                             bool optimize) {
        publish(module, input, output, tools, optimize, NativeProduct::Object);
    }

    void publishExecutable(const llvm::Module &module, const ParsedImage &input,
                           const fs::path &output, const ExecutableToolchain &tools,
                           bool optimize) {
        publish(module, input, output, tools, optimize, NativeProduct::Executable);
    }
} // namespace forge
