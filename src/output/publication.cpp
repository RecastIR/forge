#include "output/publication.h"

#include "diagnostic.h"
#include "pe/image.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ToolOutputFile.h"

#include <fcntl.h>
#include <unistd.h>

namespace forge {
    namespace {
        using namespace llvm;

        int createSiblingTemporary(const fs::path &output, fs::path &temporary) {
            const auto parent = output.parent_path();
            // Use the opposite dot prefix so even an absent destination cannot be the temporary.
            const StringRef model = output.filename().native().starts_with('.')
                                        ? "forge.tmp-%%%%%%%%"
                                        : ".forge.tmp-%%%%%%%%";
            SmallString<32> name;

            for (unsigned attempt = 0; attempt < 128; ++attempt) {
                sys::fs::createUniquePath(model, name, /*MakeAbsolute=*/false);
                temporary = parent / name.c_str();
                int fd;
                const auto error =
                    sys::fs::openFileForWrite(temporary.native(), fd, sys::fs::CD_CreateNew);

                if (!error) {
                    return fd;
                }

                if (error != std::errc::file_exists) {
                    throw InspectionError(error.message(), FailureCode::OutputCreate);
                }
            }

            throw InspectionError("could not create a unique sibling temporary file",
                                  FailureCode::OutputCreate);
        }

        void writeAndReplace(const llvm::Module &module, const fs::path &output) {
            fs::path temporary;
            int fd = createSiblingTemporary(output, temporary);
            llvm::scope_exit discardOnFailure([&] {
                // Preserve the acquisition error while rolling back the unpublished file.
                (void)sys::fs::closeFile(fd);
                (void)sys::fs::remove(temporary.native());
            });

            // LLVM reserves descriptors 0–2 even if open() reused a closed standard stream.
            if (fd <= STDERR_FILENO) {
                const int duplicate =
                    sys::RetryAfterSignal(-1, ::fcntl, fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);

                if (duplicate < 0) {
                    throw InspectionError(sys::StrError(), FailureCode::OutputDescriptor);
                }

                const auto error = sys::fs::closeFile(fd);
                fd = duplicate;

                if (error) {
                    throw InspectionError(error.message(), FailureCode::OutputClose);
                }
            }

            ToolOutputFile file(temporary.native(), fd);
            discardOnFailure.release();
            auto &stream = file.os();
            module.print(stream, nullptr);
            stream.flush();
            const auto writeError = stream.error();
            stream.clear_error();
            stream.close();
            const auto closeError = stream.error();
            stream.clear_error();

            if (writeError) {
                throw InspectionError(writeError.message(), FailureCode::OutputWrite);
            }

            if (closeError) {
                throw InspectionError(closeError.message(), FailureCode::OutputClose);
            }

            if (auto ec = sys::fs::rename(temporary.native(), output.native())) {
                throw InspectionError(ec.message(), FailureCode::OutputReplace);
            }

            file.keep();
        }

        // A filename can be absent after loading. Compare the parent identities so
        // equivalent spellings through symlinked directories still protect that name.
        bool sameDirectoryEntry(const fs::path &input, const fs::path &output) {
            if (input == output) {
                return true;
            }

            if (input.filename() != output.filename()) {
                return false;
            }

            std::error_code error;
            return fs::equivalent(input.parent_path(), output.parent_path(), error);
        }
    } // namespace

    fs::path checkedOutputDestination(const ParsedImage &input, const fs::path &output) {
        llvm::sys::fs::UniqueID destination;
        std::error_code error;
        const auto path = fs::absolute(output, error);

        if (error) {
            InspectionError failure(error.message(), FailureCode::OutputCreate);
            failure.context.input = input.module().path;
            failure.context.output = output;
            throw failure;
        }

        // The original filename may now refer to a different file. Protect both that path
        // and aliases for the file whose descriptor supplied the parsed bytes.
        if ((!llvm::sys::fs::getUniqueID(path.native(), destination) &&
             destination == input.id()) ||
            fs::equivalent(input.absolutePath(), path, error) ||
            sameDirectoryEntry(input.absolutePath(), path)) {
            InspectionError failure("--output must differ from the input image",
                                    FailureCode::OutputAlias);
            failure.context.input = input.module().path;
            failure.context.output = output;
            throw failure;
        }

        return path;
    }

    void publishIR(const llvm::Module &module, const ParsedImage &input, const fs::path &output) {
        try {
            writeAndReplace(module, checkedOutputDestination(input, output));
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
    }
} // namespace forge
