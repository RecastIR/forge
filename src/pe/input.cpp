#include "input.h"

#include "diagnostic.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/Support/Error.h"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

namespace forge {
    namespace {
        [[noreturn]] void failInput(const fs::path &path, FailureCode kind,
                                    const std::string &message) {
            InspectionError error(message, kind);
            error.context.input = path;
            throw error;
        }
    } // namespace

    InputFile::InputFile(const fs::path &path) : path(path) {
        std::error_code pathError;
        openedPath = fs::absolute(path, pathError);

        if (pathError) {
            failInput(path, FailureCode::InputOpen, pathError.message());
        }

        fd = ::open(openedPath.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);

        if (fd < 0) {
            failInput(path, FailureCode::InputOpen,
                      std::error_code(errno, std::generic_category()).message());
        }

        llvm::scope_exit closeOnFailure([&] { (void)llvm::sys::fs::closeFile(fd); });
        const auto error = llvm::sys::fs::status(fd, status);

        if (error || !llvm::sys::fs::is_regular_file(status)) {
            failInput(path, FailureCode::InputOpen,
                      error ? error.message() : "expected a regular file");
        }

        closeOnFailure.release();
    }

    InputFile::~InputFile() { (void)llvm::sys::fs::closeFile(fd); }

    std::unique_ptr<llvm::MemoryBuffer> InputFile::read() const {
        const uint64_t size = status.getSize();

        if (!std::in_range<std::ptrdiff_t>(size)) {
            failInput(path, FailureCode::InputRead, "input exceeds addressable buffer size");
        }

        // LLVM checks the complete allocation including the identifier, terminator and alignment.
        auto buffer = llvm::WritableMemoryBuffer::getNewUninitMemBuffer(static_cast<size_t>(size),
                                                                        path.native());

        if (!buffer) {
            failInput(path, FailureCode::InputRead, "cannot allocate input buffer");
        }

        constexpr size_t chunkSize = size_t{1024} * 1024;
        auto remaining = buffer->getBuffer();

        while (!remaining.empty()) {
            auto count = llvm::sys::fs::readNativeFileSlice(fd, remaining.take_front(chunkSize),
                                                            size - remaining.size());

            if (!count) {
                failInput(path, FailureCode::InputRead, llvm::toString(count.takeError()));
            }

            if (*count == 0) {
                failInput(path, FailureCode::InputRead, "unexpected end of input file");
            }

            remaining = remaining.drop_front(*count);
        }

        return buffer;
    }
} // namespace forge
