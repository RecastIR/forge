#include "input.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/Support/Error.h"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

namespace forge {
    InputFile::InputFile(const fs::path &path) : path(path) {
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);

        if (fd < 0) {
            throw InspectionError(std::error_code(errno, std::generic_category()).message(),
                                  "READ_ERROR");
        }

        llvm::scope_exit closeOnFailure([&] { (void)llvm::sys::fs::closeFile(fd); });
        const auto Error = llvm::sys::fs::status(fd, status);

        if (Error || !llvm::sys::fs::is_regular_file(status)) {
            throw InspectionError(Error ? Error.message() : "expected a regular file",
                                  "READ_ERROR");
        }

        closeOnFailure.release();
    }

    InputFile::~InputFile() { (void)llvm::sys::fs::closeFile(fd); }

    std::unique_ptr<llvm::MemoryBuffer> InputFile::read() const {
        const uint64_t Size = status.getSize();

        if (!std::in_range<std::ptrdiff_t>(Size)) {
            throw InspectionError("input exceeds addressable buffer size", "READ_ERROR");
        }

        // LLVM checks the complete allocation including the identifier, terminator and alignment.
        auto buffer = llvm::WritableMemoryBuffer::getNewUninitMemBuffer(static_cast<size_t>(Size),
                                                                        path.native());

        if (!buffer) {
            throw InspectionError("cannot allocate input buffer", "READ_ERROR");
        }

        constexpr size_t ChunkSize = size_t{1024} * 1024;
        auto remaining = buffer->getBuffer();

        while (!remaining.empty()) {
            auto count = llvm::sys::fs::readNativeFileSlice(fd, remaining.take_front(ChunkSize),
                                                            Size - remaining.size());

            if (!count) {
                throw InspectionError(llvm::toString(count.takeError()), "READ_ERROR");
            }

            if (*count == 0) {
                throw InspectionError("unexpected end of input file", "READ_ERROR");
            }

            remaining = remaining.drop_front(*count);
        }

        return buffer;
    }
} // namespace forge
