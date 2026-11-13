#include "input.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace forge {
    InputFile::InputFile(const fs::path &path)
        : path(path), fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)) {
        if (fd < 0) {
            throw InspectionError(std::error_code(errno, std::generic_category()).message(),
                                  "READ_ERROR");
        }
        auto ec = llvm::sys::fs::status(fd, status);
        if (ec || !llvm::sys::fs::is_regular_file(status)) {
            ::close(fd);
            throw InspectionError(ec ? ec.message() : "expected a regular file", "READ_ERROR");
        }
    }

    InputFile::~InputFile() { ::close(fd); }

    std::unique_ptr<llvm::MemoryBuffer> InputFile::read() const {
        auto result =
            llvm::MemoryBuffer::getOpenFile(fd, path.native(), status.getSize(), false, true);
        if (!result) {
            throw InspectionError(result.getError().message(), "READ_ERROR");
        }
        return std::move(*result);
    }
} // namespace forge
