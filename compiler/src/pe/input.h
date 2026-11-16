#pragma once

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"

#include <filesystem>
#include <memory>

namespace forge {
    namespace fs = std::filesystem;

    // Bind identity, regular-file validation, and byte reads to the same open descriptor.
    class InputFile {
      public:
        explicit InputFile(const fs::path &path);
        ~InputFile();
        InputFile(const InputFile &) = delete;
        InputFile &operator=(const InputFile &) = delete;

        llvm::sys::fs::UniqueID id() const { return status.getUniqueID(); }

        const fs::path &absolutePath() const { return openedPath; }

        // Transfers the bytes and identifier. Both survive destruction of this reader
        // and subsequent changes to the underlying file.
        std::unique_ptr<llvm::MemoryBuffer> read() const;

      private:
        fs::path path, openedPath;
        int fd;
        llvm::sys::fs::file_status status;
    };
} // namespace forge
