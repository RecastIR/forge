#pragma once

#include "forge.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"

namespace forge {
// Bind identity, regular-file validation, and byte reads to the same open descriptor.
class InputFile {
  public:
    explicit InputFile(const fs::path &path);
    ~InputFile();
    InputFile(const InputFile &) = delete;
    InputFile &operator=(const InputFile &) = delete;
    llvm::sys::fs::UniqueID id() const { return status.getUniqueID(); }
    std::unique_ptr<llvm::MemoryBuffer> read() const;

  private:
    fs::path path;
    int fd;
    llvm::sys::fs::file_status status;
};
} // namespace forge
