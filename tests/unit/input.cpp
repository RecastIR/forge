#include "diagnostic.h"
#include "pe/image.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <fstream>
#include <type_traits>
#include <unistd.h>

namespace {
    using namespace forge;

    static_assert(!std::is_copy_constructible_v<InputFile> &&
                  !std::is_move_constructible_v<InputFile> &&
                  !std::is_copy_assignable_v<InputFile> && !std::is_move_assignable_v<InputFile>);

    static_assert(!std::is_copy_constructible_v<ParsedImage> &&
                  !std::is_move_constructible_v<ParsedImage> &&
                  !std::is_copy_assignable_v<ParsedImage> &&
                  !std::is_move_assignable_v<ParsedImage>);

    void check(bool condition, const char *message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    void writeBytes(const fs::path &path, llvm::StringRef bytes, std::ios::openmode mode) {
        std::ofstream stream;
        stream.exceptions(std::ios::failbit | std::ios::badbit);
        stream.open(path, std::ios::binary | mode);
        stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        stream.close();
    }

    void checkRetainedInput(const fs::path &path, llvm::StringRef original, bool truncate) {
        writeBytes(path, original, std::ios::trunc);
        auto buffer = InputFile(path).read();
        ParsedImage image(InputFile(path), ParsePolicy::Inspection);

        if (truncate) {
            // Fail safely on a mapping regression before truncation could invalidate its pages.
            check(buffer->getBufferKind() == llvm::MemoryBuffer::MemoryBuffer_Malloc,
                  "input still maps the source file");
            fs::resize_file(path, 0);
        } else {
            writeBytes(path, "XX", std::ios::in);
        }

        check(buffer->getBufferIdentifier() == path.native(), "lost input buffer identifier");
        check(buffer->getBuffer() == original, "retained bytes changed with the file");
        const auto &module = image.module();
        const auto entry = image.mapRva(module.entryPoint, 1);
        check(module.entryPoint == 0x1000 && entry && entry->section.name == ".text" &&
                  entry->bytes == "\xc3",
              "original PE entry instruction unavailable");
    }

    int nextDescriptor() {
        const int fd = ::dup(STDERR_FILENO);
        check(fd >= 0, "cannot probe the next file descriptor");
        check(::close(fd) == 0, "cannot release probe descriptor");
        return fd;
    }

    void checkReadFailures(const fs::path &path) {
        // In this single-threaded test the next open gets the probed descriptor.
        const int fd = nextDescriptor();

        try {
            InputFile input(path.parent_path());
            throw std::runtime_error("accepted a directory as input");
        } catch (const InspectionError &error) {
            check(error.kind == FailureCode::InputOpen && error.context.input == path.parent_path(),
                  "wrong error for directory");
        }

        check(::fcntl(fd, F_GETFD) == -1 && errno == EBADF, "failed constructor leaked its fd");
        writeBytes(path, "original length", std::ios::trunc);

        try {
            InputFile input(path);
            check(::fcntl(fd, F_GETFD) >= 0, "input did not acquire expected fd");
            fs::resize_file(path, 3);
            input.read();
            throw std::runtime_error("accepted a premature EOF");
        } catch (const InspectionError &error) {
            check(error.kind == FailureCode::InputRead && error.context.input == path,
                  "wrong error for premature EOF");
            check(llvm::StringRef(error.what()).contains("unexpected end"), "missing EOF reason");
        }

        check(::fcntl(fd, F_GETFD) == -1 && errno == EBADF, "read failure leaked its fd");
    }

    void checkRepeatedRead(const fs::path &path) {
        fs::resize_file(path, 0);
        check(InputFile(path).read()->getBuffer().empty(), "empty input acquired extra bytes");
        writeBytes(path, "old", std::ios::trunc);
        InputFile input(path);
        auto first = input.read();
        writeBytes(path, "new", std::ios::in);
        fs::rename(path, path.parent_path() / "original");
        writeBytes(path, "replacement", std::ios::trunc);
        auto second = input.read();
        check(first->getBuffer() == "old" && second->getBuffer() == "new",
              "repeated read lost its original descriptor, offset, or buffer ownership");
    }
} // namespace

int main(int argc, char **argv) try {
    check(argc == 2, "expected the minimal PE fixture");
    auto fixture = llvm::MemoryBuffer::getFile(argv[1]);
    check(static_cast<bool>(fixture), "could not load fixture");
    auto bytes = (*fixture)->getBuffer().str();
    constexpr std::size_t mebibyte = std::size_t{1024} * 1024;
    bytes.append(mebibyte, 'A');
    bytes.append(mebibyte, 'B');
    bytes.append(17, 'C');

    llvm::SmallString<128> temporary;

    if (auto ec = llvm::sys::fs::createUniqueDirectory("forge-input", temporary)) {
        throw std::system_error(ec);
    }

    llvm::scope_exit cleanup([&] { (void)llvm::sys::fs::remove_directories(temporary); });
    const forge::fs::path directory(temporary.c_str());
    const auto path = directory / "input.exe";
    checkRetainedInput(path, bytes, false);
    checkRetainedInput(path, bytes, true);
    checkReadFailures(path);
    checkRepeatedRead(path);
} catch (const std::exception &error) {
    llvm::errs() << "input lifetime: " << error.what() << '\n';
    return 1;
}
