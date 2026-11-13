#pragma once

#include "input.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/BinaryFormat/COFF.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace llvm::object {
    class COFFObjectFile;
    class ObjectFile;
} // namespace llvm::object

namespace forge {
    inline std::string hex(uint64_t n) { return "0x" + llvm::utohexstr(n, true); }

    struct Section {
        std::string name, permissions;
        uint32_t rva, virtualSize, fileOffset, rawSize;
    };

    struct MappedRange {
        const Section &section;
        llvm::StringRef bytes;
        uint64_t fileOffset;
    };

    struct Symbol {
        std::string name;
        std::optional<uint16_t> ordinal;
    };

    struct Import {
        std::string name, normalizedName;
        bool delayed;
        std::vector<Symbol> symbols;
    };

    struct Export {
        uint32_t ordinal, rva;
        std::vector<std::string> names;
        std::optional<std::string> forwarder;
    };

    struct Relocation {
        unsigned type;
        uint32_t rva;
        std::optional<int16_t> adjustment;
    };

    struct RelocationBlock {
        uint32_t pageRva, size;
        std::vector<Relocation> entries;
    };

    struct TLS {
        uint32_t rva;
        uint64_t start, end, index, callbacks;
        uint32_t zeroFill, characteristics;
        std::vector<uint64_t> callbackVas;
    };

    struct RuntimeFunction {
        uint32_t begin, end, unwind;
    };

    struct Exceptions {
        uint32_t rva, size;
        std::vector<RuntimeFunction> functions;
    };

    struct Module {
        fs::path path;
        llvm::COFF::MachineTypes machine;
        bool dll;
        uint64_t imageBase;
        uint32_t entryPoint;
        std::vector<Section> sections;
        std::vector<Import> imports;
        std::vector<Export> exports;
        std::vector<RelocationBlock> relocations;
        std::optional<TLS> tls;
        std::optional<Exceptions> exceptions;
    };

    enum class ParsePolicy { Inspection, FunctionAnalysis };

    class ParsedImage {
      public:
        ParsedImage(const InputFile &input, ParsePolicy policy);
        ~ParsedImage();
        ParsedImage(const ParsedImage &) = delete;
        ParsedImage &operator=(const ParsedImage &) = delete;

        llvm::sys::fs::UniqueID id() const { return identity; }

        const fs::path &absolutePath() const { return openedPath; }

        const Module &module() const { return metadata; }

        // Both the section and bytes in a returned range borrow this image.
        // Omitting size maps to the end of the file-backed extent.
        std::optional<MappedRange> mapRva(uint64_t rva,
                                          std::optional<uint32_t> size = std::nullopt) const;
        // DWARF enrichment borrows this object for the duration of its lookup.
        const llvm::object::ObjectFile &object() const;

      private:
        friend Module inspectPE(const InputFile &input);

        llvm::sys::fs::UniqueID identity;
        fs::path openedPath;
        // COFF borrows the snapshot and must be destroyed before it.
        std::unique_ptr<llvm::MemoryBuffer> buffer;
        std::unique_ptr<llvm::object::COFFObjectFile> coff;
        Module metadata;
    };

    // Inspection reports keep detached metadata after the image releases its bytes.
    Module inspectPE(const InputFile &input);
} // namespace forge
