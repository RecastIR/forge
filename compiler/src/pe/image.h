#pragma once

#include "diagnostic.h"
#include "input.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/BinaryFormat/COFF.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <variant>
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
        bool discardable, shared;

        uint32_t initializedSize() const { return std::min(virtualSize, rawSize); }

        bool immutable() const {
            return permissions[0] == 'r' && permissions[1] != 'w' && !discardable;
        }

        bool writableData() const { return permissions == "rw-" && !discardable; }
    };

    struct RvaRange {
        uint64_t begin, end;
    };

    // Return whole ranges intersecting a nonempty interval in a sorted, disjoint index.
    llvm::ArrayRef<RvaRange> rangesIn(llvm::ArrayRef<RvaRange> view, RvaRange range);

    struct MappedRange {
        const Section &section;
        llvm::StringRef bytes;
        uint64_t fileOffset;
    };

    struct Symbol {
        std::string name;
        std::optional<uint16_t> ordinal;
        uint32_t hintNameRva = 0;
    };

    inline constexpr unsigned importSlotWidth = 8;

    struct Import {
        std::string name, normalizedName;
        bool delayed, bound;
        uint32_t descriptorRva, nameRva, lookupRva, addressTableRva, delayHandleRva;
        uint64_t descriptorOffset;
        // Entry i describes the slot at addressTableRva + i * importSlotWidth.
        // lookupRva is the original table, zero when the descriptor uses FirstThunk alone.
        std::vector<Symbol> symbols;
    };

    class RelocationIndex;

    struct ImportSlot {
        const Import &descriptor;
        const Symbol &symbol;
        uint32_t lookupEntryRva;
        // Check the original named-import evidence used for an executable binding.
        std::optional<uint32_t> unstableIdentityRva(const RelocationIndex &relocations,
                                                    llvm::ArrayRef<RvaRange> loaderWrites) const;
    };

    class ImportBindings {
      public:
        llvm::ArrayRef<Import> entries() const & { return descriptors; }

        llvm::ArrayRef<Import> entries() const && = delete;

        std::optional<ImportSlot> at(uint32_t slotRva) const &;
        std::optional<ImportSlot> at(uint32_t) const && = delete;

      private:
        friend class ParsedImage;
        // Sorted by the beginning of each disjoint descriptor-owned IAT span.
        std::vector<Import> descriptors;
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

    unsigned relocationWidth(unsigned type);

    struct ImageInitialization {
        // Sorted indices borrow the parsed relocation records for the duration of translation.
        std::vector<const Relocation *> fields;
        std::vector<RvaRange> excluded;
        std::vector<RvaRange> conflicts;
        void validateRelocations(RvaRange range) const;
        llvm::ArrayRef<const Relocation *> relocationsIn(RvaRange range) const;
        llvm::ArrayRef<RvaRange> exclusionsIn(RvaRange range) const;
    };

    struct ImageBytes {
        struct Fragment {
            uint64_t offset;
            std::string bytes;
        };

        std::string prefix;
        // Only relocated bytes that differ from the implicit zero tail need storage.
        std::vector<Fragment> tail;
    };

    struct RelocationBlock {
        uint32_t pageRva, size;
        std::vector<Relocation> entries;
    };

    // Code validation only needs fixup footprints. Borrow the parsed image's
    // records so diagnostics can identify the first overlap in PE order.
    class RelocationIndex {
      public:
        explicit RelocationIndex(llvm::ArrayRef<RelocationBlock> blocks);
        const Relocation *firstOverlap(RvaRange range) const;

      private:
        llvm::ArrayRef<RelocationBlock> blocks;
        std::vector<RvaRange> ranges;
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

        unsigned trailingBytes() const;
    };

    struct Module {
        fs::path path;
        llvm::COFF::MachineTypes machine;
        bool dll;
        bool relocationsStripped;
        uint64_t imageBase;
        uint32_t entryPoint, sizeOfImage;
        std::vector<Section> sections;
        std::vector<Import> imports;
        std::vector<Export> exports;
        std::vector<RelocationBlock> relocations;
        std::optional<TLS> tls;
        std::optional<Exceptions> exceptions;

        std::string architecture() const;
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

        // Borrow exactly the validated SizeOfHeaders bytes from the input snapshot.
        llvm::StringRef headerBytes() const &;
        llvm::StringRef headerBytes() const && = delete;

        // Both the section and bytes in a returned range borrow this image.
        // Omitting size maps to the end of the file-backed extent.
        std::optional<MappedRange> mapRva(uint64_t rva,
                                          std::optional<uint32_t> size = std::nullopt) const;
        const Section *sectionAtRva(uint64_t rva) const;
        // Borrow the initialized prefix of a virtual interval inside a single section.
        // The remaining bytes in the interval are zero-filled by the PE loader.
        llvm::StringRef initializedBytes(RvaRange range) const;
        bool advertisesDynamicRelocations() const;
        // Checks the PE loader requirements for a standalone native executable.
        void validateExecutableLayout(uint64_t guestBase) const;
        std::vector<RvaRange> loaderWrittenRanges() const;
        // Borrows the immutable index for this snapshot. Ownership failures are cached too.
        const ImportBindings &importBindings() const &;
        const ImportBindings &importBindings() const && = delete;
        ImageInitialization imageInitialization() const;
        ImageBytes imageBytes(RvaRange range, const ImageInitialization &init,
                              uint64_t guestLoadBase) const;
        // DWARF enrichment borrows this object for the duration of its lookup.
        const llvm::object::ObjectFile &object() const;

      private:
        ImportBindings buildImportBindings() const;
        friend Module inspectPE(const InputFile &input);
        std::vector<RvaRange> tlsAndConfigWrites() const;

        llvm::sys::fs::UniqueID identity;
        fs::path openedPath;
        // COFF borrows the snapshot and must be destroyed before it.
        std::unique_ptr<llvm::MemoryBuffer> buffer;
        std::unique_ptr<llvm::object::COFFObjectFile> coff;
        Module metadata;
        mutable std::once_flag importValidation;
        mutable std::variant<ImportBindings, InspectionError> bindings;
    };

    // Inspection reports keep detached metadata after the image releases its bytes.
    Module inspectPE(const InputFile &input);
} // namespace forge
