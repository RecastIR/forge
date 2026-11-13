#include "analysis/analysis.h"

#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Win64EH.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <map>
#include <type_traits>

namespace forge {

    std::optional<MappedRange> mapRva(llvm::ArrayRef<Section> sections, llvm::StringRef file,
                                      uint64_t rva, std::optional<uint32_t> size) {
        for (const auto &s : sections) {
            if (rva < s.rva) {
                continue;
            }
            const uint64_t Delta = rva - s.rva;
            const uint32_t Extent = std::min(s.virtualSize, s.rawSize);
            if (Delta >= Extent) {
                continue;
            }
            const uint32_t Available = Extent - static_cast<uint32_t>(Delta);
            const uint32_t Length = size.value_or(Available);
            const uint64_t Offset = uint64_t(s.fileOffset) + Delta;
            if (Length > Available || Offset > file.size() || Length > file.size() - Offset) {
                return std::nullopt;
            }
            return MappedRange{s, file.substr(Offset, Length), Offset};
        }
        return std::nullopt;
    }

    namespace {
        using namespace llvm;
        using namespace llvm::object;
        using namespace llvm::support;

        [[noreturn]] void invalid(StringRef field, uint64_t offset, StringRef reason) {
            throw InspectionError(field.str() + " at file offset " + hex(offset) + ": " +
                                  reason.str());
        }

        // Offsets in a View are relative to a single file-backed region. Read packed
        // LLVM records by value so even an unaligned record is safe to inspect.
        struct View {
            StringRef bytes;
            uint64_t offset;
            StringRef label;

            View slice(uint64_t pos, uint64_t size) const {
                if (pos > bytes.size() || size > bytes.size() - pos) {
                    invalid(label, offset + std::min<uint64_t>(pos, bytes.size()),
                            "range exceeds available bytes");
                }
                return {bytes.substr(pos, size), offset + pos, label};
            }

            template <typename T> T read(uint64_t pos = 0) const {
                static_assert(std::is_trivially_copyable_v<T>);
                T value;
                std::memcpy(&value, slice(pos, sizeof(T)).bytes.data(), sizeof(T));
                return value;
            }
        };

        std::string machineName(uint16_t machine) {
            switch (machine) {
            case COFF::IMAGE_FILE_MACHINE_I386:
                return "i386";
            case COFF::IMAGE_FILE_MACHINE_ARM64:
                return "arm64";
            case COFF::IMAGE_FILE_MACHINE_ARM64EC:
                return "arm64ec";
            default:
                return hex(machine);
            }
        }

        // The caller's buffer backs both file and the owned COFF object for the lifetime
        // of this parser. inspect() returns metadata with its own storage.
        class Image {
          public:
            explicit Image(MemoryBufferRef buffer);
            Module inspect(bool analysis = false);

            const COFFObjectFile &coff() const { return *object; }

          private:
            View file;
            pe32plus_header header;
            std::vector<Section> sections;
            std::unique_ptr<COFFObjectFile> object;
            // Shared or overlapping tables can expand a tiny input into a huge report.
            size_t remainingRecords = 1'000'000;
            size_t remainingNameBytes = size_t{64} * 1024 * 1024;

            View tail(uint64_t rva, StringRef label) const;
            std::optional<View> directory(unsigned index, StringRef label) const;
            void count(size_t records, const View &where);
            std::string name(View data);
            std::vector<Symbol> symbols(uint32_t rva);
            void imports(Module &module, bool delayed);
            void exports(Module &module);
            void relocations(Module &module);
            void tls(Module &module);
            void exceptions(Module &module, bool recover);
        };

        View Image::tail(uint64_t rva, StringRef label) const {
            if (auto mapped = mapRva(sections, file.bytes, rva)) {
                return {mapped->bytes, mapped->fileOffset, label};
            }
            throw InspectionError(label.str() + " RVA " + hex(rva) +
                                  " is outside file-backed sections");
        }

        Image::Image(MemoryBufferRef buffer) : file{buffer.getBuffer(), 0, "PE headers"} {
            auto dos = file.read<dos_header>();
            if (StringRef(dos.Magic, 2) != "MZ") {
                invalid(file.label, 0, "expected an MZ executable");
            }
            uint64_t pe = dos.AddressOfNewExeHeader;
            if (file.slice(pe, 4).bytes != StringRef("PE\0\0", 4)) {
                invalid(file.label, pe, "expected PE signature");
            }

            const auto Coff = file.read<coff_file_header>(pe + 4);
            if (Coff.Machine != COFF::IMAGE_FILE_MACHINE_AMD64) {
                auto arch = machineName(Coff.Machine);
                throw InspectionError("expected AMD64, found " + arch + " at file offset " +
                                          hex(pe + 4),
                                      "UNSUPPORTED_ARCHITECTURE", arch);
            }
            if (!(Coff.Characteristics & COFF::IMAGE_FILE_EXECUTABLE_IMAGE)) {
                invalid(file.label, pe, "expected an executable image");
            }
            uint64_t opt = pe + 4 + sizeof(Coff);
            View optional = file.slice(opt, Coff.SizeOfOptionalHeader);
            if (optional.read<ulittle16_t>() != COFF::PE32Header::PE32_PLUS) {
                invalid(file.label, opt, "expected PE32+ optional header");
            }
            header = optional.read<pe32plus_header>();
            optional.slice(sizeof(header),
                           uint64_t(header.NumberOfRvaAndSize) * sizeof(data_directory));
            if (header.AddressOfEntryPoint && header.AddressOfEntryPoint >= header.SizeOfImage) {
                invalid(file.label, opt, "entry point RVA exceeds SizeOfImage");
            }
            if (!Coff.NumberOfSections || Coff.NumberOfSections > 96) {
                invalid(file.label, pe, "expected 1 to 96 PE sections");
            }
            uint64_t table = opt + Coff.SizeOfOptionalHeader;
            auto sectionHeaders =
                file.slice(table, uint64_t(Coff.NumberOfSections) * sizeof(coff_section));
            if (table + sectionHeaders.bytes.size() > header.SizeOfHeaders ||
                header.SizeOfHeaders > file.bytes.size()) {
                invalid(file.label, opt, "invalid SizeOfHeaders");
            }
            for (unsigned i = 0; i < Coff.NumberOfSections; ++i) {
                auto s = sectionHeaders.read<coff_section>(i * sizeof(coff_section));
                if (s.SizeOfRawData &&
                    (!s.PointerToRawData ||
                     uint64_t(s.PointerToRawData) + s.SizeOfRawData > file.bytes.size())) {
                    invalid("section raw data", table + i * sizeof(s),
                            "missing or truncated file range");
                }
                if (uint64_t(s.VirtualAddress) + s.VirtualSize > header.SizeOfImage) {
                    invalid("section virtual range", table + i * sizeof(s), "exceeds SizeOfImage");
                }
                for (const auto &previous : sections) {
                    if (s.VirtualSize && previous.virtualSize &&
                        s.VirtualAddress < uint64_t(previous.rva) + previous.virtualSize &&
                        previous.rva < uint64_t(s.VirtualAddress) + s.VirtualSize) {
                        invalid("section virtual range", table + i * sizeof(s),
                                "overlaps another section");
                    }
                }
                std::string rwx = "---";
                if (s.Characteristics & COFF::IMAGE_SCN_MEM_READ) {
                    rwx[0] = 'r';
                }
                if (s.Characteristics & COFF::IMAGE_SCN_MEM_WRITE) {
                    rwx[1] = 'w';
                }
                if (s.Characteristics & COFF::IMAGE_SCN_MEM_EXECUTE) {
                    rwx[2] = 'x';
                }
                sections.push_back({{},
                                    rwx,
                                    s.VirtualAddress,
                                    s.VirtualSize,
                                    s.PointerToRawData,
                                    s.SizeOfRawData});
            }
            if (Coff.NumberOfSymbols && !Coff.PointerToSymbolTable) {
                invalid("COFF symbol table", pe + 4, "missing file offset");
            }
            if (Coff.PointerToSymbolTable) {
                uint64_t strings = uint64_t(Coff.PointerToSymbolTable) +
                                   uint64_t(Coff.NumberOfSymbols) * sizeof(coff_symbol16);
                if (strings > UINT32_MAX) {
                    invalid("COFF symbol table", Coff.PointerToSymbolTable, "file offset overflow");
                }
                uint32_t length = file.read<ulittle32_t>(strings);
                auto tableBytes = file.slice(strings, length);
                if (length > 4 && tableBytes.bytes.back() != '\0') {
                    invalid("COFF string table", strings, "missing terminator");
                }
            }

            // LLVM initializes load configuration during create(), before returning an
            // object. Validate its internal size first and identify hybrid ARM64EC here.
            if (header.NumberOfRvaAndSize > COFF::LOAD_CONFIG_TABLE) {
                auto dir = optional.read<data_directory>(
                    sizeof(header) + COFF::LOAD_CONFIG_TABLE * sizeof(data_directory));
                if (dir.RelativeVirtualAddress) {
                    View config =
                        tail(dir.RelativeVirtualAddress, "load configuration").slice(0, dir.Size);
                    uint32_t size = config.read<ulittle32_t>();
                    config.slice(0, size);
                    constexpr size_t Chpe =
                        offsetof(coff_load_configuration64, CHPEMetadataPointer);
                    if (size >= Chpe + 8 && config.read<ulittle64_t>(Chpe)) {
                        throw InspectionError("hybrid ARM64EC image; expected AMD64",
                                              "UNSUPPORTED_ARCHITECTURE", "arm64ec");
                    }
                }
            }
            auto parsed = COFFObjectFile::create(buffer);
            if (!parsed) {
                throw InspectionError("PE/COFF headers: " + toString(parsed.takeError()));
            }
            object = std::move(*parsed);
        }

        std::optional<View> Image::directory(unsigned index, StringRef label) const {
            const auto *dir = object->getDataDirectory(index);
            if (!dir || (!dir->RelativeVirtualAddress && !dir->Size)) {
                return std::nullopt;
            }
            if (!dir->RelativeVirtualAddress || !dir->Size) {
                throw InspectionError(label.str() + " has an incomplete directory entry at RVA " +
                                      hex(dir->RelativeVirtualAddress));
            }
            return tail(dir->RelativeVirtualAddress, label).slice(0, dir->Size);
        }

        void Image::count(size_t records, const View &where) {
            if (records > remainingRecords) {
                invalid(where.label, where.offset, "inspection record limit exceeded");
            }
            remainingRecords -= records;
        }

        std::string Image::name(View data) {
            size_t length = data.bytes.take_front(remainingNameBytes + 1).find('\0');
            if (length == StringRef::npos) {
                invalid(data.label, data.offset, "unterminated name or name budget exceeded");
            }
            auto str = data.bytes.take_front(length);
            if (str.empty() || !json::isUTF8(str)) {
                invalid(data.label, data.offset, "empty or invalid UTF-8 name");
            }
            remainingNameBytes -= length;
            return str.str();
        }

        std::vector<Symbol> Image::symbols(uint32_t rva) {
            View data = tail(rva, "import lookup table");
            std::vector<Symbol> result;
            for (size_t pos = 0;; pos += 8) {
                auto entry = data.read<import_lookup_table_entry64>(pos);
                uint64_t value = static_cast<uint64_t>(entry.Data);
                if (!value) {
                    return result;
                }
                count(1, data);
                if (entry.isOrdinal()) {
                    if (value & UINT64_C(0x7fffffffffff0000)) {
                        invalid(data.label, data.offset + pos, "reserved ordinal bits are set");
                    }
                    result.push_back({{}, entry.getOrdinal()});
                } else {
                    if (value > UINT32_MAX) {
                        invalid(data.label, data.offset + pos, "expected a hint/name RVA");
                    }
                    View hintName = tail(value, "import hint/name");
                    hintName.read<ulittle16_t>();
                    result.push_back(
                        {name(hintName.slice(2, hintName.bytes.size() - 2)), std::nullopt});
                }
            }
        }

        void Image::imports(Module &module, bool delayed) {
            auto dir = delayed ? directory(COFF::DELAY_IMPORT_DESCRIPTOR, "delay imports")
                               : directory(COFF::IMPORT_TABLE, "imports");
            if (!dir) {
                return;
            }
            size_t pos = 0;
            for (;;) {
                uint32_t dllName, lookup;
                if (delayed) {
                    auto d = dir->read<delay_import_directory_table_entry>(pos);
                    if (dir->bytes.substr(pos, sizeof(d)).find_first_not_of('\0') ==
                        StringRef::npos) {
                        return;
                    }
                    if (d.Attributes != 1) {
                        invalid(
                            dir->label, dir->offset + pos,
                            "unsupported delay descriptor attributes (expected RVA-based form)");
                    }
                    dllName = d.Name;
                    lookup = d.DelayImportNameTable;
                    pos += sizeof(d);
                } else {
                    auto d = dir->read<coff_import_directory_table_entry>(pos);
                    if (d.isNull()) {
                        return;
                    }
                    dllName = d.NameRVA;
                    lookup =
                        d.ImportLookupTableRVA ? d.ImportLookupTableRVA : d.ImportAddressTableRVA;
                    pos += sizeof(d);
                }
                count(1, *dir);
                auto spelling = name(tail(dllName, "import DLL name"));
                module.imports.push_back(
                    {spelling, StringRef(spelling).lower(), delayed, symbols(lookup)});
            }
        }

        void Image::exports(Module &module) {
            auto dir = directory(COFF::EXPORT_TABLE, "exports");
            if (!dir) {
                return;
            }
            auto d = dir->read<export_directory_table_entry>();
            uint64_t entries = d.AddressTableEntries;
            uint64_t names = d.NumberOfNamePointers;
            count(entries + names, *dir);
            std::map<uint32_t, std::vector<std::string>> aliases;
            if (names) {
                View pointers = tail(d.NamePointerRVA, "export name pointers").slice(0, names * 4);
                View indices =
                    tail(d.OrdinalTableRVA, "export ordinal indices").slice(0, names * 2);
                for (uint64_t i = 0; i < names; ++i) {
                    uint16_t index = indices.read<ulittle16_t>(i * 2);
                    if (index >= entries) {
                        invalid(indices.label, indices.offset + i * 2,
                                "index exceeds address table");
                    }
                    aliases[index].push_back(
                        name(tail(pointers.read<ulittle32_t>(i * 4), "export name")));
                }
            }
            if (!entries) {
                return;
            }
            View addresses =
                tail(d.ExportAddressTableRVA, "export addresses").slice(0, entries * 4);
            uint64_t base = object->getDataDirectory(COFF::EXPORT_TABLE)->RelativeVirtualAddress;
            for (uint64_t i = 0; i < entries; ++i) {
                uint32_t rva = addresses.read<ulittle32_t>(i * 4);
                const auto Alias =
                    aliases.find(static_cast<uint32_t>(i)); // AddressTableEntries is 32-bit.
                if (!rva) {
                    if (Alias != aliases.end()) {
                        invalid(addresses.label, addresses.offset + i * 4,
                                "name refers to an unused ordinal");
                    }
                    continue;
                }
                if (rva >= header.SizeOfImage) {
                    invalid(addresses.label, addresses.offset + i * 4,
                            "export RVA exceeds SizeOfImage");
                }
                uint64_t ordinal = uint64_t(d.OrdinalBase) + i;
                if (ordinal > UINT32_MAX) {
                    invalid(addresses.label, addresses.offset + i * 4, "ordinal overflow");
                }
                Export symbol{uint32_t(ordinal), rva, {}, {}};
                if (Alias != aliases.end()) {
                    symbol.names = std::move(Alias->second);
                }
                if (rva >= base && rva - base < dir->bytes.size()) {
                    symbol.forwarder =
                        name(dir->slice(rva - base, dir->bytes.size() - (rva - base)));
                }
                module.exports.push_back(std::move(symbol));
            }
        }

        void Image::relocations(Module &module) {
            auto dir = directory(COFF::BASE_RELOCATION_TABLE, "base relocations");
            if (!dir) {
                return;
            }
            for (size_t pos = 0; pos < dir->bytes.size();) {
                auto h = dir->read<coff_base_reloc_block_header>(pos);
                if (h.BlockSize < sizeof(h) || h.BlockSize % 2) {
                    invalid(dir->label, dir->offset + pos, "invalid relocation block size");
                }
                if (h.PageRVA % 4096 || pos % 4) {
                    invalid(dir->label, dir->offset + pos, "misaligned relocation page or block");
                }
                auto block = dir->slice(pos, h.BlockSize);
                RelocationBlock result{h.PageRVA, h.BlockSize, {}};
                count(1 + (h.BlockSize - sizeof(h)) / 2, block);
                for (size_t i = sizeof(h); i < h.BlockSize; i += 2) {
                    auto e = block.read<coff_base_reloc_block_entry>(i);
                    uint64_t target = uint64_t(h.PageRVA) + static_cast<unsigned>(e.getOffset());
                    if (target > UINT32_MAX || (e.getType() != COFF::IMAGE_REL_BASED_ABSOLUTE &&
                                                target >= header.SizeOfImage)) {
                        invalid(block.label, block.offset + i, "relocation target outside image");
                    }
                    result.entries.push_back({unsigned(e.getType()), uint32_t(target), {}});
                    if (e.getType() == COFF::IMAGE_REL_BASED_HIGHADJ) {
                        i += 2;
                        result.entries.back().adjustment = block.read<little16_t>(i);
                    }
                }
                module.relocations.push_back(std::move(result));
                pos += h.BlockSize;
            }
        }

        void Image::tls(Module &module) {
            auto dir = directory(COFF::TLS_TABLE, "TLS directory");
            if (!dir) {
                return;
            }
            auto t = dir->read<coff_tls_directory64>();
            TLS result{object->getDataDirectory(COFF::TLS_TABLE)->RelativeVirtualAddress,
                       uint64_t(t.StartAddressOfRawData),
                       uint64_t(t.EndAddressOfRawData),
                       uint64_t(t.AddressOfIndex),
                       uint64_t(t.AddressOfCallBacks),
                       t.SizeOfZeroFill,
                       t.Characteristics,
                       {}};
            if (result.end < result.start) {
                invalid(dir->label,
                        dir->offset + offsetof(coff_tls_directory64, EndAddressOfRawData),
                        "TLS template end VA precedes start VA");
            }
            if (result.callbacks) {
                if (result.callbacks < module.imageBase) {
                    invalid(dir->label, dir->offset, "callback table VA below image base");
                }
                View callbacks = tail(result.callbacks - module.imageBase, "TLS callback table");
                for (size_t i = 0;; i += 8) {
                    uint64_t va = callbacks.read<ulittle64_t>(i);
                    if (!va) {
                        break;
                    }
                    count(1, callbacks);
                    result.callbackVas.push_back(va);
                }
            }
            module.tls = std::move(result);
        }

        void Image::exceptions(Module &module, bool recover) {
            auto dir = directory(COFF::EXCEPTION_TABLE, "exception directory");
            if (!dir) {
                return;
            }
            using Entry = Win64EH::RuntimeFunction;
            if (!recover && dir->bytes.size() % sizeof(Entry)) {
                invalid(dir->label, dir->offset, "partial AMD64 runtime function");
            }
            Exceptions result{
                object->getDataDirectory(COFF::EXCEPTION_TABLE)->RelativeVirtualAddress,
                uint32_t(dir->bytes.size()),
                {}};
            count(dir->bytes.size() / sizeof(Entry), *dir);
            for (size_t i = 0; i + sizeof(Entry) <= dir->bytes.size(); i += sizeof(Entry)) {
                auto e = dir->read<Entry>(i);
                if (!recover &&
                    (e.StartAddress >= e.EndAddress || e.EndAddress > header.SizeOfImage ||
                     e.UnwindInfoOffset >= header.SizeOfImage)) {
                    invalid(dir->label, dir->offset + i,
                            "runtime function range or unwind RVA outside image");
                }
                result.functions.push_back({e.StartAddress, e.EndAddress, e.UnwindInfoOffset});
            }
            module.exceptions = std::move(result);
        }

        Module Image::inspect(bool analysis) {
            Module module{};
            module.dll = object->getCharacteristics() & COFF::IMAGE_FILE_DLL;
            module.imageBase = object->getImageBase();
            module.entryPoint = header.AddressOfEntryPoint;
            size_t index = 0;
            for (const auto &section : object->sections()) {
                auto n = section.getName();
                if (!n) {
                    throw InspectionError("section name: " + toString(n.takeError()));
                }
                if (n->size() > remainingNameBytes) {
                    throw InspectionError("section name budget exceeded");
                }
                remainingNameBytes -= n->size();
                if (!json::isUTF8(*n)) {
                    throw InspectionError("invalid UTF-8 section name");
                }
                sections[index++].name = n->str();
            }
            if (!analysis) {
                imports(module, false);
                imports(module, true);
                exports(module);
            }
            relocations(module);
            tls(module);
            exceptions(module, analysis);
            module.sections = std::move(sections);
            return module;
        }
    } // namespace

    Module inspectPE(llvm::MemoryBufferRef buffer) { return Image(buffer).inspect(); }

    Analysis analyzePE(llvm::MemoryBufferRef buffer, bool debugInfo) {
        Image image(buffer);
        auto result = discover(image.inspect(true), buffer.getBuffer());
        if (debugInfo) {
            enrichFunctions(result, image.coff());
        }
        return result;
    }
} // namespace forge
