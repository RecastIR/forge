#include "image.h"

#include "diagnostic.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Win64EH.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <map>
#include <type_traits>

namespace forge {
    namespace {
        using namespace llvm;
        using namespace llvm::object;
        using namespace llvm::support;

        std::optional<MappedRange> mapFileRange(llvm::ArrayRef<Section> sections,
                                                llvm::StringRef file, uint64_t rva,
                                                std::optional<uint32_t> size = std::nullopt) {
            for (const auto &s : sections) {
                if (rva < s.rva) {
                    continue;
                }

                const uint64_t delta = rva - s.rva;
                const uint32_t extent = s.initializedSize();

                if (delta >= extent) {
                    continue;
                }

                const uint32_t available = extent - static_cast<uint32_t>(delta);
                const uint32_t length = size.value_or(available);
                const uint64_t offset = uint64_t(s.fileOffset) + delta;

                if (length > available || offset > file.size() || length > file.size() - offset) {
                    return std::nullopt;
                }

                return MappedRange{s, file.substr(offset, length), offset};
            }

            return std::nullopt;
        }

        [[noreturn]] void invalid(StringRef field, uint64_t offset, StringRef reason) {
            InspectionError error(field.str() + " at file offset " + hex(offset) + ": " +
                                  reason.str());
            error.context.fileOffset = offset;
            throw error;
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

        const Section *virtualSection(ArrayRef<Section> sections, uint64_t rva) {
            for (const auto &section : sections) {
                if (rva >= section.rva && rva - section.rva < section.virtualSize) {
                    return &section;
                }
            }

            return nullptr;
        }

        // Borrow the initialized prefix once. A thunk can straddle the boundary
        // into the virtual zero tail, but must fit entirely in this section.
        struct ImportThunks {
            View raw;
            uint64_t extent;
            uint64_t rva;

            import_lookup_table_entry64 read(size_t pos) const {
                import_lookup_table_entry64 entry{};
                if (pos > extent || sizeof(entry) > extent - pos) {
                    throw InspectionError(raw.label.str() + " at RVA " + hex(rva + pos) +
                                          ": entry exceeds virtual section");
                }

                auto bytes = raw.bytes.substr(pos, sizeof(entry));
                if (!bytes.empty()) {
                    std::memcpy(&entry, bytes.data(), bytes.size());
                }

                return entry;
            }
        };

        ImportThunks importThunks(ArrayRef<Section> sections, StringRef file, uint32_t rva,
                                  StringRef label) {
            const auto *section = virtualSection(sections, rva);
            if (!section) {
                throw InspectionError(label.str() + " RVA " + hex(rva) + " outside sections");
            }

            const auto delta = rva - section->rva;
            const auto rawStart = std::min(delta, section->initializedSize());
            const uint64_t offset = uint64_t(section->fileOffset) + rawStart;
            return {{file.substr(offset, section->initializedSize() - rawStart), offset, label},
                    section->virtualSize - delta,
                    rva};
        }

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
        class ImageParser {
          public:
            explicit ImageParser(MemoryBufferRef buffer);
            Module inspect(ParsePolicy policy);

            std::unique_ptr<COFFObjectFile> takeObject() && { return std::move(object); }

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
            void exports(Module &module);
            void relocations(Module &module);
            void tls(Module &module);
            void exceptions(Module &module, ParsePolicy policy);
        };

        View mappedTail(ArrayRef<Section> sections, StringRef file, uint64_t rva, StringRef label) {
            if (auto mapped = mapFileRange(sections, file, rva)) {
                return {mapped->bytes, mapped->fileOffset, label};
            }
            throw InspectionError(label.str() + " RVA " + hex(rva) +
                                  " is outside file-backed sections");
        }

        View ImageParser::tail(uint64_t rva, StringRef label) const {
            return mappedTail(sections, file.bytes, rva, label);
        }

        ImageParser::ImageParser(MemoryBufferRef buffer)
            : file{buffer.getBuffer(), 0, "PE headers"} {
            auto dos = file.read<dos_header>();
            if (StringRef(dos.Magic, 2) != "MZ") {
                invalid(file.label, 0, "expected an MZ executable");
            }
            uint64_t pe = dos.AddressOfNewExeHeader;
            if (file.slice(pe, 4).bytes != StringRef("PE\0\0", 4)) {
                invalid(file.label, pe, "expected PE signature");
            }

            const auto coffHeader = file.read<coff_file_header>(pe + 4);
            if (coffHeader.Machine != COFF::IMAGE_FILE_MACHINE_AMD64) {
                auto arch = machineName(coffHeader.Machine);
                InspectionError error("expected AMD64, found " + arch + " at file offset " +
                                          hex(pe + 4),
                                      FailureCode::UnsupportedArchitecture, arch);
                error.context.fileOffset = pe + 4;
                throw error;
            }
            if (!(coffHeader.Characteristics & COFF::IMAGE_FILE_EXECUTABLE_IMAGE)) {
                invalid(file.label, pe, "expected an executable image");
            }
            uint64_t opt = pe + 4 + sizeof(coffHeader);
            View optional = file.slice(opt, coffHeader.SizeOfOptionalHeader);
            if (optional.read<ulittle16_t>() != COFF::PE32Header::PE32_PLUS) {
                invalid(file.label, opt, "expected PE32+ optional header");
            }
            header = optional.read<pe32plus_header>();
            optional.slice(sizeof(header),
                           uint64_t(header.NumberOfRvaAndSize) * sizeof(data_directory));
            if (header.SizeOfImage &&
                header.ImageBase > UINT64_MAX - (uint64_t(header.SizeOfImage) - 1)) {
                invalid(file.label, opt, "preferred image virtual addresses overflow");
            }

            if (header.AddressOfEntryPoint && header.AddressOfEntryPoint >= header.SizeOfImage) {
                invalid(file.label, opt, "entry point RVA exceeds SizeOfImage");
            }
            if (!coffHeader.NumberOfSections || coffHeader.NumberOfSections > 96) {
                invalid(file.label, pe, "expected 1 to 96 PE sections");
            }
            uint64_t table = opt + coffHeader.SizeOfOptionalHeader;
            auto sectionHeaders =
                file.slice(table, uint64_t(coffHeader.NumberOfSections) * sizeof(coff_section));
            if (table + sectionHeaders.bytes.size() > header.SizeOfHeaders ||
                header.SizeOfHeaders > file.bytes.size()) {
                invalid(file.label, opt, "invalid SizeOfHeaders");
            }
            for (unsigned i = 0; i < coffHeader.NumberOfSections; ++i) {
                auto s = sectionHeaders.read<coff_section>(i * sizeof(coff_section));
                if (s.SizeOfRawData &&
                    (s.PointerToRawData < header.SizeOfHeaders ||
                     uint64_t(s.PointerToRawData) + s.SizeOfRawData > file.bytes.size())) {
                    invalid("section raw data", table + i * sizeof(s),
                            "missing or truncated file range");
                }
                if (s.VirtualSize && s.VirtualAddress < header.SizeOfHeaders) {
                    invalid("section virtual range", table + i * sizeof(s),
                            "overlaps image headers");
                }

                if (uint64_t(s.VirtualAddress) + s.VirtualSize > header.SizeOfImage) {
                    invalid("section virtual range", table + i * sizeof(s), "exceeds SizeOfImage");
                }
                for (const auto &previous : sections) {
                    if (s.SizeOfRawData && previous.rawSize &&
                        s.PointerToRawData < uint64_t(previous.fileOffset) + previous.rawSize &&
                        previous.fileOffset < uint64_t(s.PointerToRawData) + s.SizeOfRawData) {
                        invalid("section raw data", table + i * sizeof(s),
                                "overlaps another section");
                    }

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
                                    s.SizeOfRawData,
                                    (s.Characteristics & COFF::IMAGE_SCN_MEM_DISCARDABLE) != 0});
            }
            if (coffHeader.NumberOfSymbols && !coffHeader.PointerToSymbolTable) {
                invalid("COFF symbol table", pe + 4, "missing file offset");
            }
            if (coffHeader.PointerToSymbolTable) {
                uint64_t strings = uint64_t(coffHeader.PointerToSymbolTable) +
                                   uint64_t(coffHeader.NumberOfSymbols) * sizeof(coff_symbol16);
                if (strings > UINT32_MAX) {
                    invalid("COFF symbol table", coffHeader.PointerToSymbolTable,
                            "file offset overflow");
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
                    constexpr size_t chpe =
                        offsetof(coff_load_configuration64, CHPEMetadataPointer);
                    if (size >= chpe + 8 && config.read<ulittle64_t>(chpe)) {
                        InspectionError error("hybrid ARM64EC image; expected AMD64",
                                              FailureCode::UnsupportedArchitecture, "arm64ec");
                        error.context.fileOffset = config.offset + chpe;
                        throw error;
                    }
                }
            }
            auto parsed = COFFObjectFile::create(buffer);
            if (!parsed) {
                throw InspectionError("PE/COFF headers: " + toString(parsed.takeError()));
            }
            object = std::move(*parsed);
        }

        std::optional<View> ImageParser::directory(unsigned index, StringRef label) const {
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

        void ImageParser::count(size_t records, const View &where) {
            if (records > remainingRecords) {
                invalid(where.label, where.offset, "inspection record limit exceeded");
            }
            remainingRecords -= records;
        }

        std::string readName(View data, size_t &remainingNameBytes) {
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

        struct ImportDescriptor {
            uint32_t name, lookup, addressTable, handle;
            bool bound;
        };

        std::optional<ImportDescriptor> readImportDescriptor(const View &dir, size_t &pos,
                                                             bool delayed) {
            if (delayed) {
                const auto d = dir.read<delay_import_directory_table_entry>(pos);
                if (dir.bytes.substr(pos, sizeof(d)).find_first_not_of('\0') == StringRef::npos) {
                    return {};
                }

                if (d.Attributes != 1) {
                    invalid(dir.label, dir.offset + pos,
                            "unsupported delay descriptor attributes (expected RVA-based form)");
                }

                pos += sizeof(d);
                return ImportDescriptor{d.Name, d.DelayImportNameTable, d.DelayImportAddressTable,
                                        d.ModuleHandle, false};
            }

            const auto d = dir.read<coff_import_directory_table_entry>(pos);
            if (d.isNull()) {
                return {};
            }

            pos += sizeof(d);
            return ImportDescriptor{d.NameRVA, d.ImportLookupTableRVA, d.ImportAddressTableRVA, 0,
                                    d.TimeDateStamp != 0};
        }

        std::string ImageParser::name(View data) { return readName(data, remainingNameBytes); }

        struct ImportReader {
            ArrayRef<Section> sections;
            StringRef file;
            size_t &recordBudget, &nameBudget;
            std::vector<Import> *imports;
            std::vector<RvaRange> *writes;

            void consume(const View &source, size_t pos) {
                if (!recordBudget) {
                    invalid(source.label, source.offset + pos, "import record limit exceeded");
                }

                --recordBudget;
            }

            Symbol symbol(const ImportThunks &table, size_t pos,
                          import_lookup_table_entry64 entry) {
                const auto value = static_cast<uint64_t>(entry.Data);
                if (entry.isOrdinal()) {
                    if (value & UINT64_C(0x7fffffffffff0000)) {
                        invalid(table.raw.label, table.raw.offset + pos,
                                "reserved ordinal bits are set");
                    }
                    return {{}, entry.getOrdinal()};
                }

                if (value > INT32_MAX) {
                    invalid(table.raw.label, table.raw.offset + pos, "expected a hint/name RVA");
                }

                View hintName = mappedTail(sections, file, value, "import hint/name");
                hintName.read<ulittle16_t>();
                return {readName(hintName.slice(2, hintName.bytes.size() - 2), nameBudget),
                        std::nullopt, static_cast<uint32_t>(value)};
            }

            void read(const COFFObjectFile &coff, bool delayed);
            void readTable(const ImportDescriptor &d, Import *record, bool delayed);
        };

        void ImportReader::readTable(const ImportDescriptor &d, Import *record, bool delayed) {
            const auto lookup = d.lookup ? d.lookup : d.addressTable;
            auto table = importThunks(sections, file, lookup, "import lookup table");
            auto slots = importThunks(sections, file, d.addressTable, "import address table");
            size_t pos = 0;
            for (;; pos += importSlotWidth) {
                const auto entry = table.read(pos);
                const auto slot = static_cast<uint64_t>(slots.read(pos).Data);
                const auto value = static_cast<uint64_t>(entry.Data);
                if (record &&
                    (((value == 0) != (slot == 0)) || (!delayed && !d.bound && value != slot))) {
                    invalid(slots.raw.label, slots.raw.offset + pos,
                            "lookup and address table disagree at corresponding index");
                }

                if (!entry.Data) {
                    break;
                }

                consume(table.raw, pos);
                if (record) {
                    // A bound address has no name or ordinal when OriginalFirstThunk is absent.
                    record->symbols.push_back(d.bound && !d.lookup ? Symbol{}
                                                                   : symbol(table, pos, entry));
                }
            }

            if (writes && pos) {
                writes->push_back({d.addressTable, uint64_t(d.addressTable) + pos});
            }

            if (writes && d.handle) {
                writes->push_back({d.handle, uint64_t(d.handle) + importSlotWidth});
            }
        }

        void ImportReader::read(const COFFObjectFile &coff, bool delayed) {
            const auto *dir =
                coff.getDataDirectory(delayed ? COFF::DELAY_IMPORT_DESCRIPTOR : COFF::IMPORT_TABLE);
            if (!dir || (!dir->Size && !dir->RelativeVirtualAddress)) {
                return;
            }

            const StringRef label = delayed ? "delay imports" : "imports";
            if (!dir->Size || !dir->RelativeVirtualAddress) {
                throw InspectionError(label.str() + " has an incomplete directory entry");
            }

            auto view =
                mappedTail(sections, file, dir->RelativeVirtualAddress, label).slice(0, dir->Size);
            size_t pos = 0;
            for (;;) {
                const auto start = pos;
                const auto descriptor = readImportDescriptor(view, pos, delayed);
                if (!descriptor) {
                    return;
                }

                consume(view, start);
                const auto &d = *descriptor;
                if (!d.addressTable || (delayed && !d.lookup)) {
                    invalid(label, view.offset + start, "invalid import thunk mapping");
                }

                Import *record = nullptr;
                if (imports) {
                    auto spelling =
                        readName(mappedTail(sections, file, d.name, "import DLL name"), nameBudget);
                    record = &imports->emplace_back(
                        Import{spelling,
                               StringRef(spelling).lower(),
                               delayed,
                               d.bound,
                               static_cast<uint32_t>(dir->RelativeVirtualAddress + start),
                               d.name,
                               d.lookup,
                               d.addressTable,
                               d.handle,
                               view.offset + start,
                               {}});
                }

                readTable(d, record, delayed);
            }
        }

        void validateImportOwnership(ArrayRef<Import> descriptors) {
            std::map<uint32_t, uint64_t> spans;
            for (const auto &descriptor : descriptors) {
                const uint64_t end = descriptor.addressTableRva +
                                     (descriptor.symbols.size() + uint64_t{1}) * importSlotWidth;
                auto next = spans.lower_bound(descriptor.addressTableRva);
                if ((next != spans.end() && next->first < end) ||
                    (next != spans.begin() &&
                     std::prev(next)->second > descriptor.addressTableRva)) {
                    invalid("import descriptor", descriptor.descriptorOffset,
                            "overlapping IAT slot ownership");
                }

                spans.emplace_hint(next, descriptor.addressTableRva, end);
            }

            for (const auto &descriptor : descriptors) {
                if (!descriptor.lookupRva ||
                    (!descriptor.bound && descriptor.lookupRva == descriptor.addressTableRva)) {
                    continue;
                }

                // Binding may overwrite every IAT in the image. Independent lookup evidence
                // must survive those writes, even when another descriptor owns the address table.
                const uint64_t end = descriptor.lookupRva +
                                     (descriptor.symbols.size() + uint64_t{1}) * importSlotWidth;
                const auto start = spans.lower_bound(descriptor.lookupRva);
                if ((start != spans.end() && start->first < end) ||
                    (start != spans.begin() && std::prev(start)->second > descriptor.lookupRva)) {
                    invalid("import descriptor", descriptor.descriptorOffset,
                            "lookup table overlaps an IAT");
                }
            }
        }

        void ImageParser::exports(Module &module) {
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
                const auto alias =
                    aliases.find(static_cast<uint32_t>(i)); // AddressTableEntries is 32-bit.
                if (!rva) {
                    if (alias != aliases.end()) {
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
                if (alias != aliases.end()) {
                    symbol.names = std::move(alias->second);
                }
                if (rva >= base && rva - base < dir->bytes.size()) {
                    symbol.forwarder =
                        name(dir->slice(rva - base, dir->bytes.size() - (rva - base)));
                }
                module.exports.push_back(std::move(symbol));
            }
        }

        void ImageParser::relocations(Module &module) {
            auto dir = directory(COFF::BASE_RELOCATION_TABLE, "base relocations");
            if (!dir) {
                return;
            }

            const uint64_t directoryRva =
                object->getDataDirectory(COFF::BASE_RELOCATION_TABLE)->RelativeVirtualAddress;

            for (size_t pos = 0; pos < dir->bytes.size();) {
                auto h = dir->read<coff_base_reloc_block_header>(pos);
                if (h.BlockSize < sizeof(h) || h.BlockSize % 2) {
                    invalid(dir->label, dir->offset + pos, "invalid relocation block size");
                }
                if (h.PageRVA % 4096 || (directoryRva + pos) % 4) {
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

        void ImageParser::tls(Module &module) {
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

        void ImageParser::exceptions(Module &module, ParsePolicy policy) {
            auto dir = directory(COFF::EXCEPTION_TABLE, "exception directory");

            if (!dir) {
                return;
            }

            using Entry = Win64EH::RuntimeFunction;

            Exceptions result{
                object->getDataDirectory(COFF::EXCEPTION_TABLE)->RelativeVirtualAddress,
                uint32_t(dir->bytes.size()),
                {}};

            if (policy == ParsePolicy::Inspection && result.trailingBytes()) {
                invalid(dir->label, dir->offset, "partial AMD64 runtime function");
            }

            count(dir->bytes.size() / sizeof(Entry), *dir);

            for (size_t i = 0; i + sizeof(Entry) <= dir->bytes.size(); i += sizeof(Entry)) {
                auto e = dir->read<Entry>(i);

                if (policy == ParsePolicy::Inspection &&
                    (e.StartAddress >= e.EndAddress || e.EndAddress > header.SizeOfImage ||
                     e.UnwindInfoOffset >= header.SizeOfImage)) {
                    invalid(dir->label, dir->offset + i,
                            "runtime function range or unwind RVA outside image");
                }

                result.functions.push_back({e.StartAddress, e.EndAddress, e.UnwindInfoOffset});
            }

            module.exceptions = std::move(result);
        }

        Module ImageParser::inspect(ParsePolicy policy) {
            Module module{};
            module.machine = static_cast<COFF::MachineTypes>(object->getMachine());
            module.dll = object->getCharacteristics() & COFF::IMAGE_FILE_DLL;
            module.relocationsStripped =
                object->getCharacteristics() & COFF::IMAGE_FILE_RELOCS_STRIPPED;
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

            if (policy == ParsePolicy::Inspection) {
                ImportReader reader{sections,           file.bytes,      remainingRecords,
                                    remainingNameBytes, &module.imports, nullptr};
                reader.read(*object, false);
                reader.read(*object, true);
                validateImportOwnership(module.imports);
                exports(module);
            }

            relocations(module);
            tls(module);
            exceptions(module, policy);
            module.sections = std::move(sections);
            return module;
        }
    } // namespace

    unsigned Exceptions::trailingBytes() const {
        return size % sizeof(llvm::Win64EH::RuntimeFunction);
    }

    ParsedImage::ParsedImage(const InputFile &input, ParsePolicy policy)
        : identity(input.id()), openedPath(input.absolutePath()), buffer(input.read()) {
        try {
            ImageParser parser(buffer->getMemBufferRef());
            metadata = parser.inspect(policy);
            metadata.path = buffer->getBufferIdentifier().str();
            coff = std::move(parser).takeObject();
        } catch (InspectionError &error) {
            error.context.input = buffer->getBufferIdentifier().str();
            throw;
        }
    }

    ParsedImage::~ParsedImage() = default;

    std::optional<MappedRange> ParsedImage::mapRva(uint64_t rva,
                                                   std::optional<uint32_t> size) const {
        return mapFileRange(metadata.sections, buffer->getBuffer(), rva, size);
    }

    const Section *ParsedImage::sectionAtRva(uint64_t rva) const {
        return virtualSection(metadata.sections, rva);
    }

    llvm::StringRef ParsedImage::initializedBytes(RvaRange range) const {
        const auto *section = sectionAtRva(range.begin);

        if (!section || range.end <= range.begin ||
            range.end > uint64_t(section->rva) + section->virtualSize) {
            throw InspectionError("invalid virtual section interval at RVA " + hex(range.begin));
        }

        const auto fileEnd =
            std::min(range.end, uint64_t(section->rva) + section->initializedSize());

        if (fileEnd <= range.begin) {
            return {};
        }

        auto raw = mapRva(range.begin, static_cast<uint32_t>(fileEnd - range.begin));

        if (!raw) {
            throw InspectionError("missing initialized section bytes at RVA " + hex(range.begin));
        }

        return raw->bytes;
    }

    unsigned relocationWidth(unsigned type) {
        switch (type) {
        case llvm::COFF::IMAGE_REL_BASED_ABSOLUTE:
            return 0;
        case llvm::COFF::IMAGE_REL_BASED_HIGH:
        case llvm::COFF::IMAGE_REL_BASED_LOW:
        case llvm::COFF::IMAGE_REL_BASED_HIGHADJ:
            return 2;
        case llvm::COFF::IMAGE_REL_BASED_HIGHLOW:
            return 4;
        default:
            // DIR64 and the existing conservative footprint for unknown AMD64 types.
            return 8;
        }
    }

    namespace {
        void appendLoadConfigSlot(const ParsedImage &image, uint64_t va, StringRef name,
                                  std::vector<RvaRange> &ranges) {
            if (!va) {
                return;
            }

            const auto rva = va - image.module().imageBase;
            const auto *section = image.sectionAtRva(rva);
            if (!section ||
                rva + sizeof(uint64_t) > uint64_t(section->rva) + section->virtualSize) {
                throw InspectionError(name.str() + " outside mapped section at VA " + hex(va));
            }

            ranges.push_back({rva, rva + sizeof(uint64_t)});
        }

        std::vector<RvaRange> mergeRanges(std::vector<RvaRange> ranges) {
            llvm::sort(ranges, [](auto a, auto b) { return a.begin < b.begin; });
            std::vector<RvaRange> merged;

            for (auto range : ranges) {
                if (!merged.empty() && range.begin <= merged.back().end) {
                    merged.back().end = std::max(merged.back().end, range.end);
                } else {
                    merged.push_back(range);
                }
            }

            return merged;
        }

        std::vector<RvaRange> directoryRanges(const llvm::object::COFFObjectFile &coff) {
            std::vector<RvaRange> ranges;

            for (unsigned index = 0; index < COFF::NUM_DATA_DIRECTORIES; ++index) {
                // The certificate table's "RVA" is a file offset outside the loaded image.
                if (index == COFF::CERTIFICATE_TABLE) {
                    continue;
                }

                const auto *dir = coff.getDataDirectory(index);

                if (dir && dir->RelativeVirtualAddress && dir->Size) {
                    ranges.push_back({dir->RelativeVirtualAddress,
                                      uint64_t(dir->RelativeVirtualAddress) + dir->Size});
                }
            }

            return ranges;
        }

    } // namespace

    llvm::ArrayRef<RvaRange> rangesIn(llvm::ArrayRef<RvaRange> view, RvaRange range) {
        auto begin = llvm::lower_bound(
            view, range.begin, [](RvaRange field, uint64_t rva) { return field.end <= rva; });
        auto end = std::lower_bound(begin, view.end(), range.end,
                                    [](RvaRange field, uint64_t rva) { return field.begin < rva; });
        return {begin, end};
    }

    RelocationIndex::RelocationIndex(llvm::ArrayRef<RelocationBlock> blocks) : blocks(blocks) {
        std::vector<RvaRange> fields;
        for (const auto &block : blocks) {
            for (const auto &rel : block.entries) {
                if (auto width = relocationWidth(rel.type)) {
                    fields.push_back({rel.rva, uint64_t(rel.rva) + width});
                }
            }
        }

        ranges = mergeRanges(std::move(fields));
    }

    const Relocation *RelocationIndex::firstOverlap(RvaRange range) const {
        if (range.begin >= range.end || rangesIn(ranges, range).empty()) {
            return nullptr;
        }

        // An overlap ends the lift. Only this failing query needs an original
        // record rather than a yes/no answer from the merged interval index.
        for (const auto &block : blocks) {
            for (const auto &rel : block.entries) {
                const auto width = relocationWidth(rel.type);
                if (width && rel.rva < range.end && uint64_t(rel.rva) + width > range.begin) {
                    return &rel;
                }
            }
        }

        llvm_unreachable("relocation interval must contain an original fixup");
    }

    void ImageInitialization::validateRelocations(RvaRange range) const {
        auto malformed = rangesIn(conflicts, range);

        if (!malformed.empty()) {
            throw InspectionError("overlapping base relocations at RVA " +
                                  hex(malformed.front().begin));
        }
    }

    llvm::ArrayRef<RvaRange> ImageInitialization::exclusionsIn(RvaRange range) const {
        return rangesIn(excluded, range);
    }

    llvm::ArrayRef<const Relocation *> ImageInitialization::relocationsIn(RvaRange range) const {
        llvm::ArrayRef<const Relocation *> view(fields);
        auto begin =
            llvm::lower_bound(view, range.begin, [](const Relocation *field, uint64_t rva) {
                return uint64_t(field->rva) + relocationWidth(field->type) <= rva;
            });
        auto end = std::lower_bound(
            begin, view.end(), range.end,
            [](const Relocation *field, uint64_t rva) { return field->rva < rva; });
        return {begin, end};
    }

    bool ParsedImage::advertisesDynamicRelocations() const {
        if (coff->getDynamicRelocTable()) {
            return true;
        }

        const auto *config = coff->getLoadConfig64();

        if (!config) {
            return false;
        }

        // Older directories end before these fields. A section index with offset zero
        // names a table at the beginning of the section.
        using Config = llvm::object::coff_load_configuration64;
        return (config->Size >= offsetof(Config, DynamicValueRelocTable) +
                                    sizeof(config->DynamicValueRelocTable) &&
                config->DynamicValueRelocTable) ||
               (config->Size >= offsetof(Config, DynamicValueRelocTableOffset) +
                                    sizeof(config->DynamicValueRelocTableOffset) &&
                config->DynamicValueRelocTableOffset) ||
               (config->Size >= offsetof(Config, DynamicValueRelocTableSection) +
                                    sizeof(config->DynamicValueRelocTableSection) &&
                config->DynamicValueRelocTableSection);
    }

    std::vector<RvaRange> ParsedImage::tlsAndConfigWrites() const {
        std::vector<RvaRange> ranges;

        if (metadata.tls && metadata.tls->index >= metadata.imageBase && metadata.tls->index) {
            const auto rva = metadata.tls->index - metadata.imageBase;
            if (rva <= UINT32_MAX) {
                ranges.push_back({rva, rva + 4});
            }
        }

        // Windows writes the target slots, including slots in read-only sections.
        // Older load-config versions may end before a field.
        if (const auto *config = coff->getLoadConfig64()) {
            using Config = llvm::object::coff_load_configuration64;

            if (config->Size >= offsetof(Config, SecurityCookie) + sizeof(config->SecurityCookie)) {
                appendLoadConfigSlot(*this, config->SecurityCookie, "security cookie", ranges);
            }

            if (config->Size >=
                offsetof(Config, GuardCFCheckFunction) + sizeof(config->GuardCFCheckFunction)) {
                appendLoadConfigSlot(*this, config->GuardCFCheckFunction, "control flow guard slot",
                                     ranges);
            }

            if (config->Size >=
                offsetof(Config, GuardCFCheckDispatch) + sizeof(config->GuardCFCheckDispatch)) {
                appendLoadConfigSlot(*this, config->GuardCFCheckDispatch, "control flow guard slot",
                                     ranges);
            }
        }

        return ranges;
    }

    std::vector<RvaRange> ParsedImage::loaderWrittenRanges() const {
        auto ranges = tlsAndConfigWrites();
        const auto *iat = coff->getDataDirectory(llvm::COFF::IAT);
        if (iat && bool(iat->Size) != bool(iat->RelativeVirtualAddress)) {
            throw InspectionError("incomplete import address table directory");
        }

        if (iat && iat->Size) {
            ranges.push_back(
                {iat->RelativeVirtualAddress, uint64_t(iat->RelativeVirtualAddress) + iat->Size});
        }

        size_t records = 1'000'000, names = 0;
        ImportReader reader{
            metadata.sections, buffer->getBuffer(), records, names, nullptr, &ranges};
        reader.read(*coff, false);
        reader.read(*coff, true);

        return mergeRanges(std::move(ranges));
    }

    ImportBindings ParsedImage::importBindings() const {
        size_t records = 1'000'000, names = size_t{64} * 1024 * 1024;
        ImportBindings result;
        auto &descriptors = result.descriptors;
        ImportReader reader{
            metadata.sections, buffer->getBuffer(), records, names, &descriptors, nullptr};
        reader.read(*coff, false);
        reader.read(*coff, true);
        validateImportOwnership(descriptors);
        auto otherWrites = tlsAndConfigWrites();
        for (const auto &descriptor : descriptors) {
            if (descriptor.delayHandleRva) {
                otherWrites.push_back({descriptor.delayHandleRva,
                                       uint64_t(descriptor.delayHandleRva) + importSlotWidth});
            }
        }

        otherWrites = mergeRanges(std::move(otherWrites));
        for (const auto &descriptor : descriptors) {
            const RvaRange iat{descriptor.addressTableRva,
                               descriptor.addressTableRva +
                                   (descriptor.symbols.size() + uint64_t{1}) * importSlotWidth};
            if (!rangesIn(otherWrites, iat).empty()) {
                invalid("import descriptor", descriptor.descriptorOffset,
                        "IAT overlaps another loader-written field");
            }
        }

        llvm::sort(descriptors, [](const auto &a, const auto &b) {
            return a.addressTableRva < b.addressTableRva;
        });
        return result;
    }

    std::optional<ImportSlot> ImportBindings::at(uint32_t slotRva) const & {
        const auto after =
            llvm::upper_bound(descriptors, slotRva, [](uint32_t address, const Import &descriptor) {
                return address < descriptor.addressTableRva;
            });
        if (after == descriptors.begin()) {
            return {};
        }

        const auto &descriptor = *std::prev(after);
        const auto offset = slotRva - descriptor.addressTableRva;
        if (offset % importSlotWidth || offset / importSlotWidth >= descriptor.symbols.size()) {
            return {};
        }

        const auto lookup =
            descriptor.lookupRva ? descriptor.lookupRva : descriptor.addressTableRva;
        return ImportSlot{descriptor, descriptor.symbols[offset / importSlotWidth],
                          lookup + offset};
    }

    std::optional<uint32_t> ImportSlot::unstableIdentityRva(const RelocationIndex &relocations,
                                                            ArrayRef<RvaRange> loaderWrites) const {
        const RvaRange metadata[] = {
            {descriptor.descriptorRva,
             uint64_t(descriptor.descriptorRva) + sizeof(coff_import_directory_table_entry)},
            {descriptor.nameRva, uint64_t(descriptor.nameRva) + descriptor.name.size() + 1},
            {symbol.hintNameRva,
             uint64_t(symbol.hintNameRva) + sizeof(ulittle16_t) + symbol.name.size() + 1}};
        for (const auto range : metadata) {
            if (relocations.firstOverlap(range) || !rangesIn(loaderWrites, range).empty()) {
                return static_cast<uint32_t>(range.begin);
            }
        }

        // With an unbound shared table, the loader consumes the lookup value before replacing it.
        const RvaRange lookup{lookupEntryRva, uint64_t(lookupEntryRva) + importSlotWidth};
        const bool separate =
            descriptor.lookupRva && descriptor.lookupRva != descriptor.addressTableRva;
        if (relocations.firstOverlap(lookup) ||
            (separate && !rangesIn(loaderWrites, lookup).empty())) {
            return lookupEntryRva;
        }

        return {};
    }

    ImageInitialization ParsedImage::imageInitialization() const {
        ImageInitialization result;
        result.excluded = loaderWrittenRanges();
        std::vector<const Relocation *> ordered;

        for (const auto &block : metadata.relocations) {
            for (const auto &rel : block.entries) {
                if (rel.type != COFF::IMAGE_REL_BASED_ABSOLUTE) {
                    ordered.push_back(&rel);
                }
            }
        }

        llvm::stable_sort(ordered, [](const auto *a, const auto *b) { return a->rva < b->rva; });
        std::vector<RvaRange> unavailable;
        const auto directories = directoryRanges(*coff);
        for (const auto *rel : ordered) {
            const auto *section = sectionAtRva(rel->rva);
            RvaRange field{rel->rva, uint64_t(rel->rva) + relocationWidth(rel->type)};

            if (!section || field.end > uint64_t(section->rva) + section->virtualSize) {
                throw InspectionError("relocation target outside a single mapped section at RVA " +
                                      hex(rel->rva));
            }

            // Only a mapping that selects conflicting fixups depends on how their bytes
            // would have been patched. Keep the entire cluster out of the regular field index.
            if (!result.conflicts.empty() && field.begin < result.conflicts.back().end) {
                result.conflicts.back().end = std::max(field.end, result.conflicts.back().end);
                continue;
            }

            if (!result.fields.empty()) {
                const auto *previous = result.fields.back();
                const uint64_t end = uint64_t(previous->rva) + relocationWidth(previous->type);

                if (field.begin < end) {
                    result.conflicts.push_back({previous->rva, std::max(end, field.end)});
                    result.fields.pop_back();
                    continue;
                }
            }

            result.fields.push_back(rel);

            // Directory metadata remains in its original PE representation. Exclude only the
            // fixup, so neighboring ordinary bytes stay available through the same resolver.
            const bool isMetadata = llvm::any_of(directories, [field](RvaRange dir) {
                return dir.begin < field.end && field.begin < dir.end;
            });

            if (rel->type != COFF::IMAGE_REL_BASED_DIR64 || section->permissions[2] == 'x' ||
                isMetadata || !result.exclusionsIn(field).empty()) {
                unavailable.push_back(field);
            }
        }

        unavailable.insert(unavailable.end(), result.excluded.begin(), result.excluded.end());
        unavailable.insert(unavailable.end(), result.conflicts.begin(), result.conflicts.end());
        result.excluded = mergeRanges(std::move(unavailable));
        return result;
    }

    ImageBytes ParsedImage::imageBytes(RvaRange range, const ImageInitialization &init,
                                       uint64_t guestLoadBase) const {
        // The backing can extend beyond the access that selected it. Conflicting fields
        // have no fixup in the index and their bytes are excluded from the resolver.
        ImageBytes result{initializedBytes(range).str(), {}};
        const uint64_t delta = guestLoadBase - metadata.imageBase;

        if (delta == 0) {
            return result;
        }

        const uint64_t rawEnd = range.begin + result.prefix.size();

        for (const auto *rel : init.relocationsIn(range)) {
            RvaRange field{rel->rva, uint64_t(rel->rva) + relocationWidth(rel->type)};

            if (!init.exclusionsIn(field).empty()) {
                continue;
            }

            // Decode the complete field even when a fixed image read selects only part of it.
            // Its last bytes may be loader-provided zeros beyond the PE raw extent.
            char bytes[sizeof(uint64_t)]{};
            const auto raw = initializedBytes(field);
            std::copy(raw.begin(), raw.end(), bytes);
            const uint64_t relocated = llvm::support::endian::read64le(bytes) + delta;
            llvm::support::endian::write64le(bytes, relocated);

            const auto begin = std::max(field.begin, range.begin);
            const auto end = std::min(field.end, range.end);
            const auto prefixEnd = std::min(end, rawEnd);

            if (begin < prefixEnd) {
                std::copy_n(bytes + (begin - field.begin), prefixEnd - begin,
                            result.prefix.data() + (begin - range.begin));
            }

            const auto tailBegin = std::max(begin, rawEnd);

            if (tailBegin < end) {
                llvm::StringRef tail(bytes + (tailBegin - field.begin), end - tailBegin);

                if (llvm::any_of(tail, [](char byte) { return byte != 0; })) {
                    result.tail.push_back({tailBegin - range.begin, tail.str()});
                }
            }
        }

        return result;
    }

    const llvm::object::ObjectFile &ParsedImage::object() const { return *coff; }

    Module inspectPE(const InputFile &input) {
        return ParsedImage(input, ParsePolicy::Inspection).metadata;
    }
} // namespace forge
