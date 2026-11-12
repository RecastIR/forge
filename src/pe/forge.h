#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/MemoryBufferRef.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace forge {
namespace fs = std::filesystem;

inline std::string hex(uint64_t n) { return "0x" + llvm::utohexstr(n, true); }

struct InspectionError : std::runtime_error {
    std::string code, architecture;
    explicit InspectionError(std::string message, std::string code = "INVALID_PE",
                             std::string architecture = {})
        : runtime_error(message), code(std::move(code)), architecture(std::move(architecture)) {}
};

struct Section {
    std::string name, permissions;
    uint32_t rva, virtualSize, fileOffset, rawSize;
};
struct MappedRange {
    const Section& section;
    llvm::StringRef bytes;
    uint64_t fileOffset;
};
// The section and bytes borrow from the supplied image. Omitting size maps to
// the end of the file-backed part of the section.
std::optional<MappedRange> mapRva(llvm::ArrayRef<Section> sections, llvm::StringRef file,
                                  uint64_t rva, std::optional<uint32_t> size = std::nullopt);
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

struct ModuleLocation {
    size_t module;
    fs::path path; // First canonical alias encountered in this directory.
};

struct Dependency {
    size_t importerLocation, importIndex;
    bool required = false;
    std::string kind, status;
    std::optional<size_t> targetLocation;
    fs::path path, searchDirectory;
    std::vector<fs::path> searched, candidates;
    std::string code, message, architecture;
};
struct Report {
    std::vector<Module> modules; // Root first, then deterministic discovery order.
    std::vector<ModuleLocation> locations;
    std::vector<Dependency> dependencies;
    bool strictFailure = false;
};

Module inspectPE(llvm::MemoryBufferRef buffer);
Report inspect(const fs::path& root, const std::vector<fs::path>& searchPaths);
void printReport(const Report& report, bool json, bool verbose, llvm::raw_ostream& out);
void printDiagnostics(const Report& report, llvm::raw_ostream& err);
} // namespace forge
