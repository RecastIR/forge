#pragma once

#include "pe/forge.h"

namespace llvm::object {
class ObjectFile;
}
namespace forge {
struct FunctionRange {
    RuntimeFunction record;
    std::vector<size_t> indices;
    bool entry = false, callback = false, invalid = false;
    bool chainedFragment = false;
    std::optional<unsigned> unsupportedUnwindVersion;
    std::optional<size_t> overlapGroup;
    std::string name, file;
    unsigned line = 0;
    bool covered() const { return !invalid && !overlapGroup && !unsupportedUnwindVersion; }
    bool eligible() const { return covered() && !chainedFragment; }
};
struct Finding {
    std::string code, message;
    std::vector<size_t> records;
};
struct Analysis {
    Module module;
    std::vector<FunctionRange> functions;
    std::vector<std::pair<uint32_t, uint32_t>> unknown;
    std::vector<Finding> findings;
};
Analysis discover(Module module, llvm::StringRef file);
void enrichFunctions(Analysis &analysis, const llvm::object::ObjectFile &object);
Analysis analyzePE(llvm::MemoryBufferRef buffer, bool debugInfo);
void printAnalysis(const Analysis &, bool json, llvm::raw_ostream &out);
void lift(const Analysis &, llvm::MemoryBufferRef buffer, uint32_t rva, bool wrapper,
          const fs::path &output);
} // namespace forge
