#pragma once

#include "lift/cfg.h"
#include "pe/image.h"

namespace llvm {
    class Function;
    class Module;
} // namespace llvm

namespace forge::x86 {
    // All borrows end with translation. Only immutable LLVM constants survive in the module.
    class ImageMemory {
      public:
        explicit ImageMemory(const ParsedImage &image);

        void addressTaken(const Step &step, uint64_t va);
        void access(const Step &step, std::optional<uint64_t> va, unsigned width, bool write);
        llvm::Function *emitResolver(llvm::Module &module);

      private:
        struct Span {
            const Section *section;
            RvaRange range;
            const Step *origin;
        };

        const ParsedImage &source;
        const Step *indirectRead = nullptr;
        bool overlapsStack;
        std::vector<Span> direct, executable;
        std::optional<std::vector<RvaRange>> excluded;

        const std::vector<RvaRange> &exclusions();
        void addIndirectSpans(std::vector<Span> &spans) const;
        std::vector<Span> selectedSpans();
    };
} // namespace forge::x86
