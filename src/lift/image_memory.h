#pragma once

#include "lift/cfg.h"
#include "pe/image.h"

namespace llvm {
    class Function;
    class IRBuilderBase;
    class Module;
} // namespace llvm

namespace forge::x86 {
    // Section plans and parsed relocation records borrow the image during translation.
    // The LLVM module owns the shared section storage and its initialization independently.
    class ImageMemory {
      public:
        ImageMemory(const ParsedImage &image, uint64_t guestLoadBase);

        uint64_t guestBase() const { return loadBase; }

        void checkStackMapping(const Step &step) const;
        void addressTaken(const Step &step, uint64_t va);
        void access(const Step &step, std::optional<uint64_t> va, unsigned width, bool write);
        llvm::Function *emitResolver(llvm::Module &module, llvm::IRBuilderBase &entryIR);

      private:
        struct Span {
            const Section *section;
            RvaRange range;
            const Step *origin;
        };

        const ParsedImage &source;
        uint64_t loadBase;
        const Step *indirectRead = nullptr;
        const Step *indirectWrite = nullptr;
        bool overlapsStack;
        std::vector<Span> direct, executable;
        std::optional<ImageInitialization> initialization;

        const ImageInitialization &contents();
        void addIndirectSpans(std::vector<Span> &spans) const;
        std::vector<Span> selectedSpans();
    };
} // namespace forge::x86
