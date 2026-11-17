#pragma once

#include "lift/cfg.h"
#include "pe/image.h"

#include "llvm/ADT/SmallVector.h"

#include <map>
#include <set>
#include <tuple>

namespace llvm {
    class Function;
    class IRBuilderBase;
    class Module;
} // namespace llvm

namespace forge::x86 {
    struct Continuation;
    struct ResolvedCallSite;

    struct EmittedImage {
        llvm::Function *resolver;
        llvm::Function *descriptorAccessor;
    };

    // Each selected backing owns its relocated initialized bytes and accessible intervals.
    // A plan can emit into independent modules after releasing the recovered steps and image.
    class ImagePlan {
      public:
        uint64_t guestBase() const { return loadBase; }

        EmittedImage emit(llvm::Module &module, llvm::IRBuilderBase &entryIR, bool checked) const;

      private:
        friend class ImageMemory;

        struct Backing {
            RvaRange range;
            bool writable;
            bool executable;
            ImageBytes bytes;
            llvm::SmallVector<RvaRange, 1> intervals;
        };

        uint64_t loadBase = 0;
        uint32_t sizeOfImage = 0;
        std::vector<Backing> backings;
    };

    // Selection borrows the group's steps for diagnostics and the image for section and
    // relocation data. Finishing resolves the borrows into an independently owned plan.
    class ImageMemory {
      public:
        ImageMemory(const ParsedImage &image, uint64_t guestLoadBase);

        void checkStackMapping(const Step &step) const;
        void addressTaken(const Step &step, uint64_t va);
        void fixedAccess(const Step &step, uint64_t va, unsigned width, bool write);
        void tableRead(const Step &step, const RelativeTable &table);
        void computedAccess(const Step &step, std::optional<uint64_t> va, unsigned width,
                            bool write);
        void continuationAccess(const Step &step, const Continuation &origin,
                                llvm::ArrayRef<const ResolvedCallSite *> sites, unsigned width,
                                bool write);
        ImagePlan finish() &&;

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
        std::vector<Span> direct;
        std::map<uint32_t, Span> executable;
        std::set<std::tuple<uint32_t, uint64_t, unsigned, bool>> continuationAccesses;
        std::optional<ImageInitialization> initialization;

        enum class ExecutableSelection : uint8_t { AddressTakenSection, ContinuationBytes };

        const ImageInitialization &contents();
        void fixedImageAccess(const Step &step, RvaRange access, bool write);
        void selectComputed(const Step &step, uint64_t va, unsigned width, bool write,
                            ExecutableSelection executableSelection);
        void select(const Step &step, const Section &section, RvaRange access);
        static void addExecutableSpan(std::vector<Span> &spans, const Span &span);
        void addIndirectSpans(std::vector<Span> &spans) const;
        std::vector<Span> selectedSpans();
    };
} // namespace forge::x86
