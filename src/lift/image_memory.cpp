#include "lift/image_memory.h"

#include "lift/memory.h"

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        constexpr uint64_t executableLimit = 8ULL * 1024 * 1024;
        constexpr uint64_t moduleLimit = 32ULL * 1024 * 1024;

        // A packed raw prefix and aggregate-zero tail are contiguous even for an
        // unaligned load straddling their boundary. Never expand the tail in the parser.
        GlobalVariable *embed(llvm::Module &module, const ParsedImage &image, RvaRange range) {
            auto &context = module.getContext();
            const auto length = range.end - range.begin;
            SmallVector<Constant *, 2> parts;
            const auto initialized = image.initializedBytes(range);

            if (!initialized.empty()) {
                parts.push_back(ConstantDataArray::getString(context, initialized, false));
            }

            if (initialized.size() < length) {
                auto *tail = ArrayType::get(Type::getInt8Ty(context), length - initialized.size());
                parts.push_back(ConstantAggregateZero::get(tail));
            }

            auto *data = parts.size() == 1 ? parts.front() : ConstantStruct::getAnon(parts, true);
            auto *global =
                new GlobalVariable(module, data->getType(), true, GlobalValue::PrivateLinkage, data,
                                   "image_" + utohexstr(range.begin, true));
            global->setAlignment(Align(1));
            return global;
        }

        // Each table entry describes one readable interval inside one backing global.
        // Relocation and loader-written fields separate intervals even within the same section.
        Function *resolver(llvm::Module &module, ArrayRef<Constant *> rows) {
            IRBuilder<> ir(module.getContext());
            auto *type =
                FunctionType::get(ir.getPtrTy(), {ir.getInt64Ty(), ir.getInt64Ty()}, false);
            auto *function =
                Function::Create(type, GlobalValue::InternalLinkage, "forge_image_address", module);
            auto *entry = BasicBlock::Create(module.getContext(), "entry", function);
            auto *loop = BasicBlock::Create(module.getContext(), "range", function);
            auto *found = BasicBlock::Create(module.getContext(), "mapped", function);
            auto *advance = BasicBlock::Create(module.getContext(), "advance", function);
            auto *fault = BasicBlock::Create(module.getContext(), "fault", function);
            auto *row = cast<StructType>(rows.front()->getType());
            auto *tableType = ArrayType::get(row, rows.size());
            auto *table = new GlobalVariable(module, tableType, true, GlobalValue::PrivateLinkage,
                                             ConstantArray::get(tableType, rows), "image.ranges");

            ir.SetInsertPoint(entry);
            ir.CreateBr(loop);

            ir.SetInsertPoint(loop);
            auto *index = ir.CreatePHI(ir.getInt64Ty(), 2);
            index->addIncoming(ir.getInt64(0), entry);
            auto *record = ir.CreateInBoundsGEP(row, table, index);
            auto *base = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 0));
            auto *size = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 1));
            auto *width = function->getArg(1);
            auto *offset = ir.CreateSub(function->getArg(0), base);
            auto *fits = ir.CreateICmpULE(offset, ir.CreateSub(size, width));
            ir.CreateCondBr(ir.CreateAnd(ir.CreateICmpUGE(size, width), fits), found, advance);

            ir.SetInsertPoint(found);
            auto *bytes = ir.CreateLoad(ir.getPtrTy(), ir.CreateStructGEP(row, record, 2));
            ir.CreateRet(ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset));

            ir.SetInsertPoint(advance);
            auto *next = ir.CreateAdd(index, ir.getInt64(1));
            index->addIncoming(next, advance);
            ir.CreateCondBr(ir.CreateICmpULT(next, ir.getInt64(rows.size())), loop, fault);

            ir.SetInsertPoint(fault);
            ir.CreateIntrinsic(Intrinsic::trap, {});
            ir.CreateUnreachable();
            return function;
        }
    } // namespace

    ImageMemory::ImageMemory(const ParsedImage &image) : source(image) {
        const uint64_t base = image.module().imageBase;
        overlapsStack = llvm::any_of(image.module().sections, [base](const Section &section) {
            const uint64_t start = base + section.rva;
            return section.virtualSize && start < GuestMemory::base + GuestMemory::capacity &&
                   start + (section.virtualSize - 1) >= GuestMemory::base;
        });
    }

    const std::vector<RvaRange> &ImageMemory::exclusions() {
        if (!excluded) {
            excluded = source.imageReadExclusions();
        }

        return *excluded;
    }

    void ImageMemory::addressTaken(const Step &step, uint64_t va) {
        const auto *section = source.sectionAtRva(va - source.module().imageBase);

        if (section && section->immutable() && section->permissions[2] == 'x') {
            executable.push_back(
                {section, {section->rva, uint64_t(section->rva) + section->virtualSize}, &step});
        }
    }

    void ImageMemory::access(const Step &step, std::optional<uint64_t> va, unsigned width,
                             bool write) {
        const auto base = source.module().imageBase;

        if (overlapsStack) {
            step.reject(FailureCode::ImageMemory, "PE image overlaps the guest stack");
        }

        if (!va) {
            if (!write && !indirectRead) {
                indirectRead = &step;
            }

            return;
        }

        const unsigned bytes = width / 8;

        if (*va - GuestMemory::base < GuestMemory::capacity) {
            if (*va - GuestMemory::base > GuestMemory::capacity - bytes ||
                (*va < GuestMemory::entryRsp + 8 && *va + bytes > GuestMemory::entryRsp)) {
                step.reject(FailureCode::ImageMemory,
                            "fixed access crosses guest stack boundary or return slot");
            }

            return;
        }

        const auto rva = *va - base;
        const auto *section = source.sectionAtRva(rva);

        if (!section || !section->immutable() ||
            rva + bytes > uint64_t(section->rva) + section->virtualSize) {
            step.reject(FailureCode::ImageMemory,
                        "unmapped or unsupported image access at VA " + hex(*va));
        }

        if (write) {
            step.reject(FailureCode::ImageMemory, "write to immutable image at VA " + hex(*va));
        }

        const auto &holes = exclusions();
        auto it = llvm::lower_bound(
            holes, rva, [](RvaRange range, uint64_t start) { return range.end <= start; });
        if (it != holes.end() && it->begin < rva + bytes) {
            step.reject(FailureCode::ImageMemory,
                        "image read overlaps relocation or loader-written field at RVA " +
                            hex(it->begin));
        }

        direct.push_back({section, {rva, rva + bytes}, &step});
    }

    void ImageMemory::addIndirectSpans(std::vector<Span> &spans) const {
        for (const auto &span : executable) {
            if (span.section->virtualSize > executableLimit) {
                span.origin->reject(FailureCode::ImageMemory,
                                    "executable section " + span.section->name + " extent " +
                                        hex(span.section->virtualSize) +
                                        " exceeds image mapping limit " + hex(executableLimit));
            }

            spans.push_back(span);
        }

        for (const auto &section : source.module().sections) {
            if (section.immutable() && section.permissions[2] != 'x' && section.virtualSize) {
                spans.push_back({&section,
                                 {section.rva, uint64_t(section.rva) + section.virtualSize},
                                 indirectRead});
            }
        }
    }

    std::vector<ImageMemory::Span> ImageMemory::selectedSpans() {
        auto spans = std::move(direct);

        if (indirectRead) {
            addIndirectSpans(spans);
        }

        llvm::stable_sort(
            spans, [](const Span &a, const Span &b) { return a.range.begin < b.range.begin; });
        std::vector<Span> merged;
        for (const auto &span : spans) {
            if (!merged.empty() && merged.back().section == span.section &&
                span.range.begin <= merged.back().range.end) {
                merged.back().range.end = std::max(merged.back().range.end, span.range.end);
            } else {
                merged.push_back(span);
            }
        }

        uint64_t total = 0;
        for (const auto &span : merged) {
            total += span.range.end - span.range.begin;
            if (total > moduleLimit) {
                span.origin->reject(FailureCode::ImageMemory,
                                    "image mapping extent " + hex(total) + " including section " +
                                        span.section->name + " exceeds module limit " +
                                        hex(moduleLimit));
            }
        }

        return merged;
    }

    Function *ImageMemory::emitResolver(llvm::Module &module) {
        IRBuilder<> ir(module.getContext());
        std::vector<Constant *> rows;
        for (const auto &span : selectedSpans()) {
            auto *global = embed(module, source, span.range);
            auto append = [&](uint64_t begin, uint64_t end) {
                if (begin < end) {
                    auto *offset = ir.getInt64(begin - span.range.begin);
                    auto *ptr =
                        ConstantExpr::getInBoundsGetElementPtr(ir.getInt8Ty(), global, offset);
                    rows.push_back(
                        ConstantStruct::getAnon({ir.getInt64(source.module().imageBase + begin),
                                                 ir.getInt64(end - begin), ptr}));
                }
            };

            const auto &holes = exclusions();
            uint64_t pos = span.range.begin;
            auto hole = llvm::lower_bound(
                holes, pos, [](RvaRange range, uint64_t start) { return range.end <= start; });
            for (; hole != holes.end() && hole->begin < span.range.end; ++hole) {
                append(pos, hole->begin);
                pos = std::max(pos, hole->end);
            }

            append(pos, span.range.end);
        }

        return rows.empty() ? nullptr : resolver(module, rows);
    }
} // namespace forge::x86
