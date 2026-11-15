#include "lift/image_memory.h"

#include "lift/memory.h"

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        constexpr uint64_t executableLimit = 8ULL * 1024 * 1024;
        constexpr uint64_t moduleLimit = 32ULL * 1024 * 1024;
        constexpr uint64_t writableLimit = 256ULL * 1024 * 1024;

        Constant *immutableBytes(LLVMContext &context, const ImageBytes &bytes, uint64_t length) {
            SmallVector<Constant *> parts;
            uint64_t pos = bytes.prefix.size();

            if (pos) {
                parts.push_back(ConstantDataArray::getString(context, bytes.prefix, false));
            }

            auto zeros = [&](uint64_t count) {
                if (count) {
                    auto *type = ArrayType::get(Type::getInt8Ty(context), count);
                    parts.push_back(ConstantAggregateZero::get(type));
                }
            };

            for (const auto &fragment : bytes.tail) {
                zeros(fragment.offset - pos);
                parts.push_back(ConstantDataArray::getString(context, fragment.bytes, false));
                pos = fragment.offset + fragment.bytes.size();
            }

            zeros(length - pos);
            return parts.size() == 1 ? parts.front() : ConstantStruct::getAnon(parts, true);
        }

        void initializeBytes(IRBuilder<> &init, GlobalVariable *backing, uint64_t offset,
                             StringRef bytes) {
            if (bytes.empty() || llvm::all_of(bytes, [](char byte) { return byte == 0; })) {
                return;
            }

            auto &module = *backing->getParent();

            if (!init.GetInsertBlock()) {
                auto *type = FunctionType::get(init.getVoidTy(), false);
                auto *ctor = Function::Create(type, GlobalValue::InternalLinkage,
                                              "forge_image_initialize", module);
                init.SetInsertPoint(BasicBlock::Create(init.getContext(), "initialize", ctor));
                appendToGlobalCtors(module, ctor, 65535);
            }

            auto *ptr = init.CreateInBoundsGEP(init.getInt8Ty(), backing, init.getInt64(offset));
            auto *data = ConstantDataArray::getString(init.getContext(), bytes, false);

            // Keep large virtual tails in Mach-O zerofill. Folding a constructor's
            // writes into a mixed initializer would materialize the entire virtual tail.
            backing->setExternallyInitialized(true);

            if (bytes.size() <= sizeof(uint64_t)) {
                init.CreateAlignedStore(data, ptr, Align(1));
            } else {
                auto *source =
                    new GlobalVariable(module, data->getType(), true, GlobalValue::PrivateLinkage,
                                       data, "image.initialized");
                source->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
                init.CreateMemCpy(ptr, Align(1), source, Align(1), bytes.size());
            }
        }

        GlobalVariable *embed(llvm::Module &module, IRBuilder<> &init, RvaRange range,
                              bool writable, const ImageBytes &bytes) {
            auto &context = module.getContext();
            const auto length = range.end - range.begin;
            const bool hasWritableTail = writable && bytes.prefix.size() < length;
            Constant *data = nullptr;

            if (hasWritableTail) {
                auto *type = ArrayType::get(Type::getInt8Ty(context), length);
                data = ConstantAggregateZero::get(type);
            } else {
                data = immutableBytes(context, bytes, length);
            }

            auto *global =
                new GlobalVariable(module, data->getType(), !writable, GlobalValue::PrivateLinkage,
                                   data, "image_" + utohexstr(range.begin, true));
            global->setAlignment(Align(1));

            if (hasWritableTail) {
                initializeBytes(init, global, 0, bytes.prefix);

                for (const auto &fragment : bytes.tail) {
                    initializeBytes(init, global, fragment.offset, fragment.bytes);
                }
            }

            return global;
        }

        void finishInitialization(IRBuilder<> &init, IRBuilderBase &entryIR) {
            auto *body = init.GetInsertBlock();

            if (!body) {
                return;
            }

            // A host constructor may invoke the public wrapper before our native constructor.
            // Both paths call the same guarded routine and preserve any state written by the first.
            auto *function = body->getParent();
            auto *ready = new GlobalVariable(*function->getParent(), init.getInt1Ty(), false,
                                             GlobalValue::PrivateLinkage, init.getFalse(),
                                             "image.initialized.once");
            ready->setExternallyInitialized(true);
            auto *entry = BasicBlock::Create(init.getContext(), "entry", function, body);
            auto *done = BasicBlock::Create(init.getContext(), "done", function);
            init.CreateStore(init.getTrue(), ready);
            init.CreateBr(done);
            init.SetInsertPoint(entry);
            auto *initialized = init.CreateLoad(init.getInt1Ty(), ready);
            init.CreateCondBr(initialized, done, body);
            init.SetInsertPoint(done);
            init.CreateRetVoid();
            entryIR.CreateCall(function);
        }

        // Find the last interval start at or below the unsigned guest address. Section
        // validation and span merging guarantee disjoint intervals in ascending order.
        Value *findInterval(IRBuilder<> &ir, GlobalVariable *table, StructType *row,
                            BasicBlock *fault) {
            auto *entry = ir.GetInsertBlock();
            auto *function = entry->getParent();
            auto *loop = BasicBlock::Create(ir.getContext(), "range", function);
            auto *exit = BasicBlock::Create(ir.getContext(), "range.end", function);
            auto *candidate = BasicBlock::Create(ir.getContext(), "candidate", function);
            auto count = cast<ArrayType>(table->getValueType())->getNumElements();
            ir.CreateBr(loop);

            ir.SetInsertPoint(loop);
            auto *low = ir.CreatePHI(ir.getInt64Ty(), 2, "low");
            auto *high = ir.CreatePHI(ir.getInt64Ty(), 2, "high");
            low->addIncoming(ir.getInt64(0), entry);
            high->addIncoming(ir.getInt64(count), entry);
            auto *half = ir.CreateLShr(ir.CreateSub(high, low), 1);
            auto *mid = ir.CreateAdd(low, half, "mid");
            auto *probe = ir.CreateInBoundsGEP(row, table, mid);
            auto *base = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, probe, 0));
            auto *before = ir.CreateICmpULT(function->getArg(0), base);
            auto *nextLow = ir.CreateSelect(before, low, ir.CreateAdd(mid, ir.getInt64(1)));
            auto *nextHigh = ir.CreateSelect(before, mid, high);
            low->addIncoming(nextLow, loop);
            high->addIncoming(nextHigh, loop);
            ir.CreateCondBr(ir.CreateICmpULT(nextLow, nextHigh), loop, exit);

            ir.SetInsertPoint(exit);
            ir.CreateCondBr(ir.CreateICmpNE(nextLow, ir.getInt64(0)), candidate, fault);

            ir.SetInsertPoint(candidate);
            return ir.CreateInBoundsGEP(row, table, ir.CreateSub(nextLow, ir.getInt64(1)));
        }

        Function *resolver(llvm::Module &module, ArrayRef<Constant *> rows) {
            IRBuilder<> ir(module.getContext());
            auto *type = FunctionType::get(
                ir.getPtrTy(), {ir.getInt64Ty(), ir.getInt64Ty(), ir.getInt1Ty()}, false);
            auto *function =
                Function::Create(type, GlobalValue::InternalLinkage, "forge_image_address", module);
            auto *entry = BasicBlock::Create(module.getContext(), "entry", function);
            auto *found = BasicBlock::Create(module.getContext(), "mapped", function);
            auto *fault = BasicBlock::Create(module.getContext(), "fault", function);
            auto *row = cast<StructType>(rows.front()->getType());
            auto *tableType = ArrayType::get(row, rows.size());
            auto *table = new GlobalVariable(module, tableType, true, GlobalValue::PrivateLinkage,
                                             ConstantArray::get(tableType, rows), "image.ranges");

            ir.SetInsertPoint(entry);
            auto *record = findInterval(ir, table, row, fault);
            auto *base = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 0));
            auto *size = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 1));
            auto *width = function->getArg(1);
            auto *offset = ir.CreateSub(function->getArg(0), base);
            auto *fits = ir.CreateICmpULE(offset, ir.CreateSub(size, width));
            auto *writable = ir.CreateLoad(ir.getInt1Ty(), ir.CreateStructGEP(row, record, 3));
            auto *permitted = ir.CreateOr(ir.CreateNot(function->getArg(2)), writable);
            auto *inRange = ir.CreateAnd(ir.CreateICmpUGE(size, width), fits);
            ir.CreateCondBr(ir.CreateAnd(inRange, permitted), found, fault);

            ir.SetInsertPoint(found);
            auto *bytes = ir.CreateLoad(ir.getPtrTy(), ir.CreateStructGEP(row, record, 2));
            ir.CreateRet(ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset));

            ir.SetInsertPoint(fault);
            ir.CreateIntrinsic(Intrinsic::trap, {});
            ir.CreateUnreachable();
            return function;
        }
    } // namespace

    ImageMemory::ImageMemory(const ParsedImage &image, uint64_t guestLoadBase)
        : source(image), loadBase(guestLoadBase) {
        overlapsStack =
            llvm::any_of(image.module().sections, [guestLoadBase](const Section &section) {
                const uint64_t start = guestLoadBase + section.rva;
                return section.virtualSize && start < GuestMemory::base + GuestMemory::capacity &&
                       start + (section.virtualSize - 1) >= GuestMemory::base;
            });
    }

    const ImageInitialization &ImageMemory::contents() {
        if (!initialization) {
            initialization = source.imageInitialization();
        }

        return *initialization;
    }

    void ImageMemory::addressTaken(const Step &step, uint64_t va) {
        const auto *section = source.sectionAtRva(va - loadBase);

        if (section && section->immutable() && section->permissions[2] == 'x') {
            const RvaRange extent{section->rva, uint64_t(section->rva) + section->virtualSize};
            executable.try_emplace(section->rva, Span{section, extent, &step});
        }
    }

    void ImageMemory::checkStackMapping(const Step &step) const {
        if (overlapsStack) {
            step.reject(FailureCode::ImageMemory, "PE image overlaps the guest stack");
        }
    }

    void ImageMemory::fixedAccess(const Step &step, uint64_t va, unsigned width, bool write) {
        const unsigned bytes = width / 8;

        if (va - GuestMemory::base < GuestMemory::capacity) {
            if (va - GuestMemory::base > GuestMemory::capacity - bytes ||
                (va < GuestMemory::entryRsp + 8 && va + bytes > GuestMemory::entryRsp)) {
                step.reject(FailureCode::ImageMemory,
                            "fixed access crosses guest stack boundary or return slot");
            }

            return;
        }

        const auto rva = va - loadBase;
        const auto *section = source.sectionAtRva(rva);

        if (!section || (!section->immutable() && !section->writableData()) ||
            rva + bytes > uint64_t(section->rva) + section->virtualSize) {
            step.reject(FailureCode::ImageMemory,
                        "unmapped or unsupported image access at VA " + hex(va));
        }

        if (write && !section->writableData()) {
            step.reject(FailureCode::ImageMemory, "write to immutable image at VA " + hex(va));
        }

        const RvaRange access{rva, rva + bytes};
        const auto &init = contents();
        init.validateRelocations(access);
        auto holes = init.exclusionsIn(access);

        if (!holes.empty()) {
            for (const auto *rel : init.relocationsIn(access)) {
                if (rel->type != COFF::IMAGE_REL_BASED_DIR64) {
                    step.reject(FailureCode::ImageMemory,
                                "unsupported relocation type " + std::to_string(rel->type) +
                                    " for image data at RVA " + hex(rel->rva));
                }

                if (section->permissions[2] == 'x') {
                    step.reject(FailureCode::ImageMemory,
                                "unsupported executable relocation at RVA " + hex(rel->rva));
                }
            }

            step.reject(
                FailureCode::ImageMemory,
                "image access overlaps loader-written field or relocation in PE metadata at RVA " +
                    hex(holes.front().begin));
        }

        select(step, *section, access);
    }

    void ImageMemory::computedAccess(const Step &step, std::optional<uint64_t> va, unsigned width,
                                     bool write) {
        if (!va) {
            auto &origin = write ? indirectWrite : indirectRead;

            if (!origin) {
                origin = &step;
            }

            return;
        }

        // A proven register value narrows the image selection. An invalid access still
        // goes through the runtime resolver if the guest executes the instruction.
        const auto rva = *va - loadBase;
        const auto *section = source.sectionAtRva(rva);

        if (!section || (!section->writableData() && (write || !section->immutable()))) {
            return;
        }

        const RvaRange access{rva, rva + width / 8};
        if (access.end > uint64_t(section->rva) + section->virtualSize ||
            !contents().exclusionsIn(access).empty()) {
            return;
        }

        if (section->permissions[2] == 'x') {
            if (auto literal = executable.find(section->rva); literal != executable.end()) {
                addExecutableSpan(direct, literal->second);
            }

            return;
        }

        select(step, *section, access);
    }

    void ImageMemory::select(const Step &step, const Section &section, RvaRange access) {
        // All aliases of a writable section share one backing. Known immutable reads
        // only need storage for the selected bytes.
        const RvaRange selected =
            section.writableData()
                ? RvaRange{section.rva, uint64_t(section.rva) + section.virtualSize}
                : access;
        direct.push_back({&section, selected, &step});
    }

    void ImageMemory::addExecutableSpan(std::vector<Span> &spans, const Span &span) {
        if (span.section->virtualSize > executableLimit) {
            span.origin->reject(FailureCode::ImageMemory,
                                "executable section " + span.section->name + " extent " +
                                    hex(span.section->virtualSize) +
                                    " exceeds image mapping limit " + hex(executableLimit));
        }

        spans.push_back(span);
    }

    void ImageMemory::addIndirectSpans(std::vector<Span> &spans) const {
        if (indirectRead) {
            for (const auto &[rva, span] : executable) {
                addExecutableSpan(spans, span);
            }
        }

        for (const auto &section : source.module().sections) {
            const auto *origin =
                section.writableData() && indirectWrite ? indirectWrite : indirectRead;

            if (origin && (section.immutable() || section.writableData()) &&
                section.permissions[2] != 'x' && section.virtualSize) {
                spans.push_back(
                    {&section, {section.rva, uint64_t(section.rva) + section.virtualSize}, origin});
            }
        }
    }

    std::vector<ImageMemory::Span> ImageMemory::selectedSpans() {
        auto spans = std::move(direct);

        if (indirectRead || indirectWrite) {
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

        return merged;
    }

    Function *ImageMemory::emitResolver(llvm::Module &module, IRBuilderBase &entryIR) {
        IRBuilder<> ir(module.getContext());
        IRBuilder<> init(module.getContext());
        std::vector<Constant *> rows;
        uint64_t embedded = 0;
        uint64_t immutableExtent = 0;
        uint64_t writableExtent = 0;

        for (const auto &span : selectedSpans()) {
            const bool writable = span.section->writableData();
            const uint64_t length = span.range.end - span.range.begin;
            auto reserve = [&](uint64_t &used, uint64_t amount, uint64_t limit, StringRef label) {
                used += amount;

                if (used > limit) {
                    span.origin->reject(FailureCode::ImageMemory,
                                        "image extent " + hex(used) + " including section " +
                                            span.section->name + " exceeds " + label.str() + " " +
                                            hex(limit));
                }
            };

            if (writable) {
                reserve(writableExtent, length, writableLimit, "writable virtual limit");
            } else {
                reserve(immutableExtent, length, moduleLimit, "module limit for immutable extent");
            }

            reserve(embedded, source.initializedBytes(span.range).size(), moduleLimit,
                    "module limit for embedded bytes");
            const auto &view = contents();
            auto bytes = source.imageBytes(span.range, view, loadBase);

            for (const auto &fragment : bytes.tail) {
                reserve(embedded, fragment.bytes.size(), moduleLimit,
                        "module limit for embedded bytes");
            }

            auto *global = embed(module, init, span.range, writable, bytes);
            auto append = [&](uint64_t begin, uint64_t end) {
                if (begin < end) {
                    auto *offset = ir.getInt64(begin - span.range.begin);
                    auto *ptr =
                        ConstantExpr::getInBoundsGetElementPtr(ir.getInt8Ty(), global, offset);
                    rows.push_back(ConstantStruct::getAnon({ir.getInt64(loadBase + begin),
                                                            ir.getInt64(end - begin), ptr,
                                                            ir.getInt1(writable)}));
                }
            };

            uint64_t pos = span.range.begin;

            for (auto hole : view.exclusionsIn(span.range)) {
                append(pos, hole.begin);
                pos = std::max(pos, hole.end);
            }

            append(pos, span.range.end);
        }

        finishInitialization(init, entryIR);
        return rows.empty() ? nullptr : resolver(module, rows);
    }
} // namespace forge::x86
