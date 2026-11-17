#include "lift/image_memory.h"

#include "forge/guest_range.h"
#include "forge/runtime.h"
#include "lift/address_fact.h"
#include "lift/memory.h"
#include "lift/recovery.h"

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        constexpr uint64_t executableLimit = 8ULL * 1024 * 1024;
        constexpr uint64_t moduleLimit = 32ULL * 1024 * 1024;
        constexpr uint64_t writableLimit = 256ULL * 1024 * 1024;
        constexpr auto stackRange =
            GuestRange::fromOffset({GuestMemory::base}, 0, GuestMemory::capacity).value();

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

        void finishCheckedInitialization(IRBuilder<> &ir, BasicBlock *body) {
            auto *function = body->getParent();
            auto *state = new GlobalVariable(*function->getParent(), ir.getInt8Ty(), false,
                                             GlobalValue::PrivateLinkage, ir.getInt8(0),
                                             "image.initialized.once");
            auto *entry = BasicBlock::Create(ir.getContext(), "entry", function, body);
            auto *claim = BasicBlock::Create(ir.getContext(), "claim", function, body);
            auto *wait = BasicBlock::Create(ir.getContext(), "wait", function);
            auto *done = BasicBlock::Create(ir.getContext(), "done", function);

            // The initializer writes only this module's backing and never calls guest code.
            // Every admitted caller observes the completed prefix and relocation fragments.
            ir.CreateAlignedStore(ir.getInt8(2), state, Align(1))
                ->setAtomic(AtomicOrdering::Release);
            ir.CreateBr(done);
            auto ready = [&] {
                auto *value = ir.CreateAlignedLoad(ir.getInt8Ty(), state, Align(1));
                value->setAtomic(AtomicOrdering::Acquire);
                return ir.CreateICmpEQ(value, ir.getInt8(2));
            };

            ir.SetInsertPoint(entry);
            ir.CreateCondBr(ready(), done, claim);
            ir.SetInsertPoint(claim);
            auto *won =
                ir.CreateAtomicCmpXchg(state, ir.getInt8(0), ir.getInt8(1), Align(1),
                                       AtomicOrdering::Monotonic, AtomicOrdering::Monotonic);
            ir.CreateCondBr(ir.CreateExtractValue(won, 1), body, wait);
            ir.SetInsertPoint(wait);
            ir.CreateCondBr(ready(), done, wait);
            ir.SetInsertPoint(done);
            ir.CreateRetVoid();
        }

        void finishInitialization(IRBuilder<> &init, IRBuilderBase &entryIR, bool checked) {
            auto *body = init.GetInsertBlock();

            if (!body) {
                return;
            }

            auto *function = body->getParent();
            entryIR.CreateCall(function);

            if (checked) {
                finishCheckedInitialization(init, body);
                return;
            }

            // A host constructor may invoke the public wrapper before our native constructor.
            // Both paths call the same guarded routine and preserve any state written by the first.
            appendToGlobalCtors(*function->getParent(), function, 65535);
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

        Function *resolver(llvm::Module &module, GlobalVariable *table, bool checked) {
            IRBuilder<> ir(module.getContext());
            auto *type = FunctionType::get(
                ir.getPtrTy(), {ir.getInt64Ty(), ir.getInt64Ty(), ir.getInt1Ty()}, false);
            auto *function =
                Function::Create(type, GlobalValue::InternalLinkage, "forge_image_address", module);
            auto *entry = BasicBlock::Create(module.getContext(), "entry", function);
            auto *found = BasicBlock::Create(module.getContext(), "mapped", function);
            auto *fault = BasicBlock::Create(module.getContext(), "fault", function);
            auto *row = cast<StructType>(table->getValueType()->getArrayElementType());

            ir.SetInsertPoint(entry);
            auto *record = findInterval(ir, table, row, fault);
            auto *base = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 0));
            auto *size = ir.CreateLoad(ir.getInt64Ty(), ir.CreateStructGEP(row, record, 1));
            auto *width = function->getArg(1);
            auto *offset = ir.CreateSub(function->getArg(0), base);
            auto *fits = ir.CreateICmpULE(offset, ir.CreateSub(size, width));
            Value *writable =
                ir.CreateLoad(row->getElementType(3), ir.CreateStructGEP(row, record, 3));

            if (checked) {
                writable = ir.CreateIsNotNull(ir.CreateAnd(writable, ir.getInt32(FORGE_RT_WRITE)));
            }

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

    ImageMemory::ImageMemory(const ParsedImage &image, uint64_t guestLoadBase, bool checkedMemory)
        : source(image), loadBase(guestLoadBase) {
        if (checkedMemory) {
            // The process reserves the entire image, even when no resolver rows are emitted.
            const auto size = image.module().sizeOfImage;
            const auto reservation = GuestRange::fromOffset({loadBase}, 0, size);

            if (!reservation) {
                throw InspectionError("checked image reservation at VA " + hex(loadBase) +
                                          " with SizeOfImage " + hex(size) +
                                          " overflows the guest address space",
                                      FailureCode::ImageMemory);
            }

            overlapsStack = reservation->overlaps(stackRange);
            return;
        }

        overlapsStack = llvm::any_of(image.module().sections, [&](const Section &section) {
            if (section.virtualSize == 0) {
                return false;
            }

            // validateGuestBase checked the extent of every nonempty section.
            const auto range =
                GuestRange::fromOffset({guestLoadBase}, section.rva, section.virtualSize).value();
            return range.overlaps(stackRange);
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
            step.reject(FailureCode::ImageMemory,
                        "PE image overlaps the guest stack [" + hex(GuestMemory::base) + ", " +
                            hex(GuestMemory::base + GuestMemory::capacity) +
                            ") at selected image base " + hex(loadBase) + " with SizeOfImage " +
                            hex(source.module().sizeOfImage));
        }
    }

    void ImageMemory::serviceArgument(const Step &step, uint64_t va, win64::Argument arg) {
        if (va == 0 || va - GuestMemory::base < GuestMemory::capacity) {
            return;
        }

        const auto rva = va - loadBase;
        const auto *section = source.sectionAtRva(rva);
        if (!section || section->permissions[2] == 'x' ||
            (!section->immutable() && !section->writableData())) {
            step.reject(
                FailureCode::ImageMemory,
                "service argument at guest VA " + hex(va) +
                    " requires a readable non-executable PE data section or the guest stack");
        }

        if (arg.writes() && !section->writableData()) {
            step.reject(FailureCode::ImageMemory,
                        "output argument at guest VA " + hex(va) +
                            " requires writable PE data or the guest stack");
        }

        if (!contents().exclusionsIn({rva, rva + 1}).empty()) {
            step.reject(FailureCode::ImageMemory,
                        "service argument at guest VA " + hex(va) +
                            " overlaps a protected loader-written field or relocation");
        }

        // Dynamic lengths and mutable terminators can reach anywhere in this section.
        // Leave holes and the section boundary to the checked transfer at execution.
        const uint64_t end = uint64_t(section->rva) + section->virtualSize;
        const RvaRange range = arg.extent == win64::Extent::Fixed
                                   ? RvaRange{rva, std::min(end, rva + arg.size)}
                                   : RvaRange{section->rva, end};
        select(step, *section, range);
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
        fixedImageAccess(step, {rva, rva + bytes}, write);
    }

    void ImageMemory::tableRead(const Step &step, const RelativeTable &table) {
        fixedImageAccess(step, {table.tableRva, uint64_t(table.tableRva) + 4ULL * table.count},
                         false);
    }

    void ImageMemory::fixedImageAccess(const Step &step, RvaRange access, bool write) {
        const auto *section = source.sectionAtRva(access.begin);

        if (!section || (!section->immutable() && !section->writableData()) ||
            access.end > uint64_t(section->rva) + section->virtualSize) {
            step.reject(FailureCode::ImageMemory, "unmapped or unsupported image access at VA " +
                                                      hex(loadBase + access.begin));
        }

        if (write && !section->writableData()) {
            step.reject(FailureCode::ImageMemory,
                        "write to immutable image at VA " + hex(loadBase + access.begin));
        }

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

        selectComputed(step, *va, width, write, ExecutableSelection::AddressTakenSection);
    }

    void ImageMemory::continuationAccess(const Step &step, const Continuation &origin,
                                         llvm::ArrayRef<const ResolvedCallSite *> sites,
                                         unsigned width, bool write) {
        // Repeated reads in a high-fan-in helper need only one expansion of its
        // call sites. The first selecting step owns the budget diagnostic.
        if (!continuationAccesses.emplace(origin.callee, origin.offset, width, write).second) {
            return;
        }

        for (const auto *site : sites) {
            selectComputed(step, loadBase + site->continuation + origin.offset, width, write,
                           ExecutableSelection::ContinuationBytes);
        }
    }

    void ImageMemory::selectComputed(const Step &step, uint64_t va, unsigned width, bool write,
                                     ExecutableSelection executableSelection) {
        // A proven register value narrows the image selection. An invalid access still
        // goes through the runtime resolver if the guest executes the instruction.
        const auto rva = va - loadBase;
        const auto *section = source.sectionAtRva(rva);

        if (!section || (!section->writableData() && (write || !section->immutable()))) {
            return;
        }

        const RvaRange access{rva, rva + width / 8};
        if (access.end > uint64_t(section->rva) + section->virtualSize ||
            !contents().exclusionsIn(access).empty()) {
            return;
        }

        if (section->permissions[2] == 'x' &&
            executableSelection == ExecutableSelection::AddressTakenSection) {
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

    ImagePlan ImageMemory::finish() && {
        ImagePlan plan;
        plan.loadBase = loadBase;
        plan.sizeOfImage = source.module().sizeOfImage;
        uint64_t embedded = 0;
        uint64_t immutableExtent = 0;
        uint64_t writableExtent = 0;

        const auto spans = selectedSpans();
        plan.backings.reserve(spans.size());

        for (const auto &span : spans) {
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

            ImagePlan::Backing backing{
                span.range, writable, span.section->permissions[2] == 'x', std::move(bytes), {}};
            uint64_t pos = span.range.begin;

            for (auto hole : view.exclusionsIn(span.range)) {
                if (pos < hole.begin) {
                    backing.intervals.push_back({pos, hole.begin});
                }

                pos = std::max(pos, hole.end);
            }

            if (pos < span.range.end) {
                backing.intervals.push_back({pos, span.range.end});
            }

            plan.backings.push_back(std::move(backing));
        }

        return plan;
    }

    EmittedImage ImagePlan::emit(llvm::Module &module, IRBuilderBase &entryIR, bool checked) const {
        IRBuilder<> ir(module.getContext());
        IRBuilder<> init(module.getContext());
        std::vector<Constant *> rows;
        auto *null = ConstantPointerNull::get(ir.getPtrTy());

        for (const auto &backing : backings) {
            auto *global = embed(module, init, backing.range, backing.writable, backing.bytes);
            Constant *claim = null;

            if (checked && backing.writable && !backing.intervals.empty()) {
                claim =
                    new GlobalVariable(module, ir.getInt64Ty(), false, GlobalValue::PrivateLinkage,
                                       ir.getInt64(0), "image.backing.claim");
            }

            SmallVector<Constant *, 2> attributes;

            if (checked) {
                const auto permissions = FORGE_RT_READ | (backing.writable ? FORGE_RT_WRITE : 0U) |
                                         (backing.executable ? FORGE_RT_EXECUTE : 0U);
                attributes.append({ir.getInt32(permissions), claim});
            } else {
                attributes.push_back(ir.getInt1(backing.writable));
            }

            for (auto interval : backing.intervals) {
                auto *offset = ir.getInt64(interval.begin - backing.range.begin);
                auto *ptr = ConstantExpr::getInBoundsGetElementPtr(ir.getInt8Ty(), global, offset);
                SmallVector<Constant *> fields{ir.getInt64(loadBase + interval.begin),
                                               ir.getInt64(interval.end - interval.begin), ptr};

                fields.append(attributes);
                rows.push_back(ConstantStruct::getAnon(fields));
            }
        }

        GlobalVariable *table = nullptr;

        if (!rows.empty()) {
            auto *type = ArrayType::get(rows.front()->getType(), rows.size());
            table = new GlobalVariable(module, type, true, GlobalValue::PrivateLinkage,
                                       ConstantArray::get(type, rows), "image.ranges");
        }

        EmittedImage result{table ? resolver(module, table, checked) : nullptr, nullptr};

        if (checked) {
            auto *descriptor = ConstantStruct::getAnon(
                {ir.getInt64(loadBase), ir.getInt64(sizeOfImage),
                 table ? static_cast<Constant *>(table) : null, ir.getInt64(rows.size())});
            auto *storage =
                new GlobalVariable(module, descriptor->getType(), true, GlobalValue::PrivateLinkage,
                                   descriptor, "forge_checked_image");
            auto *type = FunctionType::get(ir.getPtrTy(), false);
            result.descriptorAccessor =
                Function::Create(type, GlobalValue::ExternalLinkage, "forge_lifted_image", module);
            result.descriptorAccessor->setDSOLocal(true);
            ir.SetInsertPoint(
                BasicBlock::Create(ir.getContext(), "entry", result.descriptorAccessor));
            finishInitialization(init, ir, true);
            ir.CreateRet(storage);
        } else {
            finishInitialization(init, entryIR, false);
        }

        return result;
    }
} // namespace forge::x86
