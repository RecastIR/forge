#include "lift/memory.h"

#include "forge/runtime.h"

#include "llvm/IR/Intrinsics.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        // Only the outer slot holds a synthetic token. Nested slots hold real guest VAs.
        constexpr uint64_t returnMarker = FORGE_RT_RETURN_MARKER;
        // Incoming nonvolatile identities occupy 1..64. A nested return slot
        // may be inspected by guest code but must never be overwritten.
        constexpr uint8_t returnMark = FORGE_RT_MARK_RETURN;
        static_assert(FORGE_RT_MARK_CONCRETE == UINT8_MAX);
        constexpr uint64_t repeatByte = 0x0101010101010101ULL;
    } // namespace

    void GuestMemory::initialize(Value *stackBytes, Value *stackValidity) {
        bind(stackBytes, stackValidity, nullptr);
        ir.CreateMemSet(validity, ir.getInt8(FORGE_RT_MARK_UNINITIALIZED), capacity, Align(1));
        installReturn(ir.getInt64(entryRsp - base), returnMarker);
    }

    void GuestMemory::bind(Value *stackBytes, Value *stackValidity, Function *resolver,
                           Value *imageRegions, Value *ceiling) {
        bytes = stackBytes;
        validity = stackValidity;
        imageResolver = resolver;
        regions = imageRegions;
        stackCeiling = ceiling;
    }

    Value *GuestMemory::checkedOffset(Value *address, unsigned width, Access access) {
        const unsigned size = width / 8;
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        auto *mapped = ir.CreateICmpULE(offset, ir.getInt64(capacity - size));
        constexpr auto returnOffset = entryRsp - base;
        auto *below = ir.CreateICmpULE(offset, ir.getInt64(returnOffset - size));
        auto *above = ir.CreateICmpUGE(offset, ir.getInt64(returnOffset + 8));
        auto *allowed = ir.CreateAnd(mapped, ir.CreateOr(below, above));
        if (stackCeiling) {
            // No incoming arguments were placed above the initializer's home area.
            // This comparison also covers computed aliases and nested helpers.
            auto *end = ir.CreateAdd(address, ir.getInt64(size));
            allowed = ir.CreateAnd(allowed, ir.CreateICmpULE(end, stackCeiling));
        }

        checks.scalarBoundary(allowed, address, size, static_cast<uint32_t>(access), true);
        return offset;
    }

    GuestMemory::Location GuestMemory::stackLocation(Value *offset, unsigned width, Access access,
                                                     Value *storeMarks) {
        auto *type = ir.getIntNTy(width);
        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *markPtr = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *marks = ir.CreateAlignedLoad(type, markPtr, Align(1));

        auto *byteType = FixedVectorType::get(ir.getInt8Ty(), width / 8);
        auto *lanes = ir.CreateBitCast(marks, byteType);
        if (stackCeiling) {
            // There is no guest DLL instruction address for a native CRT continuation.
            // Never let a saved-register load, store or read-modify-write expose its bits.
            auto *opaque = ConstantVector::getSplat(byteType->getElementCount(),
                                                    ir.getInt8(FORGE_RT_MARK_CALLBACK_RETURN));
            auto *allowed = ir.CreateAndReduce(ir.CreateICmpNE(lanes, opaque));
            checks.scalarBoundary(allowed, ir.CreateAdd(offset, ir.getInt64(base)), width / 8,
                                  static_cast<uint32_t>(access), true);
        }

        const auto checkLanes = [&](Value *allowed) {
            const auto mask =
                access == Access::ReadSaved ? FORGE_RT_READ : static_cast<uint32_t>(access);
            checks.stackMarks(allowed, offset, mask);
        };

        if (access == Access::Modify) {
            checkLanes(ir.CreateICmpEQ(lanes, Constant::getAllOnesValue(byteType)));
            return {data};
        }

        auto *protectedLanes = ir.CreateICmpEQ(
            lanes, ConstantVector::getSplat(byteType->getElementCount(), ir.getInt8(returnMark)));

        if (access == Access::Write) {
            checkLanes(ir.CreateNot(protectedLanes));
            ir.CreateAlignedStore(storeMarks ? storeMarks : ConstantInt::getAllOnesValue(type),
                                  markPtr, Align(1));
            return {data};
        }

        // A plain read of a nested guest return address produces concrete bytes.
        // Its write protection belongs to the stack slot and cannot follow a copy.
        auto *readable =
            ir.CreateSelect(protectedLanes, Constant::getAllOnesValue(byteType), lanes);

        if (access == Access::ReadSaved) {
            checkLanes(ir.CreateIsNotNull(readable));
            return {data, ir.CreateBitCast(readable, type)};
        }

        checkLanes(ir.CreateICmpEQ(readable, Constant::getAllOnesValue(byteType)));
        return {data};
    }

    GuestMemory::Location GuestMemory::resolve(Value *address, unsigned width, Access access,
                                               bool stackOnly, Value *storeMarks) {
        if (stackOnly || (!imageResolver && !checks.managed())) {
            return stackLocation(checkedOffset(address, width, access), width, access, storeMarks);
        }

        auto *function = ir.GetInsertBlock()->getParent();
        auto *onStack = BasicBlock::Create(ir.getContext(), "stack.access", function);
        auto *onImage = BasicBlock::Create(ir.getContext(), "image.access", function);
        auto *join = BasicBlock::Create(ir.getContext(), "memory.ok", function);
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        ir.CreateCondBr(ir.CreateICmpULT(offset, ir.getInt64(capacity)), onStack, onImage);

        ir.SetInsertPoint(onStack);
        const auto stack =
            stackLocation(checkedOffset(address, width, access), width, access, storeMarks);
        auto *stackExit = ir.GetInsertBlock();
        ir.CreateBr(join);

        ir.SetInsertPoint(onImage);
        const bool writes = access == Access::Write || access == Access::Modify;
        SmallVector<Value *, 4> arguments{address, ir.getInt64(width / 8), ir.getInt1(writes)};
        if (checks.managed()) {
            arguments.push_back(regions);
        }

        Value *ptr = ConstantPointerNull::get(ir.getPtrTy());

        if (imageResolver) {
            ptr = ir.CreateCall(imageResolver, arguments);
        }

        if (checks.managed()) {
            ptr = checks.processScalar(ptr, address, width / 8, static_cast<uint32_t>(access));
        }

        if (storeMarks) {
            // Opaque incoming registers only have identities within this invocation.
            checks.guard(
                ir.CreateICmpEQ(storeMarks, ConstantInt::getAllOnesValue(storeMarks->getType())));
        }

        auto *imageExit = ir.GetInsertBlock();
        ir.CreateBr(join);

        ir.SetInsertPoint(join);
        auto *data = ir.CreatePHI(ir.getPtrTy(), 2);
        data->addIncoming(stack.data, stackExit);
        data->addIncoming(ptr, imageExit);

        if (access != Access::ReadSaved) {
            return {data};
        }

        auto *type = ir.getIntNTy(width);
        auto *marks = ir.CreatePHI(type, 2);
        marks->addIncoming(stack.marks, stackExit);
        marks->addIncoming(ConstantInt::getAllOnesValue(type), imageExit);
        return {data, marks};
    }

    Value *GuestMemory::load(Value *address, unsigned width, bool stackOnly) {
        auto location = resolve(address, width, Access::Read, stackOnly);
        return ir.CreateAlignedLoad(ir.getIntNTy(width), location.data, Align(1));
    }

    StoredValue GuestMemory::loadSaved(Value *address, unsigned width, bool stackOnly) {
        auto location = resolve(address, width, Access::ReadSaved, stackOnly);
        return {ir.CreateAlignedLoad(ir.getIntNTy(width), location.data, Align(1)), location.marks};
    }

    void GuestMemory::store(Value *address, StoredValue value, bool stackOnly) {
        const unsigned width = value.bits->getType()->getIntegerBitWidth();
        auto location = resolve(address, width, Access::Write, stackOnly, value.marks);
        ir.CreateAlignedStore(value.bits, location.data, Align(1));
    }

    Value *GuestMemory::atomicExchange(Value *address, Value *replacement, Value *expected,
                                       bool stackOnly) {
        const auto location = resolve(address, 64, Access::Modify, stackOnly);
        // The ARM64 atomics require natural alignment of the native backing. A
        // guest range can be aligned while an embedding host's backing is not.
        auto *native = ir.CreatePtrToInt(location.data, ir.getInt64Ty());
        auto *alignmentBits = ir.CreateAnd(ir.CreateOr(native, address), ir.getInt64(7));
        checks.requireSupported(ir.CreateIsNull(alignmentBits));
        constexpr auto order = AtomicOrdering::SequentiallyConsistent;

        if (expected) {
            auto *operation = ir.CreateAtomicCmpXchg(location.data, expected, replacement, Align(8),
                                                     order, order);
            return ir.CreateExtractValue(operation, 0);
        }

        return ir.CreateAtomicRMW(AtomicRMWInst::Xchg, location.data, replacement, Align(8), order);
    }

    void GuestMemory::modify(Value *address, unsigned width, bool stackOnly,
                             function_ref<Value *(Value *)> operation) {
        auto location = resolve(address, width, Access::Modify, stackOnly);
        auto *old = ir.CreateAlignedLoad(ir.getIntNTy(width), location.data, Align(1));
        ir.CreateAlignedStore(operation(old), location.data, Align(1));
    }

    void GuestMemory::checkReturn(Value *rsp) {
        checks.guard(ir.CreateICmpEQ(rsp, ir.getInt64(entryRsp)), FORGE_RT_FAULT_CONTROL);

        if (bytes) {
            verifyReturn(ir.getInt64(entryRsp - base), returnMarker);
        }
    }

    void GuestMemory::installReturn(Value *offset, uint64_t address, uint8_t mark) {
        auto *slot = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(address), slot, Align(1));
        ir.CreateAlignedStore(ir.getInt64(repeatByte * mark), marks, Align(1));
    }

    void GuestMemory::verifyReturn(Value *offset, uint64_t address, uint8_t mark) {
        auto *slot = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *value = ir.CreateAlignedLoad(ir.getInt64Ty(), slot, Align(1));
        auto *identity = ir.CreateAlignedLoad(ir.getInt64Ty(), marks, Align(1));
        auto *sameVA = ir.CreateICmpEQ(value, ir.getInt64(address));
        auto *protectedSlot = ir.CreateICmpEQ(identity, ir.getInt64(repeatByte * mark));
        checks.guard(ir.CreateAnd(sameVA, protectedSlot), FORGE_RT_FAULT_CONTROL);
    }

    Value *GuestMemory::reserveReturn(Value *callRsp, Value *callerEntryRsp, uint64_t address,
                                      uint8_t mark) {
        // Caller-owned shadow space ends at or below its live return slot. Even
        // after a guest RSP pivot, every nested frame strictly descends.
        auto *aligned = ir.CreateIsNull(ir.CreateAnd(callRsp, ir.getInt64(15)));
        auto *shadowLimit = ir.CreateSub(callerEntryRsp, ir.getInt64(32));
        auto *hasShadow = ir.CreateICmpULE(callRsp, shadowLimit);
        checks.guard(ir.CreateAnd(aligned, hasShadow));

        auto *nextRsp = ir.CreateSub(callRsp, ir.getInt64(8));
        installReturn(checkedOffset(nextRsp, 64, Access::Write), address, mark);
        return nextRsp;
    }

    Value *GuestMemory::returnOffset(Value *rsp, Value *expectedEntryRsp, uint64_t address,
                                     uint8_t mark) {
        checks.guard(ir.CreateICmpEQ(rsp, expectedEntryRsp), FORGE_RT_FAULT_CONTROL);
        auto *offset = ir.CreateSub(expectedEntryRsp, ir.getInt64(base));
        verifyReturn(offset, address, mark);
        return offset;
    }

    Value *GuestMemory::pushReturn(Value *callRsp, Value *callerEntryRsp, uint64_t nextGuestVA) {
        return reserveReturn(callRsp, callerEntryRsp, nextGuestVA, returnMark);
    }

    Value *GuestMemory::popReturn(Value *rsp, Value *expectedEntryRsp, uint64_t nextGuestVA) {
        auto *offset = returnOffset(rsp, expectedEntryRsp, nextGuestVA, returnMark);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(UINT64_MAX), marks, Align(1));
        return ir.CreateAdd(rsp, ir.getInt64(8));
    }

    Value *GuestMemory::pushInitializerReturn(Value *serviceRsp) {
        // The imported CALL already owns a live return at serviceRsp (8 modulo 16).
        // Subtract 32 bytes of home space and eight of alignment before the nested CALL.
        auto *home = ir.CreateSub(serviceRsp, ir.getInt64(initializerHomeEnd));
        auto *rsp = reserveReturn(home, serviceRsp, 0, FORGE_RT_MARK_CALLBACK_RETURN);
        auto *offset = ir.CreateSub(home, ir.getInt64(base));
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateMemSet(marks, ir.getInt8(FORGE_RT_MARK_UNINITIALIZED), initializerHomeEnd,
                        Align(1));
        return rsp;
    }

    void GuestMemory::popInitializerReturn(Value *rsp, Value *expectedEntryRsp) {
        auto *offset = returnOffset(rsp, expectedEntryRsp, 0, FORGE_RT_MARK_CALLBACK_RETURN);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(0), marks, Align(1));
    }
} // namespace forge::x86
