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
        constexpr uint64_t returnMarks = 0x0101010101010101ULL * returnMark;
    } // namespace

    void GuestMemory::initialize(Value *stackBytes, Value *stackValidity) {
        bind(stackBytes, stackValidity, nullptr);
        ir.CreateMemSet(validity, ir.getInt8(FORGE_RT_MARK_UNINITIALIZED), capacity, Align(1));
        installReturn(ir.getInt64(entryRsp - base), returnMarker);
    }

    void GuestMemory::bind(Value *stackBytes, Value *stackValidity, Function *resolver,
                           Value *imageRegions) {
        bytes = stackBytes;
        validity = stackValidity;
        imageResolver = resolver;
        regions = imageRegions;
    }

    uint32_t GuestMemory::permissions(Access access) {
        if (access == Access::Modify) {
            return FORGE_RT_READ | FORGE_RT_WRITE;
        }

        return access == Access::Write ? FORGE_RT_WRITE : FORGE_RT_READ;
    }

    Value *GuestMemory::checkedOffset(Value *address, unsigned width, Access access) {
        const unsigned size = width / 8;
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        auto *mapped = ir.CreateICmpULE(offset, ir.getInt64(capacity - size));
        constexpr auto returnOffset = entryRsp - base;
        auto *below = ir.CreateICmpULE(offset, ir.getInt64(returnOffset - size));
        auto *above = ir.CreateICmpUGE(offset, ir.getInt64(returnOffset + 8));
        auto *allowed = ir.CreateAnd(mapped, ir.CreateOr(below, above));
        Value *badAddress = address;

        if (checks.managed()) {
            auto *inside = ir.CreateICmpULT(offset, ir.getInt64(capacity));
            auto *crossesEnd = ir.CreateAnd(inside, ir.CreateNot(mapped));
            badAddress = ir.CreateSelect(crossesEnd, ir.getInt64(base + capacity), address);
            auto *crossesReturn =
                ir.CreateAnd(mapped, ir.CreateICmpULT(address, ir.getInt64(entryRsp)));
            badAddress = ir.CreateSelect(crossesReturn, ir.getInt64(entryRsp), badAddress);
        }

        checks.memory(allowed, badAddress, permissions(access), ir.getInt32(FORGE_RT_FAULT_STACK));

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
        const auto checkLanes = [&](Value *allowed) {
            if (checks.managed()) {
                checks.memory(ir.CreateAndReduce(allowed), ir.CreateAdd(offset, ir.getInt64(base)),
                              permissions(access), ir.getInt32(FORGE_RT_FAULT_STACK),
                              ir.CreateNot(allowed));
            } else {
                checks.guard(ir.CreateAndReduce(allowed));
            }
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
        if (stackOnly || !imageResolver) {
            if (!stackOnly && checks.managed()) {
                auto *onStack = ir.CreateICmpULT(ir.CreateSub(address, ir.getInt64(base)),
                                                 ir.getInt64(capacity));
                auto *overflow =
                    ir.CreateICmpUGT(address, ir.getInt64(UINT64_MAX - (width / 8 - 1)));
                auto *reason = ir.CreateSelect(overflow, ir.getInt32(FORGE_RT_FAULT_OVERFLOW),
                                               ir.getInt32(FORGE_RT_FAULT_UNMAPPED));
                checks.memory(onStack, address, permissions(access), reason);
            }

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

        Value *ptr = ir.CreateCall(imageResolver, arguments);

        if (checks.managed()) {
            auto *reason = ir.CreateExtractValue(ptr, 1);
            auto *faultAddress = ir.CreateExtractValue(ptr, 2);
            checks.memory(ir.CreateIsNull(reason), faultAddress, permissions(access), reason);
            ptr = ir.CreateExtractValue(ptr, 0);
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

    void GuestMemory::installReturn(Value *offset, uint64_t address) {
        auto *slot = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(address), slot, Align(1));
        ir.CreateAlignedStore(ir.getInt64(returnMarks), marks, Align(1));
    }

    void GuestMemory::verifyReturn(Value *offset, uint64_t address) {
        auto *slot = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *value = ir.CreateAlignedLoad(ir.getInt64Ty(), slot, Align(1));
        auto *identity = ir.CreateAlignedLoad(ir.getInt64Ty(), marks, Align(1));
        auto *sameVA = ir.CreateICmpEQ(value, ir.getInt64(address));
        auto *protectedSlot = ir.CreateICmpEQ(identity, ir.getInt64(returnMarks));
        checks.guard(ir.CreateAnd(sameVA, protectedSlot), FORGE_RT_FAULT_CONTROL);
    }

    Value *GuestMemory::pushReturn(Value *callRsp, Value *callerEntryRsp, uint64_t nextGuestVA) {
        // Caller-owned shadow space ends at or below its live return slot. Even
        // after a guest RSP pivot, every nested frame strictly descends.
        auto *aligned = ir.CreateIsNull(ir.CreateAnd(callRsp, ir.getInt64(15)));
        auto *shadowLimit = ir.CreateSub(callerEntryRsp, ir.getInt64(32));
        auto *hasShadow = ir.CreateICmpULE(callRsp, shadowLimit);
        checks.guard(ir.CreateAnd(aligned, hasShadow));

        auto *nextRsp = ir.CreateSub(callRsp, ir.getInt64(8));
        installReturn(checkedOffset(nextRsp, 64, Access::Write), nextGuestVA);
        return nextRsp;
    }

    Value *GuestMemory::popReturn(Value *rsp, Value *expectedEntryRsp, uint64_t nextGuestVA) {
        checks.guard(ir.CreateICmpEQ(rsp, expectedEntryRsp), FORGE_RT_FAULT_CONTROL);
        auto *offset = ir.CreateSub(expectedEntryRsp, ir.getInt64(base));
        verifyReturn(offset, nextGuestVA);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(UINT64_MAX), marks, Align(1));
        return ir.CreateAdd(rsp, ir.getInt64(8));
    }
} // namespace forge::x86
