#include "lift/memory.h"

#include "forge/runtime.h"

#include "llvm/IR/Intrinsics.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        // Only the outer slot holds a synthetic token. Nested slots hold real guest VAs.
        constexpr uint64_t returnMarker = 0x4652474552455401ULL;
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

    void GuestMemory::bind(Value *stackBytes, Value *stackValidity, Function *resolver) {
        bytes = stackBytes;
        validity = stackValidity;
        imageResolver = resolver;
    }

    void GuestMemory::guard(Value *condition) {
        auto *function = ir.GetInsertBlock()->getParent();

        if (!fault) {
            IRBuilderBase::InsertPointGuard restore(ir);
            fault = BasicBlock::Create(ir.getContext(), "stack.fault", function);
            ir.SetInsertPoint(fault);
            ir.CreateIntrinsic(Intrinsic::trap, {});
            ir.CreateUnreachable();
        }

        auto *next = BasicBlock::Create(ir.getContext(), "stack.ok", function);
        ir.CreateCondBr(condition, next, fault);
        ir.SetInsertPoint(next);
    }

    Value *GuestMemory::checkedOffset(Value *address, unsigned width) {
        const unsigned size = width / 8;
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        auto *mapped = ir.CreateICmpULE(offset, ir.getInt64(capacity - size));
        constexpr auto returnOffset = entryRsp - base;
        auto *below = ir.CreateICmpULE(offset, ir.getInt64(returnOffset - size));
        auto *above = ir.CreateICmpUGE(offset, ir.getInt64(returnOffset + 8));
        guard(ir.CreateAnd(mapped, ir.CreateOr(below, above)));

        return offset;
    }

    GuestMemory::Location GuestMemory::stackLocation(Value *offset, unsigned width, Access access,
                                                     Value *storeMarks) {
        auto *type = ir.getIntNTy(width);
        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *markPtr = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *marks = ir.CreateAlignedLoad(type, markPtr, Align(1));

        if (access == Access::Modify) {
            guard(ir.CreateICmpEQ(marks, ConstantInt::getAllOnesValue(type)));
            return {data};
        }

        auto *byteType = FixedVectorType::get(ir.getInt8Ty(), width / 8);
        auto *lanes = ir.CreateBitCast(marks, byteType);
        auto *protectedLanes = ir.CreateICmpEQ(
            lanes, ConstantVector::getSplat(byteType->getElementCount(), ir.getInt8(returnMark)));

        if (access == Access::Write) {
            guard(ir.CreateNot(ir.CreateOrReduce(protectedLanes)));
            ir.CreateAlignedStore(storeMarks ? storeMarks : ConstantInt::getAllOnesValue(type),
                                  markPtr, Align(1));
            return {data};
        }

        // A plain read of a nested guest return address produces concrete bytes.
        // Its write protection belongs to the stack slot and cannot follow a copy.
        auto *readable =
            ir.CreateSelect(protectedLanes, Constant::getAllOnesValue(byteType), lanes);

        if (access == Access::ReadSaved) {
            guard(ir.CreateAndReduce(ir.CreateIsNotNull(readable)));
            return {data, ir.CreateBitCast(readable, type)};
        }

        guard(
            ir.CreateICmpEQ(ir.CreateBitCast(readable, type), ConstantInt::getAllOnesValue(type)));
        return {data};
    }

    GuestMemory::Location GuestMemory::resolve(Value *address, unsigned width, Access access,
                                               bool stackOnly, Value *storeMarks) {
        if (stackOnly || !imageResolver) {
            return stackLocation(checkedOffset(address, width), width, access, storeMarks);
        }

        auto *function = ir.GetInsertBlock()->getParent();
        auto *onStack = BasicBlock::Create(ir.getContext(), "stack.access", function);
        auto *onImage = BasicBlock::Create(ir.getContext(), "image.access", function);
        auto *join = BasicBlock::Create(ir.getContext(), "memory.ok", function);
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        ir.CreateCondBr(ir.CreateICmpULT(offset, ir.getInt64(capacity)), onStack, onImage);

        ir.SetInsertPoint(onStack);
        const auto stack = stackLocation(checkedOffset(address, width), width, access, storeMarks);
        auto *stackExit = ir.GetInsertBlock();
        ir.CreateBr(join);

        ir.SetInsertPoint(onImage);
        const bool writes = access == Access::Write || access == Access::Modify;
        auto *ptr =
            ir.CreateCall(imageResolver, {address, ir.getInt64(width / 8), ir.getInt1(writes)});
        if (storeMarks) {
            // Opaque incoming registers only have identities within this invocation.
            guard(ir.CreateICmpEQ(storeMarks, ConstantInt::getAllOnesValue(storeMarks->getType())));
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
        guard(ir.CreateICmpEQ(rsp, ir.getInt64(entryRsp)));

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
        guard(ir.CreateAnd(sameVA, protectedSlot));
    }

    Value *GuestMemory::pushReturn(Value *callRsp, Value *callerEntryRsp, uint64_t nextGuestVA) {
        // Caller-owned shadow space ends at or below its live return slot. Even
        // after a guest RSP pivot, every nested frame strictly descends.
        auto *aligned = ir.CreateIsNull(ir.CreateAnd(callRsp, ir.getInt64(15)));
        auto *shadowLimit = ir.CreateSub(callerEntryRsp, ir.getInt64(32));
        auto *hasShadow = ir.CreateICmpULE(callRsp, shadowLimit);
        guard(ir.CreateAnd(aligned, hasShadow));

        auto *nextRsp = ir.CreateSub(callRsp, ir.getInt64(8));
        installReturn(checkedOffset(nextRsp, 64), nextGuestVA);
        return nextRsp;
    }

    Value *GuestMemory::popReturn(Value *rsp, Value *expectedEntryRsp, uint64_t nextGuestVA) {
        guard(ir.CreateICmpEQ(rsp, expectedEntryRsp));
        auto *offset = ir.CreateSub(expectedEntryRsp, ir.getInt64(base));
        verifyReturn(offset, nextGuestVA);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(ir.getInt64(UINT64_MAX), marks, Align(1));
        return ir.CreateAdd(rsp, ir.getInt64(8));
    }
} // namespace forge::x86
