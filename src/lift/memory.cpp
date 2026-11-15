#include "lift/memory.h"

#include "llvm/IR/Intrinsics.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        // An isolated invocation owns this token; it never dispatches to a guest PC.
        constexpr uint64_t returnMarker = 0x4652474552455401ULL;
    } // namespace

    void GuestMemory::allocate(Function *resolver) {
        imageResolver = resolver;
        bytes = ir.CreateAlloca(ir.getInt8Ty(), ir.getInt32(capacity), "stack.bytes");
        validity = ir.CreateAlloca(ir.getInt8Ty(), ir.getInt32(capacity), "stack.valid");
        ir.CreateMemSet(validity, ir.getInt8(0), capacity, Align(1));
        auto marker = stackLocation(ir.getInt64(entryRsp - base), 64, Access::Write);
        ir.CreateAlignedStore(ir.getInt64(returnMarker), marker.data, Align(1));
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

        if (access == Access::Write) {
            ir.CreateAlignedStore(storeMarks ? storeMarks : ConstantInt::getAllOnesValue(type),
                                  markPtr, Align(1));
            return {data};
        }

        auto *marks = ir.CreateAlignedLoad(type, markPtr, Align(1));
        if (access == Access::ReadSaved) {
            auto *byteType = FixedVectorType::get(ir.getInt8Ty(), width / 8);
            auto *lanes = ir.CreateBitCast(marks, byteType);
            guard(ir.CreateAndReduce(ir.CreateIsNotNull(lanes)));
            return {data, marks};
        }

        // Arithmetic reads concrete bytes and leaves their stack marks concrete.
        guard(ir.CreateICmpEQ(marks, ConstantInt::getAllOnesValue(type)));
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
            auto marker = stackLocation(ir.getInt64(entryRsp - base), 64, Access::Read);
            auto *value = ir.CreateAlignedLoad(ir.getInt64Ty(), marker.data, Align(1));
            guard(ir.CreateICmpEQ(value, ir.getInt64(returnMarker)));
        }
    }
} // namespace forge::x86
