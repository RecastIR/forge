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
        storeAt(ir.getInt64(entryRsp - base), {ir.getInt64(returnMarker)});
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

    StoredValue GuestMemory::loadAt(Value *offset, unsigned width, bool allowOpaque) {
        auto *type = ir.getIntNTy(width);
        auto *markPtr = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *marks = ir.CreateAlignedLoad(type, markPtr, Align(1));

        if (allowOpaque) {
            auto *byteType = FixedVectorType::get(ir.getInt8Ty(), width / 8);
            auto *lanes = ir.CreateBitCast(marks, byteType);
            guard(ir.CreateAndReduce(ir.CreateIsNotNull(lanes)));
        } else {
            guard(ir.CreateICmpEQ(marks, ConstantInt::getAllOnesValue(type)));
        }

        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        return {ir.CreateAlignedLoad(type, data, Align(1)), marks};
    }

    StoredValue GuestMemory::checkedLoad(Value *address, unsigned width, bool allowOpaque,
                                         bool stackOnly) {
        if (stackOnly || !imageResolver) {
            return loadAt(checkedOffset(address, width), width, allowOpaque);
        }

        auto *function = ir.GetInsertBlock()->getParent();
        auto *onStack = BasicBlock::Create(ir.getContext(), "stack.read", function);
        auto *onImage = BasicBlock::Create(ir.getContext(), "image.read", function);
        auto *join = BasicBlock::Create(ir.getContext(), "read.ok", function);
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        ir.CreateCondBr(ir.CreateICmpULT(offset, ir.getInt64(capacity)), onStack, onImage);

        ir.SetInsertPoint(onStack);
        const auto saved = loadAt(checkedOffset(address, width), width, allowOpaque);
        auto *stackExit = ir.GetInsertBlock();
        ir.CreateBr(join);

        ir.SetInsertPoint(onImage);
        auto *ptr = ir.CreateCall(imageResolver, {address, ir.getInt64(width / 8)});
        auto *imageBits = ir.CreateAlignedLoad(ir.getIntNTy(width), ptr, Align(1));
        ir.CreateBr(join);

        ir.SetInsertPoint(join);
        auto *bits = ir.CreatePHI(imageBits->getType(), 2);
        bits->addIncoming(saved.bits, stackExit);
        bits->addIncoming(imageBits, onImage);

        if (!allowOpaque) {
            return {bits};
        }

        auto *marks = ir.CreatePHI(imageBits->getType(), 2);
        marks->addIncoming(saved.marks, stackExit);
        marks->addIncoming(ConstantInt::getAllOnesValue(imageBits->getType()), onImage);
        return {bits, marks};
    }

    Value *GuestMemory::load(Value *address, unsigned width, bool stackOnly) {
        return checkedLoad(address, width, false, stackOnly).bits;
    }

    StoredValue GuestMemory::loadSaved(Value *address, unsigned width, bool stackOnly) {
        return checkedLoad(address, width, true, stackOnly);
    }

    Value *GuestMemory::loadWritable(Value *address, unsigned width) {
        return loadAt(checkedOffset(address, width), width, false).bits;
    }

    StoredValue GuestMemory::loadStackSaved(Value *address, unsigned width) {
        return loadAt(checkedOffset(address, width), width, true);
    }

    void GuestMemory::storeAt(Value *offset, StoredValue value) {
        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(value.bits, data, Align(1));
        auto *origin =
            value.marks ? value.marks : ConstantInt::getAllOnesValue(value.bits->getType());
        ir.CreateAlignedStore(origin, marks, Align(1));
    }

    void GuestMemory::store(Value *address, StoredValue value) {
        storeAt(checkedOffset(address, value.bits->getType()->getIntegerBitWidth()), value);
    }

    void GuestMemory::checkReturn(Value *rsp) {
        guard(ir.CreateICmpEQ(rsp, ir.getInt64(entryRsp)));

        if (bytes) {
            auto marker = loadAt(ir.getInt64(entryRsp - base), 64, false);
            guard(ir.CreateICmpEQ(marker.bits, ir.getInt64(returnMarker)));
        }
    }
} // namespace forge::x86
