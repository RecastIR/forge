#include "analysis.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <map>

namespace forge {
namespace {
using namespace llvm;

[[noreturn]] void fail(uint32_t rva, const Twine& why) {
    throw InspectionError(hex(rva) + ": " + why.str(), "LIFT_ERROR");
}

struct Step {
    uint32_t rva, next;
    MCInst inst;
    StringRef opcode;
    StringRef bytes;
    [[noreturn]] void reject(const Twine& reason) const {
        fail(rva, opcode + " [" + toHex(bytes, true) + "]: " + reason);
    }
};

bool legacyPrefix(uint8_t b) {
    switch (b) {
    case 0xf0:
    case 0xf2:
    case 0xf3:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return false;
    }
}

std::vector<Step> decode(StringRef bytes, uint32_t begin, const MCDisassembler& dis,
                         const MCInstrInfo& instructions) {
    // Establish boundaries even across skipped code. Only reachable instructions are lowered.
    if (bytes.size() > size_t{64} * 1024)
        fail(begin, "experimental lift limit is 64 KiB per function");
    std::vector<Step> steps;
    for (size_t pos = 0; pos < bytes.size();) {
        auto tail = bytes.drop_front(pos);
        uint32_t rva = begin + static_cast<uint32_t>(pos);
        uint64_t size = 0;
        MCInst inst;
        if (dis.getInstruction(inst, size, arrayRefFromStringRef(tail), rva, nulls()) !=
                MCDisassembler::Success ||
            !size || size > tail.size())
            fail(rva,
                 "invalid or truncated x86 instruction [" + toHex(tail.take_front(15), true) + "]");
        auto opcode = instructions.getName(inst.getOpcode());
        steps.push_back(
            {rva, uint32_t(rva + size), std::move(inst), opcode, tail.take_front(size)});
        pos += size;
    }
    return steps;
}

constexpr std::array<StringLiteral, 7> wideRegs{"RAX", "RCX", "RDX", "R8", "R9", "R10", "R11"};
constexpr std::array<StringLiteral, 7> lowRegs{"EAX", "ECX", "EDX", "R8D", "R9D", "R10D", "R11D"};
constexpr unsigned argumentMask = (1U << 1) | (1U << 2);

// A CMP supplies a condition only to its immediate successor. A second incoming
// edge invalidates that proof. Forward edges make one definite-assignment pass sufficient.
struct Comparison {
    Value *lhs = nullptr, *rhs = nullptr;
};
struct Incoming {
    BasicBlock* block;
    unsigned defined;
    Comparison cmp;
};

class Translator {
  public:
    Translator(llvm::Module& module, uint32_t rva, bool wrapper, const MCRegisterInfo& regs)
        : ir(module.getContext()), regs(regs), wrapper(wrapper) {
        auto* type = FunctionType::get(ir.getVoidTy(), ir.getPtrTy(), false);
        impl = Function::Create(type, Function::InternalLinkage,
                                "forge_lifted_" + utohexstr(rva, true), module);
        impl->getArg(0)->setName("state");
        appendToUsed(module, {impl});
        stateType = ArrayType::get(ir.getInt64Ty(), wideRegs.size());
        if (wrapper) {
            auto* nativeType =
                FunctionType::get(ir.getInt64Ty(), {ir.getInt64Ty(), ir.getInt64Ty()}, false);
            auto* native =
                Function::Create(nativeType, Function::ExternalLinkage, "forge_lifted", module);
            ir.SetInsertPoint(BasicBlock::Create(module.getContext(), "entry", native));
            auto* state = ir.CreateAlloca(stateType);
            ir.CreateStore(native->getArg(0), slot(state, 1));
            ir.CreateStore(native->getArg(1), slot(state, 2));
            ir.CreateCall(impl, state);
            ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), slot(state, 0)));
        }
    }

    void translate(const std::vector<Step>& steps);

  private:
    IRBuilder<> ir;
    const MCRegisterInfo& regs;
    bool wrapper;
    Function* impl;
    ArrayType* stateType;
    unsigned defined = 0;

    Value* slot(Value* state, unsigned index) {
        return ir.CreateInBoundsGEP(stateType, state, {ir.getInt32(0), ir.getInt32(index)});
    }
    unsigned reg(const Step& s, const MCOperand& operand, unsigned width) const;
    Value* read(const Step& s, unsigned index, unsigned width);
    Value* value(const Step& s, const MCOperand& operand, unsigned width);
    void write(unsigned index, Value* v);
    Comparison arithmetic(const Step& s);
    void lea(const Step& s);
};

unsigned Translator::reg(const Step& s, const MCOperand& op, unsigned width) const {
    if (!op.isReg() || !op.getReg())
        s.reject("expected a general-purpose register");
    auto name = StringRef(regs.getName(op.getReg()));
    const auto& names = width == 64 ? wideRegs : lowRegs;
    auto it = llvm::find(names, name);
    if (it == names.end())
        s.reject("unsupported register " + name);
    return static_cast<unsigned>(it - names.begin());
}

Value* Translator::read(const Step& s, unsigned index, unsigned width) {
    if (wrapper && !(defined & (1U << index)))
        s.reject("native wrapper requires undefined incoming " + wideRegs[index]);
    auto* v = ir.CreateLoad(ir.getInt64Ty(), slot(impl->getArg(0), index));
    return ir.CreateTruncOrBitCast(v, ir.getIntNTy(width));
}

Value* Translator::value(const Step& s, const MCOperand& op, unsigned width) {
    if (op.isImm())
        return ConstantInt::getSigned(ir.getIntNTy(width), op.getImm());
    return read(s, reg(s, op, width), width);
}

void Translator::write(unsigned index, Value* v) {
    ir.CreateStore(ir.CreateZExtOrBitCast(v, ir.getInt64Ty()), slot(impl->getArg(0), index));
    defined |= 1U << index;
}

void Translator::lea(const Step& s) {
    unsigned width = s.opcode == "LEA64r" ? 64 : 32;
    const auto& i = s.inst;
    if (i.getOperand(5).getReg() != 0)
        s.reject("segment-relative LEA");
    Value* result = ConstantInt::getSigned(ir.getInt64Ty(), i.getOperand(4).getImm());
    for (unsigned pos : {1U, 3U}) {
        if (!i.getOperand(pos).getReg())
            continue;
        Value* term = value(s, i.getOperand(pos), 64);
        if (pos == 3)
            term = ir.CreateMul(term,
                                ConstantInt::getSigned(ir.getInt64Ty(), i.getOperand(2).getImm()));
        result = ir.CreateAdd(result, term);
    }
    write(reg(s, i.getOperand(0), width), ir.CreateTruncOrBitCast(result, ir.getIntNTy(width)));
}

Comparison Translator::arithmetic(const Step& s) {
    // Public MC instruction names allow an exact form check with packaged LLVM,
    // which does not install the generated X86 opcode and register enums.
    StringRef form = s.opcode;
    StringRef operation = form.take_while([](char c) { return c >= 'A' && c <= 'Z'; });
    form = form.drop_front(operation.size());
    unsigned width = 0;
    if (form.consume_front("64"))
        width = 64;
    else if (form.consume_front("32"))
        width = 32;
    else
        s.reject("unsupported instruction or operand width");
    const auto& i = s.inst;
    bool registerPair = form == "rr" || form == "rr_REV";
    bool registerImmediate = form == "ri" || form == "ri8" || form == "ri32";
    bool accumulatorImmediate = form == "i32"; // implicit EAX/RAX accumulator immediate
    if (operation == "MOV" && (registerPair || registerImmediate || form == "ri_alt")) {
        write(reg(s, i.getOperand(0), width), value(s, i.getOperand(1), width));
        return {};
    }
    if ((operation == "XOR" || operation == "SUB") && registerPair &&
        i.getOperand(1).getReg() == i.getOperand(2).getReg()) {
        write(reg(s, i.getOperand(0), width), ir.getIntN(width, 0));
        return {};
    }
    bool compare = operation == "CMP";
    if (!((operation == "ADD" || operation == "SUB" || compare) &&
          (registerPair || registerImmediate || accumulatorImmediate)) &&
        !(operation == "IMUL" && registerPair))
        s.reject("unsupported instruction or operand form");
    unsigned dest = accumulatorImmediate ? 0 : reg(s, i.getOperand(0), width);
    Value* lhs = read(s, dest, width);
    Value* rhs = value(s, i.getOperand(i.getNumOperands() - 1), width);
    if (compare)
        return {lhs, rhs};
    Value* result;
    if (operation == "ADD")
        result = ir.CreateAdd(lhs, rhs);
    else if (operation == "SUB")
        result = ir.CreateSub(lhs, rhs);
    else
        result = ir.CreateMul(lhs, rhs);
    write(dest, result);
    return {};
}

CmpInst::Predicate predicate(const Step& s) {
    // Intel condition-code nibble from the decoded Jcc operand.
    switch (s.inst.getOperand(1).getImm()) {
    case 2:
        return CmpInst::ICMP_ULT;
    case 3:
        return CmpInst::ICMP_UGE;
    case 4:
        return CmpInst::ICMP_EQ;
    case 5:
        return CmpInst::ICMP_NE;
    case 6:
        return CmpInst::ICMP_ULE;
    case 7:
        return CmpInst::ICMP_UGT;
    case 12:
        return CmpInst::ICMP_SLT;
    case 13:
        return CmpInst::ICMP_SGE;
    case 14:
        return CmpInst::ICMP_SLE;
    case 15:
        return CmpInst::ICMP_SGT;
    default:
        s.reject("unsupported condition code");
    }
}

void Translator::translate(const std::vector<Step>& steps) {
    std::map<uint32_t, Incoming> incoming;
    auto block = [&](uint32_t addr) {
        return BasicBlock::Create(ir.getContext(), "rva_" + utohexstr(addr, true), impl);
    };
    incoming.emplace(steps.front().rva, Incoming{block(steps.front().rva), argumentMask, {}});
    for (const Step& s : steps) {
        auto it = incoming.find(s.rva);
        if (it == incoming.end())
            continue;
        ir.SetInsertPoint(it->second.block);
        defined = it->second.defined;
        auto edge = [&](int64_t address, Comparison cmp = {}) {
            if (address <= s.rva || address >= steps.back().next)
                s.reject("backward edge or control flow outside function to " +
                         hex(static_cast<uint64_t>(address)));
            auto target =
                std::lower_bound(steps.begin(), steps.end(), address,
                                 [](const Step& step, int64_t addr) { return step.rva < addr; });
            if (target == steps.end() || target->rva != address)
                s.reject("branch enters an instruction at " + hex(static_cast<uint64_t>(address)));
            auto [dest, added] = incoming.try_emplace(target->rva);
            if (added)
                dest->second = {block(target->rva), defined, cmp};
            else {
                dest->second.defined &= defined;
                dest->second.cmp = {};
            }
            return dest->second.block;
        };
        auto bytes = arrayRefFromStringRef(s.bytes);
        uint8_t first = bytes.front();
        if (legacyPrefix(first) || ((first & 0xf0) == 0x40 && bytes.size() > 1 &&
                                    (legacyPrefix(bytes[1]) || (bytes[1] & 0xf0) == 0x40)))
            s.reject("unsupported instruction prefix");
        if (s.opcode == "RET64") {
            if (wrapper && !(defined & 1U))
                s.reject("return with undefined RAX");
            ir.CreateRetVoid();
        } else if (s.opcode == "JMP_1" || s.opcode == "JMP_4") {
            ir.CreateBr(edge(int64_t(s.next) + s.inst.getOperand(0).getImm()));
        } else if (s.opcode == "JCC_1" || s.opcode == "JCC_4") {
            auto cmp = it->second.cmp;
            if (!cmp.lhs)
                s.reject("condition flags require an immediately preceding CMP on every path");
            auto* cond = ir.CreateICmp(predicate(s), cmp.lhs, cmp.rhs);
            auto* taken = edge(int64_t(s.next) + s.inst.getOperand(0).getImm());
            ir.CreateCondBr(cond, taken, edge(s.next));
        } else {
            Comparison cmp;
            if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r")
                lea(s);
            else
                cmp = arithmetic(s);
            ir.CreateBr(edge(s.next, cmp));
        }
    }
}

void publish(const llvm::Module& module, const fs::path& path) {
    SmallString<128> temporary;
    int fd;
    if (auto ec = sys::fs::createUniqueFile(path.string() + ".tmp-%%%%%%", fd, temporary))
        throw InspectionError(ec.message(), "OUTPUT_ERROR");
    ToolOutputFile file(temporary, fd);
    auto& stream = file.os();
    module.print(stream, nullptr);
    stream.close();
    if (stream.has_error()) {
        auto error = stream.error();
        stream.clear_error();
        throw InspectionError(error.message(), "OUTPUT_ERROR");
    }
    if (auto ec = sys::fs::rename(temporary, path.native()))
        throw InspectionError(ec.message(), "OUTPUT_ERROR");
    file.keep();
}
} // namespace

void lift(const Analysis& a, MemoryBufferRef buffer, uint32_t rva, bool wrapper,
          const fs::path& output) {
    if (a.module.dll)
        fail(rva, "DLL lifting is unsupported");
    auto it = llvm::lower_bound(a.functions, rva,
                                [](const auto& f, uint32_t addr) { return f.record.begin < addr; });
    while (it != a.functions.end() && it->record.begin == rva && (it->invalid || it->overlapGroup))
        ++it;
    if (it == a.functions.end() || it->record.begin != rva)
        fail(rva, "expected an exact, valid, unambiguous discovered function start");
    if (const auto version = it->unsupportedUnwindVersion)
        fail(rva, "unsupported unwind version " + Twine(*version));
    if (it->chainedFragment)
        fail(rva, "chained unwind fragment has no independent function entry");
    const auto& f = it->record;
    auto size = f.end - f.begin;
    auto code = mapRva(a.module.sections, buffer.getBuffer(), rva, size);
    if (!code)
        fail(rva, "function bytes outside file-backed sections");
    for (const auto& b : a.module.relocations)
        for (const auto& rel : b.entries) {
            if (!rel.type)
                continue; // ABSOLUTE is padding
            unsigned width =
                rel.type == 3 ? 4 : (rel.type == 1 || rel.type == 2 || rel.type == 4 ? 2 : 8);
            if (rel.rva < f.end && uint64_t(rel.rva) + width > rva)
                fail(rva, "function bytes overlap base relocation at " + hex(rel.rva));
        }

    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86TargetMC();
    LLVMInitializeX86Disassembler();
    Triple triple("x86_64-pc-windows-msvc");
    std::string error;
    const auto* target = TargetRegistry::lookupTarget(triple.str(), error);
    if (!target)
        fail(rva, error);
    std::unique_ptr<MCRegisterInfo> regs(target->createMCRegInfo(triple.str()));
    std::unique_ptr<MCInstrInfo> instructions(target->createMCInstrInfo());
    std::unique_ptr<MCSubtargetInfo> sub(
        target->createMCSubtargetInfo(triple.str(), "generic", ""));
    std::unique_ptr<MCAsmInfo> assembly(
        target->createMCAsmInfo(*regs, triple.str(), MCTargetOptions()));
    MCContext mc(triple, assembly.get(), regs.get(), sub.get());
    std::unique_ptr<MCDisassembler> dis(target->createMCDisassembler(*sub, mc));
    auto steps = decode(code->bytes, rva, *dis, *instructions);
    LLVMContext context;
    llvm::Module module("forge_" + utohexstr(rva, true), context);
    module.setTargetTriple("arm64-apple-macosx11.0.0");
    Translator(module, rva, wrapper, *regs).translate(steps);
    raw_string_ostream errors(error);
    if (verifyModule(module, &errors))
        fail(rva, "LLVM verifier: " + errors.str());
    publish(module, output);
}
} // namespace forge
