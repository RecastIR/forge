#include "analysis/analysis.h"
#include "lift/integer.h"

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
constexpr std::array<StringLiteral, 7> words{"AX", "CX", "DX", "R8W", "R9W", "R10W", "R11W"};
constexpr std::array<StringLiteral, 7> lowBytes{"AL", "CL", "DL", "R8B", "R9B", "R10B", "R11B"};
constexpr std::array<StringLiteral, 3> highBytes{"AH", "CH", "DH"};
// The signatureless ABI accepts a four-byte-aligned register array.
constexpr auto registerStateAlignment = Align::Constant<4>();
struct RegisterView {
    unsigned index, width, offset = 0;
    uint64_t mask() const { return maskTrailingOnes<uint64_t>(width) << offset; }
};
using Defined = std::array<uint64_t, wideRegs.size()>;
struct Incoming {
    BasicBlock* block;
    Defined defined;
    std::vector<std::pair<BasicBlock*, x86::Flags>> predecessors;
};

// All predecessors are known when a reachable forward target is visited.
x86::Flags mergeFlags(IRBuilder<>& ir, const Incoming& incoming) {
    const auto& predecessors = incoming.predecessors;
    x86::Flags flags{};
    for (unsigned f = 0; f < x86::FlagCount && !predecessors.empty(); ++f) {
        auto* first = predecessors.front().second[f];
        if (!first || llvm::any_of(predecessors, [&](const auto& p) { return !p.second[f]; }))
            continue;
        if (llvm::all_of(predecessors, [&](const auto& p) { return p.second[f] == first; })) {
            flags[f] = first;
        } else {
            auto* phi = ir.CreatePHI(ir.getInt1Ty(), static_cast<unsigned>(predecessors.size()));
            for (const auto& [source, incomingFlags] : predecessors)
                phi->addIncoming(incomingFlags[f], source);
            flags[f] = phi;
        }
    }
    return flags;
}

class Translator {
  public:
    Translator(llvm::Module& module, uint32_t rva, bool wrapper, const MCRegisterInfo& regs)
        : ir(module.getContext()), semantics(ir), regs(regs), wrapper(wrapper) {
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
            // Backing bits for partial writes must be concrete. Read eligibility is
            // proved separately, so these zeros are never exposed as incoming values.
            ir.CreateStore(ConstantAggregateZero::get(stateType), state);
            ir.CreateStore(native->getArg(0), slot(state, 1));
            ir.CreateStore(native->getArg(1), slot(state, 2));
            ir.CreateCall(impl, state);
            ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), slot(state, 0)));
        }
    }

    void translate(const std::vector<Step>& steps);

  private:
    IRBuilder<> ir;
    x86::IntegerSemantics semantics;
    const MCRegisterInfo& regs;
    bool wrapper;
    Function* impl;
    ArrayType* stateType;
    Defined defined{};

    Value* slot(Value* state, unsigned index) {
        return ir.CreateInBoundsGEP(stateType, state, {ir.getInt32(0), ir.getInt32(index)});
    }
    RegisterView reg(const Step& s, const MCOperand& operand, unsigned width) const;
    Value* read(const Step& s, RegisterView view);
    Value* value(const Step& s, const MCOperand& operand, unsigned width);
    void write(RegisterView view, Value* v);
    Value* require(const Step& s, x86::Flag flag) const;
    Value* condition(const Step& s);
    void integer(const Step& s, const x86::IntegerInstruction& instruction);
    void lower(const Step& s);
    void lea(const Step& s);
};

RegisterView Translator::reg(const Step& s, const MCOperand& op, unsigned width) const {
    if (!op.isReg() || !op.getReg())
        s.reject("expected a general-purpose register");
    auto name = StringRef(regs.getName(op.getReg()));
    const auto& names = width == 64   ? wideRegs
                        : width == 32 ? lowRegs
                        : width == 16 ? words
                                      : lowBytes;
    auto it = llvm::find(names, name);
    if (it != names.end())
        return {static_cast<unsigned>(it - names.begin()), width};
    if (width == 8) {
        auto high = llvm::find(highBytes, name);
        if (high != highBytes.end())
            return {static_cast<unsigned>(high - highBytes.begin()), 8, 8};
    }
    s.reject("unsupported register " + name);
}

Value* Translator::read(const Step& s, RegisterView view) {
    if ((defined[view.index] & view.mask()) != view.mask())
        s.reject("native wrapper requires undefined incoming " + wideRegs[view.index]);
    Value* v = ir.CreateAlignedLoad(ir.getInt64Ty(), slot(impl->getArg(0), view.index),
                                    registerStateAlignment);
    if (view.offset)
        v = ir.CreateLShr(v, view.offset);
    return ir.CreateTruncOrBitCast(v, ir.getIntNTy(view.width));
}

Value* Translator::value(const Step& s, const MCOperand& op, unsigned width) {
    if (op.isImm())
        return ConstantInt::getSigned(ir.getIntNTy(width), op.getImm());
    return read(s, reg(s, op, width));
}

void Translator::write(RegisterView view, Value* v) {
    auto* ptr = slot(impl->getArg(0), view.index);
    auto* result = ir.CreateZExtOrBitCast(v, ir.getInt64Ty());
    if (view.width < 32) {
        auto* parent = ir.CreateAlignedLoad(ir.getInt64Ty(), ptr, registerStateAlignment);
        result = ir.CreateOr(ir.CreateAnd(parent, ~view.mask()), ir.CreateShl(result, view.offset));
        defined[view.index] |= view.mask();
    } else {
        defined[view.index] = UINT64_MAX;
    }
    ir.CreateAlignedStore(result, ptr, registerStateAlignment);
}

Value* Translator::require(const Step& s, x86::Flag flag) const {
    if (!semantics.flags[flag])
        s.reject("unsupported use of undefined condition flags: " + x86::flagNames[flag]);
    return semantics.flags[flag];
}

Value* Translator::condition(const Step& s) {
    auto code = s.inst.getOperand(s.inst.getNumOperands() - 1).getImm();
    if (code < 0 || code > 15)
        s.reject("unsupported condition code");
    return semantics.condition(static_cast<unsigned>(code),
                               [&](x86::Flag f) { return require(s, f); });
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

void Translator::integer(const Step& s, const x86::IntegerInstruction& instruction) {
    using x86::Form;
    using x86::Op;
    auto [op, form, width, sourceWidth] = instruction;
    const auto& i = s.inst;
    auto dest = form == Form::Accumulator ? RegisterView{0, width} : reg(s, i.getOperand(0), width);
    const auto& last = i.getOperand(i.getNumOperands() - 1);
    if (op == Op::Mov || form == Form::Extend) {
        write(dest,
              ir.CreateIntCast(value(s, last, sourceWidth), ir.getIntNTy(width), op == Op::Movsx));
        return;
    }
    if (form == Form::ShiftCL || form == Form::ShiftOne || form == Form::ShiftImmediate) {
        auto* count =
            form == Form::ShiftCL
                ? read(s, {1, 8})
                : ir.getInt8(form == Form::ShiftOne ? 1 : static_cast<uint8_t>(last.getImm()));
        write(dest, semantics.shift(op, read(s, dest), count));
        return;
    }
    // Equal operands cancel even if the guest register has no incoming value.
    // SBB still subtracts CF, and CMP only updates flags.
    bool cancel = (op == Op::Xor || op == Op::Sub || op == Op::Cmp || op == Op::Sbb) &&
                  form == Form::Pair && i.getOperand(0).getReg() == last.getReg();
    Value* lhs = cancel ? ir.getIntN(width, 0) : read(s, dest);
    Value* rhs = nullptr;
    if (form != Form::Reg)
        rhs = cancel ? lhs : value(s, last, width);
    if (op == Op::Adc || op == Op::Sbb)
        require(s, x86::CF);
    auto* result = semantics.arithmetic(op, lhs, rhs);
    if (op != Op::Cmp && op != Op::Test)
        write(dest, result);
}

void Translator::lower(const Step& s) {
    if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
        lea(s);
    } else if (s.opcode == "SETCCr") {
        write(reg(s, s.inst.getOperand(0), 8), ir.CreateZExt(condition(s), ir.getInt8Ty()));
    } else if (s.opcode == "CMOV16rr" || s.opcode == "CMOV32rr" || s.opcode == "CMOV64rr") {
        unsigned width = s.opcode == "CMOV16rr" ? 16 : s.opcode == "CMOV32rr" ? 32 : 64;
        auto dest = reg(s, s.inst.getOperand(0), width);
        auto* old = read(s, dest);
        auto* src = value(s, s.inst.getOperand(2), width);
        write(dest, ir.CreateSelect(condition(s), src, old));
    } else if (s.opcode == "LAHF") {
        Value* byte = ir.getInt8(2);
        for (auto [flag, bit] :
             {std::pair{x86::SF, 7U}, {x86::ZF, 6U}, {x86::AF, 4U}, {x86::PF, 2U}, {x86::CF, 0U}}) {
            byte = ir.CreateOr(byte,
                               ir.CreateShl(ir.CreateZExt(require(s, flag), ir.getInt8Ty()), bit));
        }
        write({0, 8, 8}, byte);
    } else if (auto instruction = x86::integerInstruction(s.opcode)) {
        integer(s, *instruction);
    } else {
        s.reject("unsupported instruction or operand form");
    }
}

void Translator::translate(const std::vector<Step>& steps) {
    std::map<uint32_t, Incoming> incoming;
    auto block = [&](uint32_t addr) {
        return BasicBlock::Create(ir.getContext(), "rva_" + utohexstr(addr, true), impl);
    };
    Defined entry{};
    if (!wrapper)
        entry.fill(UINT64_MAX);
    entry[1] = entry[2] = UINT64_MAX;
    incoming.emplace(steps.front().rva, Incoming{block(steps.front().rva), entry, {}});
    for (const Step& s : steps) {
        auto it = incoming.find(s.rva);
        if (it == incoming.end())
            continue;
        ir.SetInsertPoint(it->second.block);
        defined = it->second.defined;
        semantics.flags = mergeFlags(ir, it->second);
        auto edge = [&](int64_t address) {
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
                dest->second = {block(target->rva), defined, {}};
            else {
                for (size_t j = 0; j < defined.size(); ++j)
                    dest->second.defined[j] &= defined[j];
            }
            dest->second.predecessors.emplace_back(ir.GetInsertBlock(), semantics.flags);
            return dest->second.block;
        };
        auto encoding = arrayRefFromStringRef(s.bytes);
        if (encoding.front() == 0x66) {
            auto instruction = x86::integerInstruction(s.opcode);
            if ((!instruction || instruction->width != 16) && s.opcode != "CMOV16rr")
                s.reject("unsupported instruction prefix");
            encoding = encoding.drop_front();
        }
        if (!encoding.empty() && (encoding.front() & 0xf0) == 0x40)
            encoding = encoding.drop_front();
        if (encoding.empty() || legacyPrefix(encoding.front()) || (encoding.front() & 0xf0) == 0x40)
            s.reject("unsupported instruction prefix");
        if (s.opcode == "RET64") {
            if (wrapper && defined[0] != UINT64_MAX)
                s.reject("return with undefined RAX");
            ir.CreateRetVoid();
        } else if (s.opcode == "JMP_1" || s.opcode == "JMP_4") {
            ir.CreateBr(edge(int64_t(s.next) + s.inst.getOperand(0).getImm()));
        } else if (s.opcode == "JCC_1" || s.opcode == "JCC_4") {
            auto* cond = condition(s);
            auto* taken = edge(int64_t(s.next) + s.inst.getOperand(0).getImm());
            ir.CreateCondBr(cond, taken, edge(s.next));
        } else {
            lower(s);
            ir.CreateBr(edge(s.next));
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
    const auto* target = TargetRegistry::lookupTarget(triple, error);
    if (!target)
        fail(rva, error);
    std::unique_ptr<MCRegisterInfo> regs(target->createMCRegInfo(triple));
    std::unique_ptr<MCInstrInfo> instructions(target->createMCInstrInfo());
    std::unique_ptr<MCSubtargetInfo> sub(target->createMCSubtargetInfo(triple, "generic", ""));
    std::unique_ptr<MCAsmInfo> assembly(target->createMCAsmInfo(*regs, triple, MCTargetOptions()));
    MCContext mc(triple, *assembly, *regs, *sub);
    std::unique_ptr<MCDisassembler> dis(target->createMCDisassembler(*sub, mc));
    auto steps = decode(code->bytes, rva, *dis, *instructions);
    LLVMContext context;
    llvm::Module module("forge_" + utohexstr(rva, true), context);
    Triple nativeTriple("arm64-apple-macosx11.0.0");
    module.setTargetTriple(nativeTriple);
    module.setDataLayout(nativeTriple.computeDataLayout());
    Translator(module, rva, wrapper, *regs).translate(steps);
    raw_string_ostream errors(error);
    if (verifyModule(module, &errors))
        fail(rva, "LLVM verifier: " + errors.str());
    publish(module, output);
}
} // namespace forge
