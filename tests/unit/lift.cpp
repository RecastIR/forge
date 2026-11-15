#include "lift/lift.h"
#include "analysis/analysis.h"
#include "diagnostic.h"
#include "lift/address_fact.h"
#include "output/publication.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"

#include <fstream>
#include <map>
#include <set>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {
    using namespace forge;

    static_assert(!std::is_copy_constructible_v<AnalyzedImage> &&
                  !std::is_move_constructible_v<AnalyzedImage>);

    void check(bool condition, const char *message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    void checkAddressAlternatives() {
        using x86::AddressFact;
        constexpr uint64_t high = uint64_t{1} << 63;
        const uint64_t expected[] = {0, 1, 4, 5, high, high + 1, high + 4, high + 5};
        const auto bounded = AddressFact{}.masked(high | 5);
        check(bounded.values() == llvm::ArrayRef(expected), "lost a sparse masked index");
        check(bounded.join(AddressFact(5)) == bounded, "duplicate widened an exact address set");
        check(!bounded.join(AddressFact(6)).known() && !AddressFact{}.masked(high | 7).known(),
              "truncated an over-cap address set");
        check(!bounded.join(AddressFact{}).known(), "discarded an unknown predecessor");
        check(AddressFact(UINT64_MAX).plus(AddressFact(1)) == AddressFact(0),
              "guest address arithmetic did not wrap");

        const AddressFact stack(x86::GuestMemory::entryRsp, AddressFact::Stack);
        const auto immediate = AddressFact(UINT32_MAX).plus(AddressFact(2)).masked(UINT32_MAX);
        check(immediate == AddressFact(1).computed() && !stack.plus(immediate).stackDerived(),
              "32-bit arithmetic lost zero extension or acquired a stack-only origin");
        check(stack.plus(AddressFact(17).times(0)).stackDerived() &&
                  !stack.plus(stack.times(0)).stackDerived(),
              "self-subtraction changed its legacy stack proof");
    }

    void checkSpillSnapshots() {
        using x86::AddressFact;
        using x86::StackSpills;
        const AddressFact first(x86::GuestMemory::base);
        const auto second = first.plus(AddressFact(8));
        StackSpills entry;
        for (unsigned slot = 0; slot < 500; ++slot) {
            entry.write(first.plus(AddressFact(8 * slot)), 64, AddressFact(slot));
        }

        const auto *original = entry.find(x86::GuestMemory::base);
        check(original && *original == AddressFact(0).computed(), "missing initial spill");
        std::vector<StackSpills> successors;
        successors.reserve(4800);
        for (unsigned block = 0; block < 4800; ++block) {
            auto &snapshot = successors.emplace_back(entry);
            snapshot.write(first, 64, AddressFact(0));
            snapshot.write(first.plus(AddressFact(4000)), 8, AddressFact{});
            check(!snapshot.merge(entry) && snapshot.find(x86::GuestMemory::base) == original,
                  "an unchanged spill snapshot copied its entries");
        }

        auto &branch = successors.front();
        branch.write(first, 64, AddressFact(17));
        check(branch.read(first) == AddressFact(17).computed() &&
                  entry.read(first) == AddressFact(0).computed(),
              "spill overwrite changed an earlier snapshot");

        auto &join = successors.back();
        const auto choices = AddressFact(0).join(AddressFact(17));
        check(join.merge(branch) && join.read(first) == choices &&
                  entry.read(first) == AddressFact(0).computed(),
              "changed join lost a target or modified a sibling");

        branch.write(first, 64, AddressFact(0));
        check(!entry.merge(branch) && entry.find(x86::GuestMemory::base) == original,
              "equal independent spill snapshots caused a detach");
        branch.write(first.plus(AddressFact(7)), 16, AddressFact{});
        check(!branch.read(first).known() && !branch.read(second).known() &&
                  entry.read(second) == AddressFact(1).computed(),
              "partial overlapping write damaged a shared predecessor");
        auto &cleared = successors[1];
        cleared.write(AddressFact{}, 64, AddressFact{});
        check(!cleared.read(first).known() && entry.read(second) == AddressFact(1).computed(),
              "unknown write cleared another branch");
    }

    void checkAlias(const llvm::Module &module, const ParsedImage &image, const fs::path &path) {
        try {
            publishIR(module, image, path);
            throw std::runtime_error("publisher accepted an input alias");
        } catch (const InspectionError &error) {
            check(error.kind == FailureCode::OutputAlias && error.context.output == path &&
                      error.context.input == image.module().path,
                  "input alias lost its publication diagnostic");
        }
    }

    std::unique_ptr<llvm::Module> checkSnapshot(const fs::path &fixture, const fs::path &directory,
                                                llvm::LLVMContext &context) {
        const auto source = directory / "input.exe";
        const auto original = directory / "original.exe";
        const auto output = directory / "function.ll";
        fs::copy_file(fixture, source);
        auto parsed =
            std::make_unique<ParsedImage>(InputFile(source), ParsePolicy::FunctionAnalysis);
        fs::rename(source, original);
        fs::resize_file(original, 0);
        fs::copy_file(original, source);
        AnalyzedImage analysis(std::move(parsed), DebugInfo::Enrich);
        constexpr uint32_t start = 0x1000;
        check(analysis.functions().size() == 1 && analysis.functions()[0].record.begin == start &&
                  analysis.functions()[0].eligible(),
              "analysis failed to discover the original function");

        try {
            generateIR(analysis, {start + 1, EntryMode::RegisterState}, context);
            throw std::runtime_error("accepted an interior RVA");
        } catch (const InspectionError &error) {
            check(error.kind == FailureCode::InvalidEntry && error.context.input == source &&
                      error.context.entryRva == start + 1,
                  "selection failure lost the requested image or RVA");
        }

        auto body = generateIR(analysis, {start, EntryMode::RegisterState}, context);
        auto *function = body->getFunction("forge_lifted_1000");
        check(function && function->hasInternalLinkage() && function->getReturnType()->isVoidTy() &&
                  function->arg_size() == 1 && function->getArg(0)->getType()->isPointerTy() &&
                  !body->getFunction("forge_lifted"),
              "unexpected register-state entry ABI");
        check(!llvm::verifyModule(*body) && !fs::exists(output),
              "in-memory state entry failed verification or published output");

        auto module = generateIR(analysis, {start, EntryMode::WindowsX64I64Pair}, context);
        auto *wrapper = module->getFunction("forge_lifted");
        check(wrapper && wrapper->hasExternalLinkage() &&
                  wrapper->getReturnType()->isIntegerTy(64) && wrapper->arg_size() == 2 &&
                  wrapper->getArg(0)->getType()->isIntegerTy(64) &&
                  wrapper->getArg(1)->getType()->isIntegerTy(64),
              "unexpected native wrapper ABI");
        check(module->getTargetTriple().str() == "arm64-apple-macosx11.0.0" &&
                  module->getDataLayoutStr() == module->getTargetTriple().computeDataLayout(),
              "incorrect output triple or data layout");

        checkAlias(*module, analysis.image(), source);
        checkAlias(*module, analysis.image(), original);
        fs::remove(source);
        checkAlias(*module, analysis.image(), source);
        const auto alias = directory / "alias";
        fs::create_directory_symlink(directory, alias);
        checkAlias(*module, analysis.image(), alias / source.filename());
        publishIR(*module, analysis.image(), output);
        check(fs::is_regular_file(output) && fs::file_size(output) > 0,
              "verified module was not published");

        return module;
    }

    void checkImageConstants(const fs::path &fixture, const fs::path &directory,
                             llvm::LLVMContext &context) {
        const auto path = directory / "image.exe";
        fs::copy_file(fixture, path);
        std::unique_ptr<llvm::Module> module;
        {
            AnalyzedImage analysis(
                std::make_unique<ParsedImage>(InputFile(path), ParsePolicy::Inspection),
                DebugInfo::Omit);
            fs::remove(path);
            auto symbol = llvm::find_if(analysis.module().exports, [](const Export &item) {
                return llvm::is_contained(item.names, "direct32");
            });
            check(symbol != analysis.module().exports.end(), "missing image-data export");
            LiftRequest request{symbol->rva, EntryMode::WindowsX64I64Pair};
            module = generateIR(analysis, request, context);
            auto second = generateIR(analysis, request, context);
            std::string firstIR, secondIR;
            llvm::raw_string_ostream(firstIR) << *module;
            llvm::raw_string_ostream(secondIR) << *second;
            check(firstIR == secondIR, "image globals changed between lifts");
        }

        check(!llvm::verifyModule(*module), "image module lost its backing storage");
        unsigned globals = 0;
        for (const auto &global : module->globals()) {
            if (global.getName().starts_with("image_")) {
                const auto *bytes =
                    llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
                check(global.isConstant() && bytes &&
                          bytes->getRawDataValues() == "\x34\x56\x78\x9a",
                      "direct read did not retain exactly its four PE bytes");
                ++globals;
            }
        }

        check(globals == 1, "direct read embedded unrelated PE contents");
    }

    void checkRelativePublication(const fs::path &fixture, const fs::path &directory,
                                  const llvm::Module &module) {
        const auto source = directory / "opened";
        const auto other = directory / "other";
        fs::create_directories(source / "child");
        fs::create_directory(other);
        fs::copy_file(fixture, source / "app.exe");
        fs::create_directory_symlink(source / "child", other / "link");
        const auto previous = fs::current_path();
        llvm::scope_exit restore([&] { fs::current_path(previous); });
        fs::current_path(directory);

        const fs::path spelling("other/link/../app.exe");
        InputFile file(spelling);
        fs::current_path(other);
        ParsedImage image(file, ParsePolicy::FunctionAnalysis);
        check(image.module().path == spelling, "lost input spelling");

        const auto replacement = source / "app.exe";
        fs::rename(replacement, source / "original.exe");
        fs::create_hard_link(source / "original.exe", "hard");
        fs::create_symlink(replacement, "sym");
        std::ofstream(replacement) << "sentinel";

        checkAlias(module, image, replacement);
        checkAlias(module, image, "link/../app.exe");
        checkAlias(module, image, "hard");
        checkAlias(module, image, "sym");
        std::string content;
        std::ifstream(replacement) >> content;
        check(content == "sentinel", "publication replaced the input name");
        publishIR(module, image, "app.exe");
        check(fs::file_size(other / "app.exe") > 0, "unrelated relative output missing");
    }

    void checkControlFlow(const fs::path &fixture) {
        AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(fixture), ParsePolicy::FunctionAnalysis),
            DebugInfo::Omit);
        llvm::LLVMContext context;
        auto module = generateIR(analysis, {0x1000, EntryMode::WindowsX64I64Pair}, context);
        const auto &body = *module->getFunction("forge_guest_1000");
        // Synthetic entry, setup, header, sign test, two latches, two returns.
        const std::map<std::string, std::vector<std::string>> expected{
            {"entry", {"rva_1000"}},
            {"rva_1000", {"rva_1017", "rva_1007"}},
            {"rva_1007", {"rva_1016", "rva_100d"}},
            {"rva_100d", {"rva_1011", "rva_100f"}},
            {"rva_100f", {"rva_1007"}},
            {"rva_1011", {"rva_1007"}},
            {"rva_1016", {}},
            {"rva_1017", {}}};
        std::map<std::string, std::vector<std::string>> edges;
        for (const auto &block : body) {
            auto &targets = edges[block.getName().str()];
            const auto *term = block.getTerminator();
            check(term != nullptr, "guest block lacks a terminator");
            for (unsigned i = 0; i < term->getNumSuccessors(); ++i) {
                targets.push_back(term->getSuccessor(i)->getName().str());
            }

            if (targets.empty()) {
                check(llvm::isa<llvm::ReturnInst>(term), "expected a guest return site");
            }

            if (block.getName() == "rva_1007") {
                const auto &carry = llvm::cast<llvm::PHINode>(block.front());
                check(carry.getName().starts_with("CF") && carry.getNumIncomingValues() == 3,
                      "loop header lost its entry carry or a backedge");
            }
        }

        check(edges == expected, "incorrect basic-block boundaries or successors");
    }

    void checkEntryBackedge(const llvm::BasicBlock &entry, const llvm::BasicBlock &header) {
        const auto *branch = llvm::dyn_cast<llvm::CondBrInst>(header.getTerminator());
        check(branch && llvm::pred_size(&header) == 2, "entry loop must have two predecessors");
        const auto *latch = branch->getSuccessor(1);
        check(llvm::isa<llvm::ReturnInst>(branch->getSuccessor(0)->getTerminator()) &&
                  llvm::isa<llvm::UncondBrInst>(latch->getTerminator()) &&
                  latch->getTerminator()->getSuccessor(0) == &header &&
                  llvm::is_contained(llvm::predecessors(&header), &entry),
              "entry loop lost its exit, synthetic entry, or backedge");
    }

    void checkIdenticalSuccessors(const llvm::BasicBlock &source) {
        const auto *branch = llvm::dyn_cast<llvm::CondBrInst>(source.getTerminator());
        check(branch && branch->getSuccessor(0) == branch->getSuccessor(1),
              "conditional branch lost its parallel edges");
        const auto *join = branch->getSuccessor(0);
        bool usesCarry = false;
        bool usesZero = false;

        for (const auto &phi : join->phis()) {
            check(phi.getNumIncomingValues() == 2 && phi.getIncomingBlock(0) == &source &&
                      phi.getIncomingBlock(1) == &source &&
                      phi.getIncomingValue(0) == phi.getIncomingValue(1),
                  "flag PHI must receive the same value on each parallel edge");
            usesCarry |= phi.getName() == "CF" && !phi.use_empty();
            usesZero |= phi.getName() == "ZF" && !phi.use_empty();
        }

        check(usesCarry && usesZero, "successor must consume both carry and zero PHIs");
    }

    void checkControlFlowLeaves(const fs::path &fixture) {
        AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(fixture), ParsePolicy::Inspection),
            DebugInfo::Omit);
        llvm::LLVMContext context;

        for (std::string_view name :
             {"cfg_entry_backedge", "cfg_identical_successors", "cfg_partial_join"}) {
            const auto &exports = analysis.module().exports;
            const auto symbol = llvm::find_if(
                exports, [&](const Export &item) { return llvm::is_contained(item.names, name); });
            check(symbol != exports.end(), "missing CFG regression export");
            auto module =
                generateIR(analysis, {symbol->rva, EntryMode::WindowsX64I64Pair}, context);
            const auto *body =
                module->getFunction("forge_guest_" + llvm::utohexstr(symbol->rva, true));
            check(body && !llvm::verifyModule(*module), "CFG regression failed LLVM verification");
            const auto &entry = body->getEntryBlock();
            const auto *start = llvm::dyn_cast<llvm::UncondBrInst>(entry.getTerminator());
            check(start != nullptr, "missing synthetic entry branch");

            if (name == "cfg_entry_backedge") {
                checkEntryBackedge(entry, *start->getSuccessor());
            } else if (name == "cfg_identical_successors") {
                checkIdenticalSuccessors(*start->getSuccessor());
            } else {
                const auto *branch =
                    llvm::dyn_cast<llvm::CondBrInst>(start->getSuccessor()->getTerminator());
                check(branch != nullptr, "partial register writes must branch");
                const auto *left =
                    llvm::dyn_cast<llvm::UncondBrInst>(branch->getSuccessor(0)->getTerminator());
                const auto *right =
                    llvm::dyn_cast<llvm::UncondBrInst>(branch->getSuccessor(1)->getTerminator());
                check(left && right && left != right &&
                          left->getSuccessor() == right->getSuccessor() &&
                          llvm::isa<llvm::ReturnInst>(left->getSuccessor()->getTerminator()),
                      "partial register return must join both writing paths");
            }
        }
    }

    uint32_t exportedRva(const AnalyzedImage &analysis, llvm::StringRef name) {
        const auto &exports = analysis.module().exports;
        auto symbol = llvm::find_if(
            exports, [&](const Export &item) { return llvm::is_contained(item.names, name); });
        check(symbol != exports.end(), "missing direct-call fixture export");
        return symbol->rva;
    }

    std::string moduleText(const llvm::Module &module) {
        std::string text;
        llvm::raw_string_ostream output(text);
        module.print(output, nullptr);
        return text;
    }

    void checkDirectCalls(const fs::path &fixture) {
        AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(fixture), ParsePolicy::Inspection),
            DebugInfo::Omit);
        llvm::LLVMContext context;

        struct Pair {
            llvm::StringRef caller, callee;
            unsigned count;
        };

        for (const Pair pair : {Pair{"call_preserves_carry", "call_result", 2},
                                Pair{"call_stack_argument", "call_fifth", 1}}) {
            const uint32_t rva = exportedRva(analysis, pair.caller);
            const LiftRequest request{rva, EntryMode::WindowsX64I64Pair};
            const auto module = generateIR(analysis, request, context);
            const auto suffix = llvm::utohexstr(rva, true);
            const auto *caller = module->getFunction("forge_guest_" + suffix);
            const auto *callee = module->getFunction(
                "forge_guest_" + llvm::utohexstr(exportedRva(analysis, pair.callee), true));
            const auto *adapter = module->getFunction("forge_lifted_" + suffix);
            check(caller && callee && adapter && module->getFunction("forge_lifted"),
                  "missing guest body or selected entry adapter");
            unsigned bodies = 0, adapters = 0, calls = 0, invocations = 0;

            for (const auto &function : *module) {
                bodies += function.getName().starts_with("forge_guest_");
                adapters += function.getName().starts_with("forge_lifted_");

                for (const auto &instruction : llvm::instructions(function)) {
                    if (const auto *allocation = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) {
                        if (allocation->getAllocatedType()->isStructTy()) {
                            check(&function == adapter, "guest body allocated an invocation");
                            ++invocations;
                        }
                    }

                    const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);

                    if (call && call->getCalledFunction() == callee) {
                        check(&function == caller && call->arg_size() == 1 &&
                                  call->getArgOperand(0) == caller->getArg(0),
                              "callee received a separate invocation context");
                        ++calls;
                    }
                }
            }

            check(caller->hasInternalLinkage() && callee->hasInternalLinkage() && bodies == 2 &&
                      adapters == 1 && invocations == 1 && calls == pair.count,
                  "wrong number of bodies, adapters, invocation allocations, or direct calls");
            const auto repeated = generateIR(analysis, request, context);
            check(moduleText(*repeated) == moduleText(*module),
                  "repeated generation changed the linked guest module");
        }
    }

    void checkVerifierFailure(llvm::LLVMContext &context, const fs::path &source) {
        llvm::Module module("invalid", context);
        auto *type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
        auto *function =
            llvm::Function::Create(type, llvm::Function::ExternalLinkage, "invalid", module);
        llvm::BasicBlock::Create(context, "no_terminator", function);

        try {
            verifyLiftedIR(module, source, 0x1000);
            throw std::runtime_error("accepted an unterminated IR block");
        } catch (const InspectionError &error) {
            const auto &kind = failureKind(error.kind);
            check(error.kind == FailureCode::VerificationFailed &&
                      std::string_view(kind.category) == "internal" &&
                      std::string_view(kind.stage) == "verification" &&
                      error.context.input == source && error.context.entryRva == 0x1000,
                  "verifier failure lost its stage, category or provenance");
        }
    }

    // The native image suite compiles this output with both LLVM pipelines. Printing
    // after analysis destruction also exercises the returned module's ownership.
    void emitRebased(const fs::path &path, llvm::StringRef entry, llvm::StringRef base) {
        uint32_t rva;
        uint64_t guestBase;
        check(!entry.getAsInteger(0, rva) && !base.getAsInteger(0, guestBase),
              "invalid rebase test arguments");
        llvm::LLVMContext context;
        std::unique_ptr<llvm::Module> module;
        {
            AnalyzedImage analysis(
                std::make_unique<ParsedImage>(InputFile(path), ParsePolicy::FunctionAnalysis),
                DebugInfo::Omit);
            module = generateIR(analysis, {rva, EntryMode::WindowsX64I64Pair, guestBase}, context);
        }

        check(!llvm::verifyModule(*module), "rebased module lost its backing storage");
        module->print(llvm::outs(), nullptr);
    }

    std::unique_ptr<llvm::Module> readMeasurementIR(const fs::path &path,
                                                    llvm::LLVMContext &context) {
        llvm::SMDiagnostic diagnostic;
        auto module = llvm::parseAssemblyFile(path.string(), diagnostic, context);
        if (!module) {
            diagnostic.print("image measurement", llvm::errs());
            throw std::runtime_error("invalid measurement IR");
        }

        return module;
    }

    void countResolverBlocks(const fs::path &path) {
        llvm::LLVMContext context;
        const auto module = readMeasurementIR(path, context);
        auto *resolver = module->getFunction("forge_image_address");
        auto *entry = module->getFunction("forge_lifted");
        check(resolver && !resolver->empty() && entry && !entry->empty() &&
                  entry->getReturnType()->isIntegerTy(64),
              "missing resolver or callable entry for measurement");

        // The counter covers only the resolver body. A helper could hide an entire scan.
        for (const auto &inst : llvm::instructions(resolver)) {
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
                check(call->getIntrinsicID() == llvm::Intrinsic::trap,
                      "unmeasured call in image resolver");
            }
        }

        llvm::IRBuilder<> ir(context);
        auto *counter = new llvm::GlobalVariable(*module, ir.getInt64Ty(), false,
                                                 llvm::GlobalValue::InternalLinkage, ir.getInt64(0),
                                                 "resolver.block.visits");
        for (auto &block : *resolver) {
            ir.SetInsertPoint(&block, block.getFirstInsertionPt());
            auto *visits = ir.CreateLoad(ir.getInt64Ty(), counter);
            visits->setVolatile(true);
            ir.CreateStore(ir.CreateAdd(visits, ir.getInt64(1)), counter, true);
        }

        // Reset on every invocation and return the measured visits after the real lookup.
        auto &first = entry->getEntryBlock();
        ir.SetInsertPoint(&first, first.getFirstInsertionPt());
        ir.CreateStore(ir.getInt64(0), counter);
        for (auto &block : *entry) {
            if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>(block.getTerminator())) {
                ir.SetInsertPoint(ret);
                ret->setOperand(0, ir.CreateLoad(ir.getInt64Ty(), counter));
            }
        }

        check(!llvm::verifyModule(*module), "invalid instrumented resolver IR");
        module->print(llvm::outs(), nullptr);
    }

    // Count stored byte-array payloads, including embedded zero bytes. Aggregate
    // zero fill represents a virtual extent without an explicit byte payload.
    uint64_t initializerBytes(const llvm::Constant &value) {
        if (value.isNullValue()) {
            return 0;
        }

        if (const auto *bytes = llvm::dyn_cast<llvm::ConstantDataArray>(&value)) {
            check(bytes->getElementType()->isIntegerTy(8), "unexpected image initializer type");
            return bytes->getRawDataValues().size();
        }

        const auto *parts = llvm::dyn_cast<llvm::ConstantStruct>(&value);
        check(parts && parts->getType()->isPacked(), "unexpected image initializer form");
        uint64_t total = 0;
        for (const auto &fragment : parts->operands()) {
            total += initializerBytes(*llvm::cast<llvm::Constant>(fragment.get()));
        }

        return total;
    }

    uint64_t constructorBytes(const llvm::Module &module,
                              const std::set<const llvm::Value *> &backings) {
        const auto *ctor = module.getFunction("forge_image_initialize");
        if (!ctor) {
            return 0;
        }

        const auto *guard = module.getNamedGlobal("image.initialized.once");
        check(!guard || (guard->hasPrivateLinkage() && guard->getValueType()->isIntegerTy(1)),
              "unexpected image initialization guard");
        uint64_t total = 0;
        for (const auto &inst : llvm::instructions(ctor)) {
            llvm::MemoryLocation write;
            if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
                write = llvm::MemoryLocation::get(store);
            } else if (const auto *copy = llvm::dyn_cast<llvm::MemCpyInst>(&inst)) {
                write = llvm::MemoryLocation::getForDest(copy);
            } else {
                check(!inst.mayWriteToMemory(), "unknown image constructor write");
                continue;
            }

            if (write.Ptr == guard && llvm::isa<llvm::StoreInst>(inst)) {
                continue;
            }

            check(backings.contains(write.Ptr->stripInBoundsConstantOffsets()),
                  "unexpected image constructor destination");
            check(write.Size.hasValue() && write.Size.isPrecise() &&
                      !write.Size.getValue().isScalable(),
                  "unknown image constructor write length");
            total += write.Size.getValue().getFixedValue();
        }

        return total;
    }

    // Measure the raw module. The PE determines the budget charge and the module's
    // initializers determine the payload. Backing sizes include holes and virtual tails.
    void imageStats(const fs::path &path, llvm::StringRef base, const fs::path &irPath) {
        uint64_t guestBase;
        check(!base.getAsInteger(0, guestBase), "invalid measurement load base");
        ParsedImage image(InputFile(path), ParsePolicy::FunctionAnalysis);
        const auto initialization = image.imageInitialization();
        llvm::LLVMContext context;
        const auto module = readMeasurementIR(irPath, context);
        std::set<uint32_t> sections;
        std::set<const llvm::Value *> backings;
        uint64_t budgeted = 0;
        uint64_t emitted = 0;
        uint64_t extent = 0;
        for (const auto &global : module->globals()) {
            auto name = global.getName();
            if (!name.consume_front("image_")) {
                continue;
            }

            uint32_t rva;
            check(!name.getAsInteger(16, rva), "invalid backing RVA");
            const auto *section = image.sectionAtRva(rva);
            check(section != nullptr, "missing PE section for image backing");
            check(global.hasInitializer(), "missing image backing initializer");
            sections.insert(section->rva);
            backings.insert(&global);
            const auto size = module->getDataLayout().getTypeAllocSize(global.getValueType());
            const auto bytes =
                image.imageBytes({rva, rva + size.getFixedValue()}, initialization, guestBase);
            extent += size.getFixedValue();
            budgeted += bytes.prefix.size();
            emitted += initializerBytes(*global.getInitializer());

            for (const auto &fragment : bytes.tail) {
                budgeted += fragment.bytes.size();
            }
        }

        const auto *ranges = module->getNamedGlobal("image.ranges");
        const auto *resolver = module->getFunction("forge_image_address");
        llvm::json::Object stats{
            {"selected_sections", sections.size()},
            {"budgeted_initialized_bytes", budgeted},
            {"emitted_initializer_bytes", emitted + constructorBytes(*module, backings)},
            {"virtual_bytes", extent},
            {"intervals", ranges ? ranges->getValueType()->getArrayNumElements() : 0},
            {"resolver_blocks", resolver ? resolver->size() : 0},
            {"resolver_instructions", resolver ? resolver->getInstructionCount() : 0},
            {"ir_bytes", fs::file_size(irPath)}};
        llvm::outs() << llvm::json::Value(std::move(stats)) << '\n';
    }
} // namespace

int main(int argc, char **argv) try {
    if (argc == 5 && std::string_view(argv[1]) == "--emit-rebased") {
        emitRebased(argv[2], argv[3], argv[4]);
        return 0;
    }

    if (argc == 5 && std::string_view(argv[1]) == "--image-stats") {
        imageStats(argv[2], argv[3], argv[4]);
        return 0;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--count-resolver-blocks") {
        countResolverBlocks(argv[2]);
        return 0;
    }

    check(argc == 5, "expected add.exe, cfg.exe, image.exe and stack.exe fixtures");
    checkAddressAlternatives();
    checkSpillSnapshots();
    checkControlFlow(argv[2]);
    checkControlFlowLeaves(argv[2]);
    checkDirectCalls(argv[4]);
    llvm::SmallString<128> temporary;

    if (auto error = llvm::sys::fs::createUniqueDirectory("forge-lift", temporary)) {
        throw std::system_error(error);
    }

    llvm::scope_exit cleanup([&] { (void)llvm::sys::fs::remove_directories(temporary); });
    llvm::LLVMContext context;
    const forge::fs::path directory(temporary.c_str());
    checkImageConstants(argv[3], directory, context);
    const auto artifact = checkSnapshot(argv[1], directory, context);
    check(!llvm::verifyModule(*artifact), "IR did not survive image destruction");
    checkRelativePublication(argv[1], directory, *artifact);
    checkVerifierFailure(context, directory / "input.exe");
} catch (const forge::InspectionError &error) {
    llvm::errs() << forge::failureKind(error.kind).code << ": " << error.what() << '\n';
    return 1;
} catch (const std::exception &error) {
    llvm::errs() << "lift contract: " << error.what() << '\n';
    return 1;
}
