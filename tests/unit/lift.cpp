#include "lift/lift.h"
#include "analysis/analysis.h"
#include "diagnostic.h"
#include "output/publication.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include <fstream>
#include <map>
#include <string_view>
#include <type_traits>

namespace {
    using namespace forge;

    static_assert(!std::is_copy_constructible_v<AnalyzedImage> &&
                  !std::is_move_constructible_v<AnalyzedImage>);

    void check(bool condition, const char *message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
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
        const auto &body = *module->getFunction("forge_lifted_1000");
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
                module->getFunction("forge_lifted_" + llvm::utohexstr(symbol->rva, true));
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
} // namespace

int main(int argc, char **argv) try {
    check(argc == 3, "expected add.exe and cfg.exe fixtures");
    checkControlFlow(argv[2]);
    checkControlFlowLeaves(argv[2]);
    llvm::SmallString<128> temporary;

    if (auto error = llvm::sys::fs::createUniqueDirectory("forge-lift", temporary)) {
        throw std::system_error(error);
    }

    llvm::scope_exit cleanup([&] { (void)llvm::sys::fs::remove_directories(temporary); });
    llvm::LLVMContext context;
    const forge::fs::path directory(temporary.c_str());
    const auto artifact = checkSnapshot(argv[1], directory, context);
    check(!llvm::verifyModule(*artifact), "IR did not survive image destruction");
    checkRelativePublication(argv[1], directory, *artifact);
    checkVerifierFailure(context, directory / "input.exe");
} catch (const std::exception &error) {
    llvm::errs() << "lift contract: " << error.what() << '\n';
    return 1;
}
