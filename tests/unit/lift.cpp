#include "lift/lift.h"
#include "analysis/analysis.h"
#include "diagnostic.h"
#include "output/publication.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include <fstream>
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
    check(argc == 2, "expected the add.exe fixture");
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
