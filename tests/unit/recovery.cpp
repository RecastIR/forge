#include "lift/recovery.h"
#include "analysis/analysis.h"
#include "lift/group_analysis.h"
#include "lift/memory.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/raw_ostream.h"

#include <array>
#include <type_traits>
#include <utility>

namespace {
    using namespace forge;
    using x86::RecoveredFunctionGroup;
    using x86::ValidatedEntry;

    static_assert(!std::is_aggregate_v<ValidatedEntry> &&
                  !std::is_constructible_v<ValidatedEntry, const AnalyzedImage &, uint32_t,
                                           MappedRange, RelocationIndex &&>);
    static_assert(!std::is_copy_constructible_v<ValidatedEntry> &&
                  !std::is_move_constructible_v<ValidatedEntry>);
    static_assert(std::is_const_v<decltype(ValidatedEntry::rva)> &&
                  std::is_const_v<decltype(ValidatedEntry::code)> &&
                  std::is_const_v<decltype(ValidatedEntry::relocations)>);

    template <class Group>
    constexpr bool borrowsFromTemporary = requires { std::declval<Group &&>().functions(); } ||
                                          requires { std::declval<Group &&>().function(0); } ||
                                          requires { std::declval<Group &&>().registers(); };

    static_assert(!borrowsFromTemporary<RecoveredFunctionGroup> &&
                  !borrowsFromTemporary<const RecoveredFunctionGroup>);

    void check(bool condition, const char *message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    uint32_t exportedRva(const AnalyzedImage &analysis, llvm::StringRef name) {
        const auto &exports = analysis.module().exports;
        auto symbol = llvm::find_if(
            exports, [&](const Export &item) { return llvm::is_contained(item.names, name); });
        check(symbol != exports.end(), "missing recovery fixture export");
        return symbol->rva;
    }

    void checkRange(const AnalyzedImage &analysis, const RecoveredFunctionGroup &group,
                    uint32_t rva) {
        const auto &ranges = analysis.functions();
        const auto found = llvm::find_if(ranges, [&](const FunctionRange &function) {
            return function.eligible() && function.record.begin == rva;
        });
        check(found != ranges.end(), "recovered function has no validated range");
        const auto mapped = analysis.image().mapRva(rva, found->record.end - rva);
        const auto &code = group.function(rva).code;
        check(mapped && &code.section == &mapped->section &&
                  code.fileOffset == mapped->fileOffset && code.bytes == mapped->bytes,
              "recovered range differs from the validated PE mapping");
    }

    void checkRepeatedCalls(const AnalyzedImage &analysis, const RecoveredFunctionGroup &group) {
        const auto root = exportedRva(analysis, "call_preserves_carry");
        const auto target = exportedRva(analysis, "call_result");
        check(group.root() == root && &group.image() == &analysis.image() &&
                  group.functions().size() == 2 && group.functions().begin()->first == target,
              "wrong selected image, root or ordered function group");
        checkRange(analysis, group, root);
        checkRange(analysis, group, target);
        const auto &caller = group.function(root);
        const auto &callee = group.function(target);
        check(caller.incoming.empty() && caller.graph.size() == 1 && caller.calls.size() == 2 &&
                  callee.incoming.size() == 2 && callee.calls.empty(),
              "a repeated call changed group membership, block boundaries or site count");

        const auto &steps = caller.graph.at(root).steps;
        constexpr std::array<unsigned, 7> offsets{0, 5, 10, 13, 18, 23, 27};
        check(steps.size() == offsets.size(), "wrong number of straight-line instructions");

        for (size_t i = 0; i < offsets.size(); ++i) {
            const auto &step = steps[i];
            const auto bytes = group.image().mapRva(step.rva, step.next - step.rva);
            check(step.rva == root + offsets[i] && bytes && step.bytes == bytes->bytes,
                  "wrong instruction extent, order or snapshot bytes");
        }

        for (size_t i = 0; i < callee.incoming.size(); ++i) {
            const auto &step = steps[2 * i + 1];
            const auto *site = caller.callAt(step.rva);
            check(site && site == callee.incoming[i] && site->caller == root &&
                      site->instruction == step.rva && site->block == root &&
                      site->continuation == steps[2 * i + 2].rva && site->callee == target &&
                      step.opcode == "CALL64pcrel32",
                  "wrong ordered site, decoded opcode or same-block continuation");
        }

        check(steps[2].bytes == "\x48\x39\xd1" && !caller.callAt(steps[2].rva),
              "the instruction after the first call is not the original CMP");
    }

    void checkEntryContracts(const RecoveredFunctionGroup &group) {
        const auto base = group.image().module().imageBase;
        const auto state = x86::analyzeGroup(group, base, EntryMode::RegisterState);
        const auto typed = x86::analyzeGroup(group, base, EntryMode::WindowsX64I64Pair);
        const auto &stateFlow = state.flows.at(group.root());
        const auto &typedFlow = typed.flows.at(group.root());
        check(stateFlow.entry.registers[0] == UINT64_MAX && typedFlow.entry.registers[0] == 0,
              "mode-specific entry proofs interfered with each other");
        const auto &sites = group.function(group.root()).calls;
        const auto &stateCalls = stateFlow.blocks.at(group.root()).calls;
        const auto &typedCalls = typedFlow.blocks.at(group.root()).calls;
        check(sites.size() == 2 && stateCalls.size() == 2 && typedCalls.size() == 2,
              "analysis lost a repeated direct call");
        size_t index = 0;

        for (const auto &[rva, site] : sites) {
            check(stateCalls[index].site == &site && typedCalls[index].site == &site,
                  "entry proofs lost their authoritative call site");
            ++index;
        }
    }

    void checkSelfRecursion(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "call_depth");
        const RecoveredFunctionGroup recursive(analysis, root);
        const auto &function = recursive.function(root);
        const auto *self = function.callAt(root + 12);
        check(recursive.functions().size() == 1 && function.incoming.size() == 1 && self &&
                  self == function.incoming.front() && self->caller == self->callee &&
                  self->caller == root && self->continuation == root + 17,
              "self-recursion did not return to the selected function");
        const auto &branch = function.graph.at(root);
        check(branch.exit == x86::Flow::Conditional && branch.successors.size() == 2 &&
                  branch.successors[0] == root + 25 && branch.successors[1] == root + 5,
              "conditional successors lost taken-then-fallthrough ordering");
    }

    void checkMutualRecursion(const AnalyzedImage &analysis) {
        const auto a = exportedRva(analysis, "recovery_mutual_a");
        const auto b = exportedRva(analysis, "recovery_mutual_b");
        const RecoveredFunctionGroup mutual(analysis, b);
        const auto &first = mutual.function(a);
        const auto &second = mutual.function(b);
        const auto *toSecond = first.callAt(a + 4);
        const auto *toFirst = second.callAt(b + 4);
        const auto *self = second.callAt(b + 9);
        check(mutual.root() == b && mutual.functions().size() == 2 && first.incoming.size() == 1 &&
                  second.incoming.size() == 2 && toSecond && toFirst && self &&
                  first.incoming.front() == toFirst && second.incoming[0] == toSecond &&
                  second.incoming[1] == self && self->caller == b && self->callee == b &&
                  toSecond->caller == a && toSecond->callee == b && toFirst->caller == b &&
                  toFirst->callee == a,
              "mutual recursion lost a function or a cycle edge");
    }

    void checkParallelEdges(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "parallel_memory_edges");
        const RecoveredFunctionGroup group(analysis, root);
        const auto &graph = group.function(root).graph;
        const auto &branch = graph.at(root);
        check(graph.size() == 2 && branch.exit == x86::Flow::Conditional &&
                  branch.successors.size() == 2 && branch.successors[0] == root + 10 &&
                  branch.successors[1] == root + 10,
              "recovery discarded one of two parallel CFG edges");
    }

    void checkFailure(const AnalyzedImage &analysis, uint32_t root, uint32_t caller,
                      uint32_t target, FailureCode expected) {
        const auto instruction = caller + 4;
        const auto mapped = analysis.image().mapRva(instruction, 5);

        try {
            const RecoveredFunctionGroup group(analysis, root);
            throw std::runtime_error("recovery accepted an invalid or unresolved call");
        } catch (const InspectionError &error) {
            const auto &location = error.context;
            check(mapped && error.kind == expected && location.input == analysis.module().path &&
                      location.entryRva == root && location.blockRva == caller &&
                      location.instructionRva == instruction && location.branchTarget == target &&
                      location.bytes == llvm::toHex(mapped->bytes, true) &&
                      location.opcode == "CALL64pcrel32" &&
                      location.fileOffset == mapped->fileOffset,
                  "bad call changed diagnostic classification or location");
            check(location.functionRva == (root == caller ? std::nullopt : std::optional(caller)),
                  "bad call lost its owning guest function");
        }
    }

    void checkAnalysisFailure(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "call_bad_teardown");
        const auto callee = exportedRva(analysis, "bad_teardown");
        const auto entry = x86::validateEntry(analysis, root);
        const RecoveredFunctionGroup group(entry);

        // Placing .text on the guest stack rejects the first PUSH in the lower-RVA callee.
        const auto requestedBase = x86::GuestMemory::base - entry.code.section.rva;
        const auto base = x86::validateGuestBase(entry, requestedBase);
        const auto instruction = analysis.image().mapRva(callee, 1);

        try {
            x86::analyzeGroup(group, base, EntryMode::WindowsX64I64Pair);
            throw std::runtime_error("analysis accepted overlapping guest image and stack");
        } catch (const InspectionError &error) {
            const auto &location = error.context;
            check(error.kind == FailureCode::ImageMemory &&
                      llvm::StringRef(error.what()).contains("PE image overlaps the guest stack"),
                  "standalone analysis changed the image overlap diagnostic");
            check(location.input == analysis.module().path && location.entryRva == root &&
                      location.endRva == root + entry.code.bytes.size(),
                  "standalone analysis lost the requested entry range");
            check(instruction && location.functionRva == callee && location.blockRva == callee &&
                      location.instructionRva == callee &&
                      location.fileOffset == instruction->fileOffset &&
                      location.opcode == "PUSH64r" && location.bytes == "51",
                  "standalone analysis lost the failing nested instruction");
        }
    }
} // namespace

int main(int argc, char **argv) try {
    check(argc == 2, "expected stack.exe");
    const AnalyzedImage analysis(
        std::make_unique<ParsedImage>(InputFile(argv[1]), ParsePolicy::Inspection),
        DebugInfo::Omit);
    const auto root = exportedRva(analysis, "call_preserves_carry");
    const RecoveredFunctionGroup first(analysis, root);

    {
        const RecoveredFunctionGroup second(analysis, root);
        checkRepeatedCalls(analysis, second);
    }

    // Destruction of an independent decoder must leave the first group's borrows intact.
    checkRepeatedCalls(analysis, first);
    checkEntryContracts(first);
    checkSelfRecursion(analysis);
    checkMutualRecursion(analysis);
    checkParallelEdges(analysis);
    checkAnalysisFailure(analysis);
    const auto nested = exportedRva(analysis, "recovery_invalid_callee");
    checkFailure(analysis, exportedRva(analysis, "recovery_invalid_entry"), nested, nested + 1,
                 FailureCode::InvalidCallTarget);
    const auto unresolved = exportedRva(analysis, "recovery_unrecorded");
    checkFailure(analysis, unresolved, unresolved, analysis.module().entryPoint,
                 FailureCode::UnsupportedControlFlow);
    return 0;
} catch (const std::exception &error) {
    llvm::errs() << error.what() << "\n";
    return 1;
}
