#include "lift/recovery.h"
#include "analysis/analysis.h"
#include "forge/guest_range.h"
#include "lift/group_analysis.h"
#include "lift/memory.h"
#include "lift/operands.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/raw_ostream.h"

#include <array>
#include <future>
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

    void checkGuestRanges() {
        const auto bytes = GuestRange::fromOffset({0x1000}, 8, 8);
        const auto adjacent = GuestRange::fromOffset({0x1010}, 0, 2);
        const auto overlap = GuestRange::fromOffset({0x100f}, 0, 2);
        const auto interior = GuestRange::fromOffset({0x100b}, 0, 2);

        if (!bytes || !adjacent || !overlap || !interior) {
            throw std::runtime_error("valid guest range failed construction");
        }

        check(bytes->contains({0x1008}) && bytes->contains({0x100f}) &&
                  !bytes->contains({0x1007}) && !bytes->contains({0x1010}),
              "guest range did not contain exactly its requested bytes");
        check(!bytes->overlaps(*adjacent) && !adjacent->overlaps(*bytes) &&
                  bytes->overlaps(*overlap) && overlap->overlaps(*bytes) &&
                  bytes->overlaps(*interior) && interior->overlaps(*bytes),
              "guest range confused adjacency and overlap");

        const auto highest = GuestRange::fromOffset({UINT64_MAX - 4}, 3, 2);
        const auto lastByte = GuestRange::fromOffset({UINT64_MAX}, 0, 1);
        const auto lowest = GuestRange::fromOffset({0}, 0, 1);
        check(highest && lastByte && lowest && highest->overlaps(*lastByte) &&
                  lastByte->contains({UINT64_MAX}) && !lastByte->contains({UINT64_MAX - 1}) &&
                  !highest->contains({0}) && !highest->overlaps(*lowest),
              "guest range at the top of the address space wrapped through zero");
        check(!GuestRange::fromOffset({UINT64_MAX}, 0, 0) &&
                  !GuestRange::fromOffset({UINT64_MAX - 4}, 5, 1) &&
                  !GuestRange::fromOffset({UINT64_MAX - 4}, 3, 3),
              "guest range accepted an empty span or a wrapping start or last byte");
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
                      site->continuation == steps[2 * i + 2].rva && site->guest().rva == target &&
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

    void checkRipOffsets(x86::Step lea, const llvm::MCRegisterInfo &regs) {
        constexpr uint64_t base = 0x140000000;
        const x86::InstructionOperands operands(regs, base);
        lea.next = UINT32_MAX;
        lea.inst.getOperand(4).setImm(INT32_MAX);
        const auto above = int64_t(UINT32_MAX) + INT32_MAX;
        check(operands.ripRva(lea, 1) == above && operands.ripAddress(lea, 1) == base + above,
              "RIP-relative calculation narrowed a destination above the RVA space");

        lea.next = 7;
        lea.inst.getOperand(4).setImm(0x80000000);
        const auto below = int64_t(7) + INT32_MIN;
        check(operands.ripRva(lea, 1) == below &&
                  operands.ripAddress(lea, 1) == base - static_cast<uint64_t>(-below),
              "RIP-relative calculation lost the sign bit of disp32");
    }

    void checkRegisterCalls(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "call_indirect");
        const auto shared = exportedRva(analysis, "indirect_preserve");
        const auto leaf = exportedRva(analysis, "indirect_leaf");
        const auto recursive = exportedRva(analysis, "indirect_recurse");
        const RecoveredFunctionGroup group(analysis, root);
        const auto &caller = group.function(root);
        const auto &incoming = group.function(shared).incoming;
        check(group.functions().size() == 4 && caller.calls.size() == 5 && incoming.size() == 3 &&
                  group.function(shared).origin == x86::RecoveryOrigin::UnwindBacked &&
                  group.function(leaf).origin == x86::RecoveryOrigin::InferredLeaf,
              "mixed call sites lost a shared body or its recovery origin");

        const x86::InstructionOperands operands(group.registers(), 0);
        const auto flow =
            x86::analyzeGroup(group, analysis.module().imageBase, EntryMode::WindowsX64I64Pair);
        uint32_t previous = 0;
        for (const auto *site : incoming) {
            const auto *step = caller.instructionContaining(site->instruction);
            const auto &calls = flow.flows.at(root).blocks.at(site->block).calls;
            check(
                step && step->rva == site->instruction && site == caller.callAt(step->rva) &&
                    site->guest().rva == shared && site->caller == root &&
                    site->continuation == step->next && site->continuation > previous &&
                    llvm::any_of(calls, [site](const auto &effect) { return effect.site == site; }),
                "mixed call proof or continuation does not refer to the recovered site");
            previous = site->continuation.value();

            if (site == incoming.back()) {
                check(site->guest().kind == x86::CallKind::Direct && step->isDirectCall() &&
                          site->guest().evidenceRva == step->rva,
                      "direct call lost its encoded target evidence");
                continue;
            }

            const auto *lea = caller.instructionContaining(site->guest().evidenceRva);
            check(site->guest().kind == x86::CallKind::RipRelativeRegister &&
                      step->isRegisterCall() && lea && lea->opcode == "LEA64r" &&
                      operands.ripRva(*lea, 1) == shared &&
                      lea->inst.getOperand(0).getReg() == step->inst.getOperand(0).getReg(),
                  "register call lost its source LEA or operand");
        }

        checkRipOffsets(*caller.instructionContaining(incoming.front()->guest().evidenceRva),
                        group.registers());
        const auto &self = group.function(recursive);
        check(self.calls.size() == 1 && self.incoming.size() == 2 &&
                  self.calls.begin()->second.guest().rva == recursive &&
                  self.incoming.back() == &self.calls.begin()->second,
              "recursive register call did not reuse its own function");
    }

    void checkTailTransfer(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "tail_caller");
        const auto bridge = exportedRva(analysis, "tail_only");
        const auto reader = exportedRva(analysis, "tail_reader");
        const RecoveredFunctionGroup group(analysis, root);
        const auto &source = group.function(bridge);
        const auto &block = source.graph.at(bridge);
        const auto *edge = source.callAt(bridge);

        check(block.exit == x86::Flow::TailJump && block.successors.empty() &&
                  block.steps.size() == 1 && source.mayReturn,
              "tail-only body requires a returning target and no local successor");
        check(edge && edge->isTailJump() && edge->guest().kind == x86::CallKind::TailJump &&
                  edge->guest().evidenceRva == bridge && edge->guest().rva == reader &&
                  group.function(reader).incoming.front() == edge,
              "tail transfer lost its location or acquired a continuation");
        check(source.incoming.front()->continuation && group.function(root).mayReturn,
              "caller did not resume after transitive return");
    }

    void checkSelfRecursion(const AnalyzedImage &analysis) {
        const auto root = exportedRva(analysis, "call_depth");
        const RecoveredFunctionGroup recursive(analysis, root);
        const auto &function = recursive.function(root);
        const auto *self = function.callAt(root + 12);
        check(recursive.functions().size() == 1 && function.incoming.size() == 1 && self &&
                  self == function.incoming.front() && self->caller == self->guest().rva &&
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
        const auto *toFirst = second.callAt(b + 8);
        const auto *self = second.callAt(b + 13);
        check(mutual.root() == b && mutual.functions().size() == 2 && first.incoming.size() == 1 &&
                  second.incoming.size() == 2 && toSecond && toFirst && self &&
                  first.incoming.front() == toFirst && second.incoming[0] == toSecond &&
                  second.incoming[1] == self && self->caller == b && self->guest().rva == b &&
                  toSecond->caller == a && toSecond->guest().rva == b && toFirst->caller == b &&
                  toFirst->guest().rva == a,
              "mutual recursion lost a function or a cycle edge");

        const auto loop = exportedRva(analysis, "recovery_no_base");
        const RecoveredFunctionGroup cycle(analysis, loop);
        const auto &only = cycle.function(loop);
        const auto *recurse = only.callAt(loop + 4);
        check(cycle.functions().size() == 1 && only.calls.size() == 1 && recurse &&
                  recurse->guest().rva == loop &&
                  !only.instructionContaining(recurse->continuation.value()),
              "recursion without a base case reached a dead call");
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

    void checkLeafInstructions(const AnalyzedImage &analysis,
                               const x86::RecoveredFunction &function) {
        for (const auto &[leader, block] : function.graph) {
            for (const auto &step : block.steps) {
                const auto mapped = analysis.image().mapRva(step.rva, step.next - step.rva);
                check(mapped && step.bytes.data() == mapped->bytes.data() && !step.opcode.empty() &&
                          function.instructionContaining(step.rva) == &step,
                      "lost inferred instruction or borrow");

                const bool overlaps =
                    llvm::any_of(analysis.functions(), [&](const FunctionRange &record) {
                        return step.rva < record.record.end && record.record.begin < step.next;
                    });
                check(!overlaps, "leaf overlaps an observed PE range");
            }
        }
    }

    void checkLeaves(const AnalyzedImage &analysis, const RecoveredFunctionGroup &group) {
        const auto root = group.root();
        const auto &caller = group.function(root);
        check(group.functions().size() == 5 && caller.calls.size() == 5 &&
                  caller.origin == x86::RecoveryOrigin::UnwindBacked,
              "incorrect leaf group");
        const auto &first = caller.calls.begin()->second;
        const auto &second = std::next(caller.calls.begin())->second;
        const auto &shared = group.function(first.guest().rva);
        check(first.guest().rva == second.guest().rva && shared.incoming.size() == 2 &&
                  shared.incoming.front() == &first && shared.incoming.back() == &second &&
                  first.continuation == first.instruction + 5 &&
                  second.continuation == second.instruction + 5,
              "shared leaf lost call identity or continuation");

        for (const auto &[rva, f] : group.functions()) {
            if (rva == root) {
                continue;
            }

            check(f.entry == rva && f.origin == x86::RecoveryOrigin::InferredLeaf &&
                      f.calls.empty() && f.code.section.permissions[2] == 'x',
                  "wrong inferred evidence");

            checkLeafInstructions(analysis, f);
        }
    }

    void checkLeafRegisters(const AnalyzedImage &analysis) {
        for (auto caller : {"recovery_mov_source", "recovery_cmp_input", "recovery_store_source",
                            "recovery_extend_source", "recovery_cmov_source"}) {
            const auto root = exportedRva(analysis, caller);
            try {
                const RecoveredFunctionGroup group(analysis, root);
                throw std::runtime_error("recovery admitted an unmodeled source register");
            } catch (const InspectionError &error) {
                const auto &where = error.context;
                check(error.kind == FailureCode::UnsupportedRegister && where.functionRva &&
                          where.instructionRva == where.functionRva && where.sourceCall &&
                          where.sourceCall->caller == root &&
                          where.sourceCall->instruction == root + 4,
                      "unmodeled leaf operand lost its classification or source call");
            }
        }

        const auto root = exportedRva(analysis, "recovery_saved_input");
        const RecoveredFunctionGroup group(analysis, root);
        const auto target = group.function(root).calls.begin()->second.guest().rva;
        check(group.function(target).origin == x86::RecoveryOrigin::InferredLeaf,
              "reading a supported nonvolatile source disqualified a leaf");
    }

    void checkJumpTable(const AnalyzedImage &analysis) {
        const auto entry = exportedRva(analysis, "cfg_jump_table");
        const RecoveredFunctionGroup first(analysis, entry);
        const RecoveredFunctionGroup repeated(analysis, entry);
        const auto &function = first.function(entry);
        checkRange(analysis, first, entry);
        check(first.functions().size() == 1 && function.calls.empty() && function.incoming.empty(),
              "table entries became call edges");

        const auto dispatch = llvm::find_if(function.graph, [](const auto &item) {
            return item.second.exit == x86::Flow::Indirect;
        });
        check(dispatch != function.graph.end(), "missing indirect terminator");
        const auto &block = dispatch->second;
        const auto &jump = block.steps.back();
        const auto &again = repeated.function(entry).graph.at(dispatch->first);
        const auto mapped = analysis.image().mapRva(jump.rva, jump.next - jump.rva);
        const auto &table = block.table.value();
        check(mapped && table.count == 5 && block.successors.size() == 5 &&
                  block.successors == again.successors && again.steps.back().rva == jump.rva &&
                  jump.opcode == "JMP64r" && function.instructionContaining(jump.rva) == &jump &&
                  jump.bytes.data() == mapped->bytes.data(),
              "dispatch identity, source bytes or repeated recovery differ");

        const auto &guard = function.graph.at(table.compareRva);
        check(guard.exit == x86::Flow::Conditional && guard.steps.back().rva == table.guardRva &&
                  guard.successors[1] == dispatch->first &&
                  block.successors[0] == block.successors[1],
              "range guard or duplicate table edge lost");

        for (unsigned i = 0; i < table.count; ++i) {
            const auto word = analysis.image().mapRva(table.tableRva + 4 * i, 4).value();
            const auto offset =
                llvm::SignExtend64<32>(llvm::support::endian::read32le(word.bytes.data()));
            const auto target = block.successors[i];
            check(int64_t(table.tableRva) + offset == target && function.graph.contains(target) &&
                      function.graph.at(target).steps.front().rva == target,
                  "table successor is not the linked entry's instruction boundary");
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

    void checkImportSnapshot(const fs::path &path) {
        const AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(path), ParsePolicy::Inspection),
            DebugInfo::Omit);
        auto lookup = [&] { return &analysis.image().importBindings(); };
        auto pending = std::async(std::launch::async, lookup);
        const auto *index = lookup();
        check(pending.get() == index, "concurrent lookups did not share the image index");

        const auto root = exportedRva(analysis, "last_error");
        const auto helper = exportedRva(analysis, "last_error_set");
        const RecoveredFunctionGroup first(analysis, root);
        const RecoveredFunctionGroup second(analysis, helper);
        const auto &calls = first.function(helper).calls;
        check(calls.size() == 1, "missing setter in nested helper");
        const auto &[site, call] = *calls.begin();
        const auto *target = call.external();
        const auto *repeat = second.function(helper).callAt(site);
        check(target && repeat && repeat->external(), "expected the same external call site");
        const auto slot = index->at(target->slot);
        check(slot && &target->descriptor == &slot->descriptor &&
                  &repeat->external()->descriptor == &target->descriptor,
              "the recovered groups do not share the image-owned descriptor");
    }

    void checkTerminalGuestCall(const fs::path &path) {
        const AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(path), ParsePolicy::Inspection),
            DebugInfo::Omit);
        const RecoveredFunctionGroup group(analysis, analysis.module().entryPoint);
        const auto &root = group.function(group.root());
        check(root.calls.size() == 1, "expected one call from the entry to its exit helper");
        const auto &site = root.calls.begin()->second;
        const auto *step = root.instructionContaining(site.instruction);
        check(!site.external() && step && step->next == site.continuation &&
                  !root.instructionContaining(site.continuation.value()),
              "terminal guest call must retain its return address and exclude dead instructions");
        const auto &helper = group.function(site.guest().rva);
        check(helper.incoming.size() == 1 && helper.incoming.front() == &site,
              "terminal callee lost its incoming call site");
    }

    void checkInitializerTables(const fs::path &path) {
        const AnalyzedImage analysis(
            std::make_unique<ParsedImage>(InputFile(path), ParsePolicy::Inspection),
            DebugInfo::Omit);
        const RecoveredFunctionGroup group(analysis, analysis.module().entryPoint);
        const auto &caller = group.function(group.root());
        std::vector<std::pair<uint32_t, size_t>> observed;
        std::map<uint32_t, const x86::ResolvedCallSite *> initializers;
        for (const auto &[rva, site] : caller.calls) {
            const auto *service = site.external();
            if (!service || !service->initializers) {
                continue;
            }

            check(service->binding.callback == win64::Callback::Initializer,
                  "callback proof attached to an unrelated service");
            const auto &table = *service->initializers;
            const auto size = table.last - table.first;
            observed.emplace_back(size / sizeof(uint64_t), table.targets.size());
            std::set<uint32_t> slotTargets;
            for (auto slot = table.first; slot < table.last; slot += sizeof(uint64_t)) {
                const auto bytes = analysis.image().mapRva(slot, sizeof(uint64_t));
                check(bytes && bytes->section.writableData(), "expected a writable table slot");
                const auto va = llvm::support::endian::read64le(bytes->bytes.data());
                if (va) {
                    slotTargets.insert(static_cast<uint32_t>(va - analysis.module().imageBase));
                }
            }
            check(std::ranges::equal(table.targets, slotTargets),
                  "initializer target set differs from the source PE slots");
            for (const auto target : slotTargets) {
                initializers.try_emplace(target, &site);
            }
        }
        const std::vector<std::pair<uint32_t, size_t>> expected{{0, 0}, {1, 0}, {1, 1}, {5, 3}};
        check(observed == expected && initializers.size() == 3, "wrong recovered table ranges");

        bool nestedLeaf = false;
        for (const auto &[rva, function] : group.functions()) {
            const auto origin = initializers.find(rva);
            check(function.callbackSource ==
                      (origin == initializers.end() ? nullptr : origin->second),
                  "initializer origin differs from its first admitting table");
            if (function.callbackSource && function.origin == x86::RecoveryOrigin::InferredLeaf &&
                !function.incoming.empty()) {
                nestedLeaf |= initializers.contains(function.incoming.front()->caller);
            }
        }
        check(nestedLeaf, "missing metadata-free initializer shared with an ordinary guest call");
    }

    // Check PE stability for the differential runner's independently disassembled caller.
    // The first interval is code. Each following interval is a relative table.
    void checkDispatchSpans(const fs::path &path, llvm::ArrayRef<char *> bounds) {
        const auto slots =
            llvm::find_if(bounds, [](llvm::StringRef arg) { return arg == "--iat-slots"; });
        const auto intervals = bounds.take_front(static_cast<size_t>(slots - bounds.begin()));
        check(intervals.size() >= 2 && intervals.size() % 2 == 0,
              "expected a code RVA span and optional table spans");
        ParsedImage image(InputFile(path), ParsePolicy::FunctionAnalysis);
        check(!image.advertisesDynamicRelocations(), "unknown dynamic relocation writes");
        const auto init = image.imageInitialization();

        for (size_t i = 0; i < intervals.size(); i += 2) {
            uint32_t begin = 0, end = 0;
            check(!llvm::StringRef(bounds[i]).getAsInteger(0, begin) &&
                      !llvm::StringRef(bounds[i + 1]).getAsInteger(0, end) && begin < end,
                  "invalid dispatch span");
            const auto mapped = image.mapRva(begin, end - begin);
            check(mapped && mapped->section.immutable() &&
                      (mapped->section.permissions[2] == 'x') == (i == 0),
                  "dispatch requires stable file-backed bytes");
            check(init.exclusionsIn({begin, end}).empty() &&
                      init.relocationsIn({begin, end}).empty(),
                  "dispatch overlaps loader-written bytes or relocations");
        }

        if (slots != bounds.end()) {
            const RelocationIndex relocations(image.module().relocations);
            for (const auto *arg : bounds.drop_front(intervals.size() + 1)) {
                uint32_t rva = 0;
                check(!llvm::StringRef(arg).getAsInteger(0, rva), "invalid IAT slot RVA");
                const auto slot = image.importBindings().at(rva);
                check(slot && !slot->descriptor.delayed &&
                          slot->descriptor.normalizedName == "kernel32.dll" &&
                          (slot->symbol.name == "GetLastError" ||
                           slot->symbol.name == "SetLastError" ||
                           slot->symbol.name == "lstrlenA") &&
                          !slot->unstableIdentityRva(relocations, init.excluded),
                      "unproven supported-service IAT call");
            }
        }
    }
} // namespace

int main(int argc, char **argv) try {
    if (argc >= 3 && llvm::StringRef(argv[1]) == "--check-dispatch-spans") {
        checkDispatchSpans(argv[2], llvm::ArrayRef(argv + 3, static_cast<size_t>(argc - 3)));
        return 0;
    }

    check(argc == 8,
          "expected stack, leaves, jump, indirect, last-error, noreturn and CRT fixtures");
    checkGuestRanges();
    checkImportSnapshot(argv[5]);
    checkTerminalGuestCall(argv[6]);
    checkInitializerTables(argv[7]);
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
    checkTailTransfer(analysis);
    checkSelfRecursion(analysis);
    checkMutualRecursion(analysis);
    checkParallelEdges(analysis);
    checkLeafRegisters(analysis);
    checkAnalysisFailure(analysis);
    const auto nested = exportedRva(analysis, "recovery_invalid_callee");
    checkFailure(analysis, exportedRva(analysis, "recovery_invalid_entry"), nested, nested + 1,
                 FailureCode::InvalidCallTarget);
    const auto unrecorded = exportedRva(analysis, "recovery_unrecorded");
    const RecoveredFunctionGroup retOnly(analysis, unrecorded);
    check(retOnly.function(analysis.module().entryPoint).origin ==
              x86::RecoveryOrigin::InferredLeaf,
          "a direct call to the unrecorded RET should recover one leaf");

    const AnalyzedImage leaves(
        std::make_unique<ParsedImage>(InputFile(argv[2]), ParsePolicy::Inspection),
        DebugInfo::Omit);
    const auto caller = exportedRva(leaves, "call_leaves");
    const RecoveredFunctionGroup leafGroup(leaves, caller);
    {
        const RecoveredFunctionGroup other(leaves, caller);
        checkLeaves(leaves, other);
    }

    checkLeaves(leaves, leafGroup);
    const AnalyzedImage jumps(
        std::make_unique<ParsedImage>(InputFile(argv[3]), ParsePolicy::Inspection),
        DebugInfo::Omit);
    checkJumpTable(jumps);
    const AnalyzedImage indirect(
        std::make_unique<ParsedImage>(InputFile(argv[4]), ParsePolicy::Inspection),
        DebugInfo::Omit);
    checkRegisterCalls(indirect);
    return 0;
} catch (const std::exception &error) {
    llvm::errs() << error.what() << "\n";
    return 1;
}
