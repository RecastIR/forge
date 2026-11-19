#include "lift/cfg.h"
#include "lift/guarded_call.h"
#include "lift/integer.h"
#include "lift/jump_table.h"
#include "lift/operands.h"
#include "pe/image.h"

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/Support/Endian.h"

#include <algorithm>
#include <set>

namespace forge::x86 {
    using namespace llvm;

    void Step::reject(FailureCode kind, const Twine &reason, std::optional<int64_t> target,
                      std::optional<uint32_t> importSlot,
                      const std::optional<ImportOwnershipFailure> &ownership) const {
        auto encoded = toHex(bytes, true);
        InspectionError failure(hex(rva) + ": " + (opcode + " [" + encoded + "]: " + reason).str(),
                                kind);
        failure.context.instructionRva = rva;
        failure.context.opcode = opcode.str();
        failure.context.bytes = std::move(encoded);
        failure.context.branchTarget = target;
        failure.context.importSlot = importSlot;
        failure.context.importOwnership = ownership;
        throw failure;
    }

    namespace {
        constexpr unsigned maxLeafInstructions = 4096;

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

        void checkPrefix(const Step &s) {
            if (s.isRepeatedQwordStore()) {
                return;
            }

            auto encoding = arrayRefFromStringRef(s.bytes);
            if (s.isLockedCompareExchange()) {
                encoding = encoding.drop_front();
            }

            // GS + REX.W MOV r64,[disp32] with no base/index and NT_TIB.Self at +0x30.
            if (s.opcode == "MOV64rm" && encoding.size() == 9 && encoding[0] == 0x65 &&
                (encoding[1] & 0xfbU) == 0x48 && encoding[2] == 0x8b &&
                (encoding[3] & 0xc7U) == 4 && encoding[4] == 0x25 &&
                llvm::support::endian::read32le(encoding.data() + 5) == 0x30) {
                encoding = encoding.drop_front();
            }
            if (encoding.front() == 0x66) {
                auto instruction = x86::integerInstruction(s.opcode);

                if ((!instruction || instruction->width != 16) && s.opcode != "CMOV16rr" &&
                    s.opcode != "NOOPW") {
                    s.reject(FailureCode::UnsupportedPrefix, "unsupported instruction prefix");
                }

                encoding = encoding.drop_front();
            }

            if (!encoding.empty() && (encoding.front() & 0xf0U) == 0x40) {
                encoding = encoding.drop_front();
            }

            if (encoding.empty() || legacyPrefix(encoding.front()) ||
                (encoding.front() & 0xf0U) == 0x40) {
                s.reject(FailureCode::UnsupportedPrefix, "unsupported instruction prefix");
            }
        }

        Step decodeStep(StringRef tail, uint32_t rva, const MCDisassembler &dis,
                        const MCInstrInfo &info) {
            MCInst inst;
            uint64_t size = 0;
            if (dis.getInstruction(inst, size, arrayRefFromStringRef(tail), rva, nulls()) !=
                    MCDisassembler::Success ||
                !size || size > tail.size()) {
                auto encoded = toHex(tail.take_front(15), true);
                InspectionError failure(hex(rva) + ": invalid or truncated x86 instruction [" +
                                            encoded + "]",
                                        FailureCode::InvalidInstruction);
                failure.context.instructionRva = rva;
                failure.context.bytes = std::move(encoded);
                throw failure;
            }

            auto opcode = info.getName(inst.getOpcode());
            // LLVM MC decodes LOCK as a separate pseudo-instruction. Keep the prefix
            // and its supported operation in one instruction extent and one CFG step.
            if (opcode == "LOCK_PREFIX" && size == 1 && tail.size() > 1) {
                MCInst following;
                uint64_t extra = 0;
                if (dis.getInstruction(following, extra, arrayRefFromStringRef(tail.drop_front()),
                                       uint64_t(rva) + 1, nulls()) == MCDisassembler::Success &&
                    extra && extra < 15 && info.getName(following.getOpcode()) == "CMPXCHG64rm") {
                    inst = std::move(following);
                    opcode = info.getName(inst.getOpcode());
                    size += extra;
                }
            }

            return {rva, static_cast<uint32_t>(rva + size), std::move(inst), opcode,
                    tail.take_front(size)};
        }

        Flow control(const Step &s, const MCInstrInfo &info, bool recordedExtent) {
            if (s.opcode == "RET64") {
                return Flow::Return;
            }

            if (s.opcode == "JMP_1" || s.opcode == "JMP_4") {
                return Flow::Jump;
            }

            if (s.opcode == "JCC_1" || s.opcode == "JCC_4") {
                return Flow::Conditional;
            }

            if (recordedExtent && s.opcode == "JMP64r") {
                return Flow::Indirect;
            }

            if (recordedExtent && s.isMemoryCall()) {
                return Flow::Fallthrough;
            }

            const auto &desc = info.get(s.inst.getOpcode());
            if (!recordedExtent && desc.isIndirectBranch()) {
                s.reject(FailureCode::UnsupportedControlFlow,
                         "unsupported control transfer in inferred leaf: indirect jump recovery "
                         "requires a validated unwind-backed function extent");
            }

            if (desc.isCall() && !s.isDirectCall() && !(recordedExtent && s.isRegisterCall())) {
                s.reject(FailureCode::UnsupportedControlFlow, "unsupported indirect or far call");
            }

            if (desc.isBranch() || desc.isReturn()) {
                s.reject(FailureCode::UnsupportedControlFlow, "unsupported control transfer");
            }

            return Flow::Fallthrough;
        }

        class Discovery {
          public:
            Discovery(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                      const MCInstrInfo &info, LeafStepCheck validateLeaf, JumpTableReader *tables,
                      bool registerImports)
                : bytes(bytes), begin(begin), end(begin + static_cast<uint32_t>(bytes.size())),
                  dis(dis), info(info), validateLeaf(validateLeaf), tables(tables),
                  registerImports(registerImports) {
                leaders.emplace(begin, Leader{begin, true, {}});
                pending.push_back(begin);
            }

            bool advance(CallFlow classify);
            void resume(uint32_t instruction);
            bool hasBypassedProof() const;
            ControlFlowGraph finish();

          private:
            StringRef bytes;
            uint32_t begin, end;
            const MCDisassembler &dis;
            const MCInstrInfo &info;
            LeafStepCheck validateLeaf;
            JumpTableReader *tables;
            bool registerImports;
            bool returned = false;
            std::map<uint32_t, Step> decoded;

            struct TableEdges {
                RelativeTable proof;
                SmallVector<uint32_t, 2> targets;
            };

            std::map<uint32_t, TableEdges> resolved;
            std::vector<std::pair<uint32_t, uint32_t>> registerProofs;
            std::multimap<uint32_t, uint32_t> branchPredecessors;
            std::vector<uint32_t> registerImportCalls;
            std::set<uint32_t> unresolved;
            unsigned tableEntries = 0;
            void resolve(uint32_t site);
            std::optional<uint32_t> tableBypass(uint32_t site, const RelativeTable &proof) const;
            std::optional<uint32_t> registerBypass(uint32_t producer, uint32_t call) const;
            std::optional<uint32_t> unprovenRegisterImport() const;
            void validateGuards() const;

            using TableOrigin = std::pair<uint32_t, unsigned>; // Dispatch RVA, entry index.

            struct Leader {
                uint32_t firstSource;
                bool explicitEntry;
                std::optional<TableOrigin> table;
            };

            std::map<uint32_t, Leader> leaders;
            std::vector<uint32_t> pending;
            void schedule(const Step &s, int64_t address, bool explicitEntry,
                          std::optional<unsigned> index = {});
            std::optional<int64_t> registerTarget(Step &call);
            void recordEdges(Step &s, CallFlow classify);
            void trace(uint32_t start, CallFlow classify);
            [[noreturn]] void rejectTableTarget(TableOrigin origin, const Twine &reason) const;
            std::optional<TableOrigin> overlapOrigin(std::optional<TableOrigin> origin,
                                                     uint32_t instruction) const;
            [[noreturn]] void overlap(uint32_t target, uint32_t instruction) const;
            ControlFlowGraph partition();
            void annotate(InspectionError &error) const;
        };

        void Discovery::schedule(const Step &s, int64_t address, bool explicitEntry,
                                 std::optional<unsigned> index) {
            if (address < begin || address >= end) {
                auto dest = address < 0 ? "-" + hex(static_cast<uint64_t>(-address))
                                        : hex(static_cast<uint64_t>(address));
                s.reject(
                    FailureCode::UnsupportedControlFlow,
                    (validateLeaf
                         ? "insufficient evidence: control flow outside inferred leaf bounds to "
                         : "control flow outside function to ") +
                        dest,
                    address);
            }

            auto target = static_cast<uint32_t>(address);
            auto [found, inserted] = leaders.try_emplace(target, Leader{s.rva, explicitEntry, {}});
            auto &leader = found->second;
            leader.explicitEntry |= explicitEntry;

            if (registerImports && explicitEntry) {
                branchPredecessors.emplace(target, s.rva);
            }

            if (index) {
                TableOrigin origin{s.rva, *index};

                if (!leader.table || origin < *leader.table) {
                    leader.table = origin;
                }
            }

            if (inserted) {
                pending.push_back(target);
            }
        }

        void Discovery::rejectTableTarget(TableOrigin origin, const Twine &reason) const {
            const auto [site, index] = origin;
            const auto &edges = resolved.at(site);
            edges.proof.rejectEntry(decoded.at(site), index, FailureCode::InvalidBranchTarget,
                                    reason, edges.targets[index]);
        }

        std::optional<Discovery::TableOrigin>
        Discovery::overlapOrigin(std::optional<TableOrigin> origin, uint32_t instruction) const {
            if (resolved.empty()) {
                return {};
            }

            // A case may fall through other leaders before its instruction crosses
            // the target. On failure, consider every such table edge on either side.
            auto before = decoded.lower_bound(instruction);

            for (;;) {
                const auto leader = leaders.find(instruction);

                if (leader != leaders.end() && leader->second.table &&
                    (!origin || leader->second.table < origin)) {
                    origin = leader->second.table;
                }

                if (before == decoded.begin()) {
                    return origin;
                }

                const auto &previous = (--before)->second;

                if (previous.next != instruction || previous.flow != Flow::Fallthrough) {
                    return origin;
                }

                instruction = previous.rva;
            }
        }

        void Discovery::overlap(uint32_t target, uint32_t instruction) const {
            const auto &leader = leaders.at(target);
            const auto reason = "branch enters an instruction at " + hex(target);

            if (const auto origin = overlapOrigin(leader.table, instruction)) {
                rejectTableTarget(*origin,
                                  reason + " (instruction begins at " + hex(instruction) + ")");
            }

            const auto &source = decoded.at(leader.firstSource);
            source.reject(validateLeaf ? FailureCode::InvalidCallTarget
                                       : FailureCode::UnsupportedControlFlow,
                          reason, target);
        }

        std::optional<int64_t> Discovery::registerTarget(Step &call) {
            const auto &regs = *dis.getContext().getRegisterInfo();
            const InstructionOperands operands(regs, 0);
            // Only the current block can supply a direct LEA. Later branch or table
            // edges may split this provisional block and must still validate at publication.
            const auto leader = std::prev(leaders.upper_bound(call.rva))->first;
            const auto first = std::make_reverse_iterator(decoded.find(call.rva));
            const auto stop = std::make_reverse_iterator(decoded.find(leader));
            const auto producer =
                std::find_if(first, stop, [](const auto &row) { return !isNoop(row.second); });
            const bool lea = producer != stop && producer->second.opcode == "LEA64r";
            if (!lea) {
                call.guardedPointerCall = recognizeGuardedPointerCall(decoded, call, operands);
                if (call.guardedPointerCall) {
                    registerProofs.emplace_back(call.guardedPointerCall->producer, call.rva);
                    return {};
                }
            }

            if (registerImports && (!lea || producer->second.inst.getOperand(0).getReg() !=
                                                call.inst.getOperand(0).getReg())) {
                call.registerImportSlot =
                    reachingImportSlot(decoded, branchPredecessors, call, info, regs);
                if (call.registerImportSlot) {
                    registerImportCalls.push_back(call.rva);
                    return {};
                }
            }

            const auto proof =
                operands.leaCallTarget(call, producer == stop ? nullptr : &producer->second);
            registerProofs.emplace_back(proof.producer, call.rva);
            return proof.target;
        }

        void Discovery::recordEdges(Step &s, CallFlow classify) {
            if (s.isRegisterCall()) {
                s.flow = classify(s, registerTarget(s));
            } else if (classify && (s.isDirectCall() || s.isMemoryCall())) {
                s.flow = classify(s, s.directCallTarget());
            } else if (s.flow == Flow::Return) {
                returned = true;
            } else if (s.flow == Flow::Indirect) {
                unresolved.insert(s.rva);
            } else if (s.flow == Flow::Conditional || s.flow == Flow::Jump) {
                schedule(s, int64_t(s.next) + s.inst.getOperand(0).getImm(), true);

                if (s.flow == Flow::Conditional) {
                    schedule(s, s.next, false);
                }
            }
        }

        void Discovery::trace(uint32_t start, CallFlow classify) try {
            for (auto rva = start; rva < end;) {
                auto after = decoded.lower_bound(rva);
                if (after != decoded.end() && after->first == rva) {
                    return;
                }

                if (after != decoded.begin() && std::prev(after)->second.next > rva) {
                    const auto instruction = std::prev(after)->first;
                    overlap(rva, instruction);
                }

                if (validateLeaf && decoded.size() >= maxLeafInstructions) {
                    throw InspectionError(
                        hex(rva) +
                            ": insufficient evidence within the inferred leaf instruction budget",
                        FailureCode::UnsupportedControlFlow);
                }

                auto s = decodeStep(bytes.drop_front(rva - begin), rva, dis, info);
                // A forward target may already be scheduled, even before its decode.
                auto leader = leaders.upper_bound(rva);
                if (leader != leaders.end() && leader->first < s.next) {
                    overlap(leader->first, rva);
                }

                checkPrefix(s);
                s.flow = control(s, info, tables != nullptr);

                if (validateLeaf) {
                    validateLeaf(s, s.flow);
                }

                auto &step = decoded.emplace_hint(after, rva, std::move(s))->second;
                recordEdges(step, classify);

                if (step.flow != Flow::Fallthrough) {
                    return;
                }

                rva = step.next;
            }
        } catch (const InspectionError &error) {
            const auto location = error.context.instructionRva;

            if (error.kind != FailureCode::InvalidInstruction || !location) {
                throw;
            }

            const auto leader = leaders.find(*location);

            if (leader != leaders.end() && leader->second.table) {
                rejectTableTarget(leader->second.table.value(), error.what());
            }

            throw;
        }

        void Discovery::resolve(uint32_t site) {
            const auto &jump = decoded.at(site);
            auto proof = tables->recognize(decoded, jump);
            constexpr unsigned maxFunctionEntries = 4096;

            if (proof.count > maxFunctionEntries - tableEntries) {
                jump.reject(FailureCode::UnsupportedControlFlow,
                            proof.describe() + ": function jump-table recovery budget exceeded");
            }

            tableEntries += proof.count;
            auto targets = tables->targets(jump, proof, {begin, end});
            auto &edges =
                resolved.emplace(site, TableEdges{proof, std::move(targets)}).first->second;

            for (unsigned i = 0; i < edges.targets.size(); ++i) {
                schedule(jump, edges.targets[i], true, i);
            }
        }

        std::optional<uint32_t> Discovery::tableBypass(uint32_t site,
                                                       const RelativeTable &proof) const {
            // Only sequential execution from CMP may reach its JA and the dispatch prefix.
            // Include edges discovered through other tables and case/loop backedges.
            const auto stop = leaders.upper_bound(site);
            const auto alternate =
                std::find_if(leaders.upper_bound(proof.compareRva), stop,
                             [](const auto &leader) { return leader.second.explicitEntry; });
            return alternate == stop ? std::nullopt : std::optional(alternate->first);
        }

        std::optional<uint32_t> Discovery::registerBypass(uint32_t producer, uint32_t call) const {
            const bool guarded = decoded.at(call).guardedPointerCall.has_value();
            // The null guard deliberately creates a fallthrough leader. Any explicit
            // edge into the middle, including one discovered after CALL, bypasses evidence.
            for (auto it = leaders.upper_bound(producer); it != leaders.end() && it->first <= call;
                 ++it) {
                if (!guarded || it->second.explicitEntry) {
                    return it->first;
                }
            }
            return {};
        }

        std::optional<uint32_t> Discovery::unprovenRegisterImport() const {
            // An edge discovered after the first visit can carry a different definition,
            // including through a resumed guest call or a newly resolved jump table.
            for (auto site : registerImportCalls) {
                const auto &call = decoded.at(site);
                if (reachingImportSlot(decoded, branchPredecessors, call, info,
                                       *dis.getContext().getRegisterInfo()) !=
                    call.registerImportSlot) {
                    return site;
                }
            }

            return {};
        }

        bool Discovery::hasBypassedProof() const {
            if (unprovenRegisterImport()) {
                return true;
            }

            for (const auto &[producer, call] : registerProofs) {
                if (registerBypass(producer, call)) {
                    return true;
                }
            }

            return llvm::any_of(resolved, [&](const auto &table) {
                return tableBypass(table.first, table.second.proof).has_value();
            });
        }

        void Discovery::validateGuards() const {
            if (auto site = unprovenRegisterImport()) {
                const auto &call = decoded.at(*site);
                call.reject(
                    FailureCode::UnsupportedControlFlow,
                    "register call does not retain the same IAT load on every incoming path", {},
                    call.registerImportSlot);
            }

            for (const auto &[producer, call] : registerProofs) {
                if (!decoded.at(call).guardedPointerCall) {
                    continue;
                }

                if (const auto bypass = registerBypass(producer, call)) {
                    decoded.at(call).reject(
                        FailureCode::UnsupportedControlFlow,
                        "edge bypasses indirect call pointer proof at " + hex(*bypass), *bypass);
                }
            }
            for (const auto &[site, edges] : resolved) {
                if (auto alternate = tableBypass(site, edges.proof)) {
                    decoded.at(site).reject(FailureCode::UnsupportedControlFlow,
                                            edges.proof.describe() +
                                                ": unproven bounds: edge bypasses proof at " +
                                                hex(*alternate),
                                            *alternate);
                }
            }
        }

        ControlFlowGraph Discovery::partition() {
            ControlFlowGraph graph;
            for (const auto &[start, source] : leaders) {
                auto &block = graph[start];
                auto it = decoded.find(start);

                for (;;) {
                    auto &step = block.steps.emplace_back(std::move(it->second));
                    block.exit = step.flow;
                    if (block.exit == Flow::Jump || block.exit == Flow::Conditional) {
                        block.successors.push_back(static_cast<uint32_t>(
                            int64_t(step.next) + step.inst.getOperand(0).getImm()));
                    }

                    if (block.exit == Flow::Indirect) {
                        auto &edges = resolved.at(step.rva);
                        block.table = edges.proof;
                        block.successors = std::move(edges.targets);
                    }

                    if (block.exit == Flow::Conditional) {
                        block.successors.push_back(step.next);
                    }

                    if (block.exit != Flow::Fallthrough) {
                        break;
                    }

                    if (step.next == end) {
                        block.exit = Flow::FallOff;
                        break;
                    }

                    if (leaders.contains(step.next)) {
                        block.successors.push_back(step.next);
                        break;
                    }

                    ++it;
                }
            }

            return graph;
        }

        bool Discovery::advance(CallFlow classify) try {
            if (bytes.size() > maxFunctionBytes) {
                throw InspectionError(hex(begin) +
                                          ": experimental lift limit is 64 KiB per function",
                                      FailureCode::FunctionSize);
            }

            while (!pending.empty() || !unresolved.empty()) {
                if (pending.empty()) {
                    resolve(unresolved.extract(unresolved.begin()).value());
                    continue;
                }

                const auto start = pending.back();
                pending.pop_back();
                trace(start, classify);
            }

            return returned;
        } catch (InspectionError &error) {
            annotate(error);
            throw;
        }

        void Discovery::annotate(InspectionError &error) const {
            if (error.context.instructionRva) {
                const auto leader = std::prev(leaders.upper_bound(*error.context.instructionRva));
                error.context.blockRva = leader->first;
            }
        }

        void Discovery::resume(uint32_t instruction) {
            auto &call = decoded.at(instruction);
            call.flow = Flow::Fallthrough;

            if (call.next < end && !decoded.contains(call.next)) {
                pending.push_back(call.next);
            }
        }

        ControlFlowGraph Discovery::finish() try {
            validateGuards();
            return partition();
        } catch (InspectionError &error) {
            annotate(error);
            throw;
        }

    } // namespace

    struct RecordedCFG::State : Discovery {
        using Discovery::Discovery;
    };

    RecordedCFG::RecordedCFG(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                             const MCInstrInfo &info, JumpTableReader &tables, bool registerImports)
        : state(std::make_unique<State>(bytes, begin, dis, info, nullptr, &tables,
                                        registerImports)) {}

    RecordedCFG::~RecordedCFG() = default;

    bool RecordedCFG::advance(CallFlow classify) { return state->advance(classify); }

    void RecordedCFG::resume(uint32_t instruction) { state->resume(instruction); }

    bool RecordedCFG::hasBypassedProof() const { return state->hasBypassedProof(); }

    ControlFlowGraph RecordedCFG::finish() { return state->finish(); }

    ControlFlowGraph discoverCFG(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                                 const MCInstrInfo &info, LeafStepCheck validateLeaf) {
        Discovery discovery(bytes, begin, dis, info, validateLeaf, nullptr, false);
        discovery.advance({});
        return discovery.finish();
    }
} // namespace forge::x86
