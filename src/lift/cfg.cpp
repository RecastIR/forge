#include "lift/cfg.h"
#include "lift/integer.h"
#include "lift/jump_table.h"
#include "pe/image.h"

#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"

#include <algorithm>
#include <set>

namespace forge::x86 {
    using namespace llvm;

    void Step::reject(FailureCode kind, const Twine &reason, std::optional<int64_t> target) const {
        auto encoded = toHex(bytes, true);
        InspectionError failure(hex(rva) + ": " + (opcode + " [" + encoded + "]: " + reason).str(),
                                kind);
        failure.context.instructionRva = rva;
        failure.context.opcode = opcode.str();
        failure.context.bytes = std::move(encoded);
        failure.context.branchTarget = target;
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
            auto encoding = arrayRefFromStringRef(s.bytes);
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
            return {rva, static_cast<uint32_t>(rva + size), std::move(inst), opcode,
                    tail.take_front(size)};
        }

        Flow control(const Step &s, const MCInstrInfo &info, bool allowTables) {
            if (s.opcode == "RET64") {
                return Flow::Return;
            }

            if (s.opcode == "JMP_1" || s.opcode == "JMP_4") {
                return Flow::Jump;
            }

            if (s.opcode == "JCC_1" || s.opcode == "JCC_4") {
                return Flow::Conditional;
            }

            if (allowTables && s.opcode == "JMP64r") {
                return Flow::Indirect;
            }

            const auto &desc = info.get(s.inst.getOpcode());
            if (!allowTables && desc.isIndirectBranch()) {
                s.reject(FailureCode::UnsupportedControlFlow,
                         "unsupported control transfer in inferred leaf: indirect jump recovery "
                         "requires a validated unwind-backed function extent");
            }

            if (desc.isCall() && !s.isDirectCall()) {
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
                      const MCInstrInfo &info, LeafStepCheck validateLeaf, JumpTableReader *tables)
                : bytes(bytes), begin(begin), end(begin + static_cast<uint32_t>(bytes.size())),
                  dis(dis), info(info), validateLeaf(validateLeaf), tables(tables) {}

            ControlFlowGraph run();

          private:
            StringRef bytes;
            uint32_t begin, end;
            const MCDisassembler &dis;
            const MCInstrInfo &info;
            LeafStepCheck validateLeaf;
            JumpTableReader *tables;
            std::map<uint32_t, Step> decoded;

            struct TableEdges {
                RelativeTable proof;
                SmallVector<uint32_t, 2> targets;
            };

            std::map<uint32_t, TableEdges> resolved;
            std::set<uint32_t> unresolved;
            unsigned tableEntries = 0;
            void resolve(uint32_t site);
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
            void recordEdges(const Step &s, Flow flow);
            void trace(uint32_t start);
            [[noreturn]] void rejectTableTarget(TableOrigin origin, const Twine &reason) const;
            std::optional<TableOrigin> overlapOrigin(std::optional<TableOrigin> origin,
                                                     uint32_t instruction) const;
            [[noreturn]] void overlap(uint32_t target, uint32_t instruction) const;
            ControlFlowGraph partition();
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

                if (previous.next != instruction ||
                    control(previous, info, true) != Flow::Fallthrough) {
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

        void Discovery::recordEdges(const Step &s, Flow flow) {
            if (flow == Flow::Indirect) {
                unresolved.insert(s.rva);
            } else if (flow == Flow::Conditional || flow == Flow::Jump) {
                schedule(s, int64_t(s.next) + s.inst.getOperand(0).getImm(), true);

                if (flow == Flow::Conditional) {
                    schedule(s, s.next, false);
                }
            }
        }

        void Discovery::trace(uint32_t start) try {
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
                auto flow = control(s, info, tables != nullptr);
                if (validateLeaf) {
                    validateLeaf(s, flow);
                }

                auto &step = decoded.emplace_hint(after, rva, std::move(s))->second;
                recordEdges(step, flow);

                if (flow != Flow::Fallthrough) {
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

        void Discovery::validateGuards() const {
            // Only sequential execution from CMP may reach its JA and the dispatch prefix.
            // Include edges discovered through other tables and case/loop backedges.
            for (const auto &[site, edges] : resolved) {
                const auto stop = leaders.upper_bound(site);
                const auto alternate =
                    std::find_if(leaders.upper_bound(edges.proof.compareRva), stop,
                                 [](const auto &leader) { return leader.second.explicitEntry; });

                if (alternate != stop) {
                    decoded.at(site).reject(FailureCode::UnsupportedControlFlow,
                                            edges.proof.describe() +
                                                ": unproven bounds: edge bypasses proof at " +
                                                hex(alternate->first),
                                            alternate->first);
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
                    block.exit = control(step, info, tables != nullptr);
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

        ControlFlowGraph Discovery::run() try {
            if (bytes.size() > maxFunctionBytes) {
                throw InspectionError(hex(begin) +
                                          ": experimental lift limit is 64 KiB per function",
                                      FailureCode::FunctionSize);
            }

            leaders.emplace(begin, Leader{begin, true, {}});
            pending.push_back(begin);

            while (!pending.empty() || !unresolved.empty()) {
                if (pending.empty()) {
                    resolve(unresolved.extract(unresolved.begin()).value());
                    continue;
                }

                const auto start = pending.back();
                pending.pop_back();
                trace(start);
            }

            validateGuards();
            return partition();
        } catch (InspectionError &error) {
            if (error.context.instructionRva) {
                auto leader = std::prev(leaders.upper_bound(*error.context.instructionRva));
                error.context.blockRva = leader->first;
            }

            throw;
        }
    } // namespace

    ControlFlowGraph discoverCFG(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                                 const MCInstrInfo &info, LeafStepCheck validateLeaf) {
        return Discovery(bytes, begin, dis, info, validateLeaf, nullptr).run();
    }

    ControlFlowGraph discoverCFG(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                                 const MCInstrInfo &info, JumpTableReader &tables) {
        return Discovery(bytes, begin, dis, info, {}, &tables).run();
    }
} // namespace forge::x86
