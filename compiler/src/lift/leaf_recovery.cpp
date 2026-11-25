#include "lift/leaf_recovery.h"
#include "analysis/analysis.h"
#include "lift/operands.h"

#include "llvm/MC/MCDisassembler/MCDisassembler.h"

namespace forge::x86 {
    using namespace llvm;

    // Ineligible records also fence inference. An empty or reversed record claims its start.
    std::vector<RvaRange> recordedFunctionRanges(const AnalyzedImage &analysis) {
        std::vector<RvaRange> ranges;

        for (const auto &f : analysis.functions()) {
            const uint64_t begin = f.record.begin;
            const uint64_t end = std::max<uint64_t>(begin + 1, f.record.end);

            if (!ranges.empty() && begin <= ranges.back().end) {
                ranges.back().end = std::max(ranges.back().end, end);
            } else {
                ranges.push_back({begin, end});
            }
        }

        return ranges;
    }

    namespace {
        // Reachable blocks have contiguous instructions. This temporary index stores their
        // exclusive ends and owner RVAs. Gaps between blocks remain available to other candidates.
        struct BlockIndex {
            struct Span {
                uint32_t end, owner;
            };

            std::map<uint32_t, Span> blocks;

            void add(const RecoveredFunction &f) {
                for (const auto &[rva, block] : f.graph) {
                    blocks.emplace(rva, Span{block.steps.back().next, f.entry});
                }
            }

            const Span *overlap(uint32_t begin, uint64_t end) const {
                const auto after = blocks.upper_bound(begin);

                if (after != blocks.begin() && std::prev(after)->second.end > begin) {
                    return &std::prev(after)->second;
                }

                return after != blocks.end() && after->first < end ? &after->second : nullptr;
            }
        };

        void checkLeafEffects(const Step &step, Flow flow, const InstructionOperands &operands) {
            if (flow != Flow::Fallthrough || isNoop(step)) {
                return;
            }

            if (step.isDirectCall()) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "inferred leaf contains a nested call");
            }

            if (stackInstruction(step.opcode)) {
                step.reject(FailureCode::UnsupportedControlFlow, "inferred leaf modifies RSP");
            }

            std::optional<RegisterView> dest;

            if (auto op = integerInstruction(step.opcode)) {
                operands.validateIntegerOperands(step, *op);

                if (writesRegister(*op)) {
                    dest = operands.destination(step, *op);
                }
            } else {
                dest = operands.resultRegister(step);

                if (!dest) {
                    step.reject(FailureCode::UnsupportedInstruction,
                                "instruction effects are unsupported for inferred leaf recovery");
                }

                if (step.opcode == "LEA64r" || step.opcode == "LEA64_32r") {
                    operands.decodeAddress(step, 1, false);
                } else if (step.opcode.starts_with("CMOV")) {
                    operands.reg(step, step.inst.getOperand(2), dest->width);
                }
            }

            if (dest && (dest->index == rspIndex || nonvolatile(dest->index))) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "inferred leaf modifies " + registerName(dest->index));
            }
        }

        struct LeafRecovery {
            const ValidatedEntry &entry;
            std::map<uint32_t, RecoveredFunction> &functions;
            const std::map<uint32_t, const ResolvedCallSite *> &deferred;
            ArrayRef<RvaRange> recorded;
            ArrayRef<RvaRange> thunks;
            ArrayRef<RvaRange> loaderWrites;
            const MCDisassembler &dis;
            const MCInstrInfo &instructions;
            const InstructionOperands operands;
            BlockIndex occupied;

            std::string ownerEvidence(uint32_t rva) const;
            MappedRange window(uint32_t rva) const;
            ControlFlowGraph decode(uint32_t target, const MappedRange &code) const;
            void recover(uint32_t target, const ResolvedCallSite &call);
        };

        std::string LeafRecovery::ownerEvidence(uint32_t rva) const {
            const auto site = deferred.find(rva);

            if (site == deferred.end()) {
                return hex(rva);
            }

            return hex(rva) + " called at " + hex(site->second->instruction);
        }

        MappedRange LeafRecovery::window(uint32_t rva) const {
            const auto mapped = entry.analysis.image().mapRva(rva);

            if (!mapped || mapped->section.permissions[2] != 'x') {
                throw InspectionError("target is outside file-backed executable bytes",
                                      FailureCode::InvalidCallTarget);
            }

            const auto next =
                std::partition_point(recorded.begin(), recorded.end(),
                                     [rva](RvaRange range) { return range.end <= rva; });

            if (next != recorded.end() && next->begin <= rva) {
                throw InspectionError("target conflicts with a recorded function range at " +
                                          hex(next->begin),
                                      FailureCode::UnsupportedControlFlow);
            }

            uint64_t end = std::min<uint64_t>(UINT32_MAX, uint64_t(rva) + maxFunctionBytes);

            if (next != recorded.end()) {
                end = std::min(end, next->begin);
            }

            return {mapped->section, mapped->bytes.take_front(end - rva), mapped->fileOffset};
        }

        ControlFlowGraph LeafRecovery::decode(uint32_t target, const MappedRange &code) const try {
            bool returned = false;
            auto validate = [&](const Step &step, Flow flow) {
                if (!rangesIn(thunks, {step.rva, step.next}).empty()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "candidate overlaps a proven import thunk");
                }

                if (const auto *span = occupied.overlap(step.rva, step.next)) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "candidate overlaps decoded function " +
                                    ownerEvidence(span->owner));
                }

                if (const auto *rel = entry.relocations.firstOverlap({step.rva, step.next})) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "leaf instruction overlaps base relocation at " + hex(rel->rva));
                }

                const auto writes = rangesIn(loaderWrites, {step.rva, step.next});
                if (!writes.empty()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "leaf instruction overlaps loader-written bytes at " +
                                    hex(std::max<uint64_t>(step.rva, writes.front().begin)));
                }

                checkLeafEffects(step, flow, operands);
                returned |= flow == Flow::Return;

                if (flow == Flow::Fallthrough &&
                    step.next == uint64_t(target) + code.bytes.size()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "insufficient evidence: fallthrough reaches decode boundary " +
                                    hex(step.next),
                                step.next);
                }
            };

            auto graph = discoverCFG(code.bytes, target, dis, instructions, validate);

            if (!returned) {
                throw InspectionError("insufficient evidence: no reachable normal return",
                                      FailureCode::UnsupportedControlFlow);
            }

            return graph;
        } catch (const InspectionError &error) {
            const uint64_t end = uint64_t(target) + code.bytes.size();
            const uint64_t fileEnd = uint64_t(code.section.rva) + code.section.initializedSize();
            const auto location = error.context.instructionRva;
            if (!location || end >= fileEnd || end - *location >= 15) {
                throw;
            }

            if (error.kind != FailureCode::InvalidInstruction &&
                error.kind != FailureCode::UnsupportedPrefix) {
                throw;
            }

            // Diagnostic lookahead only. No instruction past the fence enters the CFG.
            const auto tail = entry.analysis.image().mapRva(*location);
            MCInst probe;
            uint64_t size = 0;
            if (!tail || &tail->section != &code.section ||
                dis.getInstruction(probe, size, arrayRefFromStringRef(tail->bytes.take_front(15)),
                                   *location, nulls()) != MCDisassembler::Success ||
                size <= end - *location) {
                throw;
            }

            InspectionError failure(
                hex(*location) + ": insufficient evidence: instruction crosses decode boundary " +
                    hex(end),
                FailureCode::UnsupportedControlFlow);
            failure.context = error.context;
            failure.context.functionRva = target;
            failure.context.bytes = toHex(code.bytes.drop_front(*location - target), true);
            failure.context.opcode.clear();
            throw failure;
        }

        void LeafRecovery::recover(uint32_t target, const ResolvedCallSite &call) try {
            if (const auto *span = occupied.overlap(target, uint64_t(target) + 1)) {
                const auto *step = functions.at(span->owner).instructionContaining(target);

                if (step->rva != target) {
                    throw InspectionError("call enters decoded instruction at " + hex(step->rva) +
                                              " in function " + ownerEvidence(span->owner),
                                          FailureCode::InvalidCallTarget);
                }

                throw InspectionError(
                    "unsupported call target belongs to a decoded block of function " +
                        ownerEvidence(span->owner),
                    FailureCode::UnsupportedControlFlow);
            }

            const auto code = window(target);
            auto graph = decode(target, code);
            auto &leaf = functions.try_emplace(target, target, RecoveryOrigin::InferredLeaf, code)
                             .first->second;
            leaf.mayReturn = true;
            leaf.graph = std::move(graph);
            occupied.add(leaf);
        } catch (InspectionError &error) {
            const bool localEdge = error.kind == FailureCode::UnsupportedControlFlow &&
                                   error.context.branchTarget.has_value();

            if (error.context.functionRva || localEdge ||
                (error.kind != FailureCode::InvalidCallTarget &&
                 error.kind != FailureCode::UnsupportedControlFlow)) {
                error.context.functionRva = target;
                error.context.sourceCall = CallLocation{call.caller, call.instruction};
                throw;
            }

            // Keep call-target diagnostics anchored to the original CALL, including its bytes.
            const auto *site = functions.at(call.caller).instructionContaining(call.instruction);
            try {
                const auto destination =
                    call.external() ? site->directCallTarget() : std::optional<int64_t>{target};
                site->reject(error.kind,
                             "cannot recover leaf at " + hex(target) + ": " + error.what(),
                             destination);
            } catch (InspectionError &failure) {
                failure.context.blockRva = call.block;

                if (call.caller != entry.rva) {
                    failure.context.functionRva = call.caller;
                }

                throw;
            }
        }
    } // namespace

    void recoverLeaves(const ValidatedEntry &entry,
                       std::map<uint32_t, RecoveredFunction> &functions,
                       const std::map<uint32_t, const ResolvedCallSite *> &deferred,
                       ArrayRef<RvaRange> recorded, ArrayRef<RvaRange> thunks,
                       ArrayRef<RvaRange> loaderWrites, const MCDisassembler &dis,
                       const MCInstrInfo &instructions, const MCRegisterInfo &regs) {
        LeafRecovery recovery{
            entry,    functions,    deferred,
            recorded, thunks,       loaderWrites,
            dis,      instructions, InstructionOperands(regs, entry.analysis.module().imageBase),
            {}};

        for (const auto &[rva, function] : functions) {
            recovery.occupied.add(function);
        }

        for (const auto &[rva, call] : deferred) {
            try {
                recovery.recover(rva, *call);
            } catch (InspectionError &error) {
                if (call->external()) {
                    call->annotateCallbackFailure(error.context, rva);
                }
                throw;
            }
        }
    }
} // namespace forge::x86
