#include "lift/group_analysis.h"
#include "lift/address_fact.h"
#include "lift/operands.h"
#include "lift/recovery.h"

#include <algorithm>
#include <set>
#include <utility>

namespace forge::x86 {
    namespace {
        struct AddressFacts {
            std::array<AddressFact, registerCount> registers;
            StackSpills spills;

            bool merge(const AddressFacts &other) {
                bool changed = spills.merge(other.spills);

                for (size_t i = 0; i < registers.size(); ++i) {
                    auto joined = registers[i].join(other.registers[i]);
                    changed |= joined != registers[i];
                    registers[i] = std::move(joined);
                }

                return changed;
            }
        };

        struct CallInputs {
            AddressFact rsp;
            std::array<AddressFact, 4> arguments;

            bool merge(const CallInputs &other) {
                const auto before = *this;
                rsp = rsp.join(other.rsp);

                for (size_t i = 0; i < arguments.size(); ++i) {
                    arguments[i] = arguments[i].join(other.arguments[i]);
                }

                return rsp != before.rsp || arguments != before.arguments;
            }
        };

        // A missing entry or return means no such path has reached the worklist.
        // An observed call or return may carry a genuinely unknown guest value.
        struct CallAddresses {
            struct FunctionState {
                explicit FunctionState(const CallInputs &inputs) : entry(inputs) {}

                CallInputs entry;
                std::optional<AddressFact> returned;
                bool restart = false;
                std::set<uint32_t> readyBlocks;
                // (caller, block) pairs suspended before this function's first return.
                std::set<std::pair<uint32_t, uint32_t>> waiting;
            };

            std::map<uint32_t, FunctionState> functions;
            std::set<uint32_t> pending;

            void enter(uint32_t target, const CallInputs &inputs) {
                auto [it, inserted] = functions.try_emplace(target, inputs);

                if (!inserted && !it->second.entry.merge(inputs)) {
                    return;
                }

                it->second.restart = true;
                pending.insert(target);
            }

            void recordReturn(uint32_t rva, const AddressFact &value,
                              llvm::ArrayRef<const ResolvedCallSite *> sites) {
                auto &state = functions.at(rva);

                if (!state.returned) {
                    state.returned = value;

                    for (auto [caller, block] : state.waiting) {
                        functions.at(caller).readyBlocks.insert(block);
                        pending.insert(caller);
                    }

                    state.waiting.clear();
                    return;
                }

                const auto joined = state.returned->join(value);

                if (*state.returned == joined) {
                    return;
                }

                // Earlier caller prefixes may already have used the old return fact.
                state.returned = joined;

                for (const auto *site : sites) {
                    const auto caller = site->caller;
                    const auto parent = functions.find(caller);

                    if (parent != functions.end()) {
                        parent->second.restart = true;
                        pending.insert(caller);
                    }
                }
            }
        };

        class FunctionAnalyzer {
          public:
            FunctionAnalyzer(const RecoveredFunctionGroup &group, uint32_t rva,
                             const InstructionOperands &operands, ImageMemory &imageMemory,
                             FunctionPlan &plan)
                : group(group), function(group.function(rva)), rva(rva), operands(operands),
                  imageMemory(imageMemory), plan(plan) {}

            void summarizeFunction(FunctionFlow &flow);
            void analyzeAddresses(CallAddresses &calls);
            void collectAddresses(CallAddresses &calls);
            bool accessesMemory = false;
            bool tracksOrigins = false;

          private:
            const RecoveredFunctionGroup &group;
            const RecoveredFunction &function;
            uint32_t rva;
            const InstructionOperands &operands;
            ImageMemory &imageMemory;
            FunctionPlan &plan;
            AddressFact entryAddresses;
            std::map<uint32_t, AddressFacts> blockAddresses;

            struct AddressCursor {
                size_t index;
                AddressFacts facts;
            };

            std::map<uint32_t, AddressCursor> suspendedBlocks;
            void recordWrite(DefinitionEffect &state, RegisterView view);
            void requireMemory(const Step &s);
            void planMemoryAccess(const Step &s, const IntegerInstruction &op,
                                  const AddressOperand &operand, const AddressFact &address);
            void traceStackInstruction(const Step &s, StackOp op, AddressFacts &facts) const;
            AddressFact integerFact(const Step &s, const IntegerInstruction &op, RegisterView dest,
                                    const AddressFacts &facts) const;
            void traceInteger(const Step &s, const IntegerInstruction &op, AddressFacts &facts,
                              bool collect, const std::optional<RelativeTable> &table);
            AddressFact savedAddress(const AddressFacts &facts, const AddressFact &address) const;
            bool traceCall(const ResolvedCallSite &site, AddressFacts &facts, CallAddresses &calls,
                           bool collect) const;
            size_t traceAddresses(const GuestBlock &block, AddressFacts &facts,
                                  CallAddresses &calls, bool collect, size_t start = 0);
            void summarize(const Step &s, DefinitionEffect &state);
        };

        void FunctionAnalyzer::recordWrite(DefinitionEffect &state, RegisterView view) {
            state.writes[view.index] |= view.writeMask();
            plan.modified.set(view.index);
            tracksOrigins |= nonvolatile(view.index);
        }

        void FunctionAnalyzer::requireMemory(const Step &s) {
            if (!accessesMemory) {
                imageMemory.checkStackMapping(s);
                accessesMemory = true;
            }
        }

        AddressFact addressFact(const AddressOperand &operand, const AddressFacts &facts) {
            AddressFact result(operand.displacement);

            if (operand.base) {
                result = result.plus(facts.registers[operand.base->index]);
            }

            if (operand.index) {
                result = result.plus(facts.registers[operand.index->index].times(operand.scale));
            }

            return result;
        }

        AddressFact FunctionAnalyzer::integerFact(const Step &s, const IntegerInstruction &op,
                                                  RegisterView dest,
                                                  const AddressFacts &facts) const {
            const auto &last = s.inst.getOperand(s.inst.getNumOperands() - 1);

            if (op.op == Op::Mov && op.form == Form::Immediate && dest.width >= 32) {
                return AddressFact(static_cast<uint64_t>(last.getImm()) & dest.mask());
            }

            if (dest.width < 32 || (op.form != Form::Pair && op.form != Form::Immediate &&
                                    op.form != Form::Accumulator)) {
                return {};
            }

            const auto &lhs = facts.registers[dest.index];

            if ((op.op == Op::Xor || op.op == Op::Sub) && operandsCancel(s, op)) {
                // Known 64-bit constant subtraction already supplied a constant offset
                // for the checked stack path. Newly proved zeros are computed facts.
                return op.op == Op::Sub && dest.width == 64 && lhs.known()
                           ? lhs.times(0)
                           : AddressFact(0, AddressFact::Computed);
            }

            if (op.op == Op::And && last.isImm()) {
                return lhs.masked(static_cast<uint64_t>(last.getImm()) & dest.mask());
            }

            if (dest.width == 32 && !last.isImm() && op.op != Op::Mov) {
                return {};
            }

            auto rhs = last.isImm() ? AddressFact(static_cast<uint64_t>(last.getImm()))
                                    : facts.registers[operands.reg(s, last, dest.width).index];

            if (op.op == Op::Mov) {
                return dest.width == 64 ? rhs : rhs.masked(dest.mask());
            }

            if (op.op != Op::Add && op.op != Op::Sub) {
                return {};
            }

            auto sum = lhs.plus(op.op == Op::Sub ? rhs.times(uint64_t(0) - 1) : rhs);
            return dest.width == 64 ? sum : sum.masked(dest.mask());
        }

        void FunctionAnalyzer::planMemoryAccess(const Step &s, const IntegerInstruction &op,
                                                const AddressOperand &operand,
                                                const AddressFact &address) {
            const bool write = memoryDestination(op.form) && op.op != Op::Cmp;

            if (!operand.base && !operand.index) {
                imageMemory.fixedAccess(s, operand.displacement, op.sourceWidth, write);
                return;
            }

            if (address.stackDerived()) {
                plan.stackAccesses.insert(s.rva);
                return;
            }

            for (const auto &origin : address.continuations()) {
                imageMemory.continuationAccess(s, origin, group.function(origin.callee).incoming,
                                               op.sourceWidth, write);
            }

            if (address.hasUnknown()) {
                imageMemory.computedAccess(s, std::nullopt, op.sourceWidth, write);
            }

            auto onStack = [](uint64_t va) {
                return va - GuestMemory::base < GuestMemory::capacity;
            };

            if (address.known() && llvm::all_of(address.values(), onStack)) {
                plan.stackAccesses.insert(s.rva);
                return;
            }

            for (auto va : address.values()) {
                imageMemory.computedAccess(s, va, op.sourceWidth, write);
            }
        }

        AddressFact FunctionAnalyzer::savedAddress(const AddressFacts &facts,
                                                   const AddressFact &address) const {
            // An argument can also carry the exact absolute address of the slot.
            // Equal sets with several alternatives need not agree on a given path.
            const bool absoluteSlot = address.known() && entryAddresses.known() &&
                                      entryAddresses.values().size() == 1 &&
                                      address.values() == entryAddresses.values();

            if (!function.incoming.empty() && (address.frameOffset() == 0 || absoluteSlot)) {
                // The current activation protects all eight bytes until its RET.
                // At the external entry the synthetic slot still faults on access.
                return AddressFact::continuation(rva);
            }

            return facts.spills.read(address);
        }

        void FunctionAnalyzer::traceStackInstruction(const Step &s, StackOp op,
                                                     AddressFacts &facts) const {
            auto &rsp = facts.registers[rspIndex];

            if (op == StackOp::Leave) {
                rsp = facts.registers[framePointer.index];
            }

            if (op == StackOp::Pop || op == StackOp::Leave) {
                const auto dest =
                    op == StackOp::Pop ? operands.reg(s, s.inst.getOperand(0), 64) : framePointer;
                auto saved = savedAddress(facts, rsp);
                rsp = rsp.plus(AddressFact(8));
                facts.registers[dest.index] = std::move(saved);
            } else {
                const auto &operand = s.inst.getOperand(0);
                auto saved = op == StackOp::PushRegister
                                 ? facts.registers[operands.reg(s, operand, 64).index]
                                 : AddressFact(static_cast<uint64_t>(operand.getImm()));
                rsp = rsp.plus(AddressFact(uint64_t(0) - 8));
                facts.spills.write(rsp, 64, saved);
            }
        }

        void FunctionAnalyzer::traceInteger(const Step &s, const IntegerInstruction &op,
                                            AddressFacts &facts, bool collect,
                                            const std::optional<RelativeTable> &table) {
            if (!hasMemoryOperand(op.form)) {
                if (writesRegister(op)) {
                    auto dest = operands.destination(s, op);
                    facts.registers[dest.index] = integerFact(s, op, dest, facts);
                }

                return;
            }

            const auto operand = operands.decodeAddress(s, memoryOperand(s, op), true);
            const auto address = addressFact(operand, facts);

            if (collect && table && table->loadRva == s.rva) {
                imageMemory.tableRead(s, *table);
            } else if (collect) {
                planMemoryAccess(s, op, operand, address);
            }

            if (writesRegister(op)) {
                auto dest = operands.destination(s, op);
                facts.registers[dest.index] = op.op == Op::Mov && dest.width == 64
                                                  ? savedAddress(facts, address)
                                                  : AddressFact{};
            } else if (memoryDestination(op.form) && op.op != Op::Cmp) {
                AddressFact stored;

                if (op.form == Form::Store && op.width == 64) {
                    const auto &src = s.inst.getOperand(s.inst.getNumOperands() - 1);
                    stored = src.isReg() ? facts.registers[operands.reg(s, src, 64).index]
                                         : AddressFact(static_cast<uint64_t>(src.getImm()));
                }

                facts.spills.write(address, op.width, stored);
            }
        }

        bool FunctionAnalyzer::traceCall(const ResolvedCallSite &site, AddressFacts &facts,
                                         CallAddresses &calls, bool collect) const {
            if (site.external()) {
                std::fill_n(facts.registers.begin(), callerSlots, AddressFact{});
                // These services take no guest pointers. Only CALL writes guest memory.
                const auto slot = facts.registers[rspIndex].plus(AddressFact(uint64_t(0) - 8));
                facts.spills.write(slot, 64, {});
                return true;
            }

            if (!collect) {
                CallInputs inputs;
                inputs.rsp = facts.registers[rspIndex]
                                 .project(entryAddresses)
                                 .plus(AddressFact(uint64_t(0) - 8));

                for (size_t i = 0; i < inputs.arguments.size(); ++i) {
                    inputs.arguments[i] = facts.registers[i + 1].project(entryAddresses);
                }

                calls.enter(site.guest().rva, inputs);
            }

            auto &callee = calls.functions.at(site.guest().rva);

            if (!callee.returned) {
                if (!collect) {
                    callee.waiting.emplace(site.caller, site.block);
                }

                return false;
            }

            // Checked returns preserve RSP and nonvolatiles. Any other volatile
            // or saved stack value can have changed through a register or alias.
            std::fill_n(facts.registers.begin(), callerSlots, AddressFact{});
            facts.registers[0] = *callee.returned;
            facts.spills = {};
            return true;
        }

        size_t FunctionAnalyzer::traceAddresses(const GuestBlock &block, AddressFacts &facts,
                                                CallAddresses &calls, bool collect,
                                                size_t start) try {
            for (size_t index = start; index < block.steps.size(); ++index) {
                const auto &s = block.steps[index];

                if (const auto *site = function.callAt(s.rva)) {
                    if (!traceCall(*site, facts, calls, collect)) {
                        return index;
                    }

                    continue;
                }

                if (auto stack = stackInstruction(s.opcode)) {
                    traceStackInstruction(s, *stack, facts);
                    continue;
                }

                if (auto op = integerInstruction(s.opcode)) {
                    traceInteger(s, *op, facts, collect, block.table);
                    continue;
                }

                auto dest = operands.resultRegister(s);

                if (!dest) {
                    continue;
                }

                auto &result = facts.registers[dest->index];

                if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
                    auto value = addressFact(operands.decodeAddress(s, 1, false), facts);
                    result = dest->width == 64 ? value : value.masked(dest->mask());
                } else if (s.opcode == "CMOV64rr") {
                    const auto src = operands.reg(s, s.inst.getOperand(2), 64);
                    result = result.join(facts.registers[src.index]).computed();
                } else {
                    result = {};
                }
            }

            return block.steps.size();
        } catch (InspectionError &failure) {
            if (failureKind(failure.kind).stage == "lifting") {
                failure.context.blockRva = block.steps.front().rva;
            }

            throw;
        }

        void FunctionAnalyzer::analyzeAddresses(CallAddresses &calls) {
            auto &state = calls.functions.at(rva);
            const auto &incoming = function.incoming;
            auto pending = std::exchange(state.readyBlocks, {});

            if (std::exchange(state.restart, false)) {
                blockAddresses.clear();
                suspendedBlocks.clear();
                pending = {rva};

                entryAddresses = state.entry.rsp;
                auto &registers = blockAddresses[rva].registers;
                const auto &arguments = state.entry.arguments;
                std::copy(arguments.begin(), arguments.end(), registers.begin() + 1);
                registers[rspIndex] = incoming.empty()
                                          ? AddressFact(GuestMemory::entryRsp, AddressFact::Stack)
                                          : AddressFact::frameStack();
            }

            while (!pending.empty()) {
                const auto address = pending.extract(pending.begin()).value();
                const auto &block = function.graph.at(address);
                auto suspended = suspendedBlocks.extract(address);
                auto cursor = suspended.empty() ? AddressCursor{0, blockAddresses.at(address)}
                                                : std::move(suspended.mapped());
                cursor.index = traceAddresses(block, cursor.facts, calls, false, cursor.index);

                if (cursor.index != block.steps.size()) {
                    // A first return resumes this exact prefix. A widened input,
                    // successor state or previous return invalidates the prefix.
                    suspendedBlocks.emplace(address, std::move(cursor));
                    continue;
                }

                if (block.exit == Flow::Return) {
                    calls.recordReturn(rva, cursor.facts.registers[0].project(entryAddresses),
                                       incoming);
                }

                for (auto successor : block.successors) {
                    auto [it, inserted] = blockAddresses.try_emplace(successor, cursor.facts);

                    if (inserted || it->second.merge(cursor.facts)) {
                        suspendedBlocks.erase(successor);
                        pending.insert(successor);
                    }
                }
            }
        }

        void FunctionAnalyzer::collectAddresses(CallAddresses &calls) {
            for (auto &[address, facts] : blockAddresses) {
                traceAddresses(function.graph.at(address), facts, calls, true);
            }

            blockAddresses.clear();
            suspendedBlocks.clear();
        }

        void FunctionAnalyzer::summarize(const Step &s, DefinitionEffect &state) {
            if (auto op = stackInstruction(s.opcode)) {
                requireMemory(s);
                tracksOrigins = true;
                recordWrite(state, stackPointer);

                if (*op == StackOp::Leave) {
                    recordWrite(state, framePointer);
                } else if (*op == StackOp::Pop) {
                    recordWrite(state, operands.reg(s, s.inst.getOperand(0), 64));
                }

                return;
            }

            if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
                if (auto address = operands.ripAddress(s, 1)) {
                    imageMemory.addressTaken(s, *address);
                }
            }

            RegisterView dest{};

            if (auto instruction = integerInstruction(s.opcode)) {
                if (instruction->op == Op::Mov &&
                    (instruction->form == Form::Pair || instruction->form == Form::Store)) {
                    const auto &src = s.inst.getOperand(s.inst.getNumOperands() - 1);
                    tracksOrigins |=
                        src.isReg() && nonvolatile(operands.reg(s, src, instruction->width).index);
                }

                if (hasMemoryOperand(instruction->form)) {
                    requireMemory(s);
                }

                if (instruction->form == Form::Store) {
                    return;
                }

                auto effect = flagEffect(instruction->op, instruction->width,
                                         shiftCount(s, instruction->form));
                state.flags.generated = effect.apply(state.flags.generated);
                state.flags.carried = effect.apply(state.flags.carried);

                if (!writesRegister(*instruction)) {
                    return;
                }

                dest = operands.destination(s, *instruction);
            } else if (auto result = operands.resultRegister(s)) {
                dest = *result;
            } else {
                return;
            }

            recordWrite(state, dest);
        }

        void FunctionAnalyzer::summarizeFunction(FunctionFlow &flow) {
            for (const auto &[address, block] : function.graph) {
                auto &effects = flow.blocks[address];

                try {
                    for (const auto &s : block.steps) {
                        if (const auto *site = function.callAt(s.rva)) {
                            requireMemory(s);
                            effects.calls.push_back({site, std::exchange(effects.tail, {})});
                        } else {
                            summarize(s, effects.tail);
                        }
                    }
                } catch (InspectionError &failure) {
                    failure.context.blockRva = address;
                    throw;
                }
            }
        }
    } // namespace

    GroupAnalysis analyzeGroup(const RecoveredFunctionGroup &group, uint64_t guestBase,
                               EntryMode mode, bool checkedMemory) try {
        GroupAnalysis result;
        ImageMemory image(group.image(), guestBase, checkedMemory);
        const InstructionOperands operands(group.registers(), guestBase);
        std::map<uint32_t, FunctionAnalyzer> analyzers;

        for (const auto &[address, function] : group.functions()) {
            auto &analyzer = analyzers
                                 .try_emplace(address, group, address, operands, image,
                                              result.functions[address])
                                 .first->second;
            analyzer.summarizeFunction(result.flows[address]);
            result.stack |= analyzer.accessesMemory;
            result.origins |= analyzer.tracksOrigins;
        }

        Definitions initial;
        initial.registers[rspIndex] = UINT64_MAX;

        if (mode == EntryMode::RegisterState) {
            std::fill_n(initial.registers.begin(), callerSlots, UINT64_MAX);
        } else {
            initial.registers[1] = initial.registers[2] = UINT64_MAX;
        }

        proveCallFlow(group, result.flows, initial);
        CallAddresses calls;
        calls.enter(group.root(), {AddressFact(GuestMemory::entryRsp), {}});

        while (!calls.pending.empty()) {
            const auto address = calls.pending.extract(calls.pending.begin()).value();
            analyzers.at(address).analyzeAddresses(calls);
        }

        for (auto &[address, analyzer] : analyzers) {
            analyzer.collectAddresses(calls);
        }

        result.image = std::move(image).finish();
        return result;
    } catch (InspectionError &failure) {
        group.annotateFailure(failure);
        throw;
    } catch (const std::exception &error) {
        InspectionError failure(error.what(), FailureCode::LiftingInternal);
        group.annotateFailure(failure);
        throw failure;
    }
} // namespace forge::x86
