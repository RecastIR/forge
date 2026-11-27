#include "lift/group_analysis.h"
#include "lift/address_fact.h"
#include "lift/operands.h"
#include "lift/recovery.h"
#include "lift/service_location.h"

#include <algorithm>
#include <bit>
#include <set>
#include <utility>

namespace forge::x86 {
    namespace {
        struct AddressFacts {
            std::array<AddressFact, registerCount> registers;
            StackSpills spills;

            AddressFact serviceValue(const win64::ServiceBinding &binding, size_t position,
                                     const AddressFact &entryRsps) const {
                const ServiceLocation location{position};
                const auto width = win64::width(binding.arguments[position].type);
                if (location.inRegister()) {
                    const auto &value = registers[location.registerIndex()];
                    return width == 32 ? value.project(entryRsps).masked(UINT32_MAX) : value;
                }

                const auto slot = registers[rspIndex].plus(AddressFact(location.callerOffset()));
                return spills.read(slot, entryRsps, width).reloaded(entryRsps);
            }

            bool merge(const AddressFacts &other, const AddressFact &entryRsps) {
                bool changed = spills.merge(other.spills, entryRsps);

                for (size_t i = 0; i < registers.size(); ++i) {
                    auto joined = registers[i].joinInFrame(other.registers[i], entryRsps);
                    changed |= joined != registers[i];
                    registers[i] = std::move(joined);
                }

                return changed;
            }
        };

        struct CallInputs {
            // Frame offsets use the original return slot, including across tail transfers.
            AddressFact frameRsp;
            bool callbackFrame = false;
            AddressFacts facts;

            explicit CallInputs(AddressFact frameRsp) : frameRsp(std::move(frameRsp)) {
                facts.registers[rspIndex] = AddressFact::frameStack();
            }

            bool merge(const CallInputs &other) {
                const auto rsp = frameRsp.join(other.frameRsp);
                const bool changed = rsp != frameRsp || (other.callbackFrame && !callbackFrame);
                callbackFrame |= other.callbackFrame;
                frameRsp = rsp;
                return facts.merge(other.facts, frameRsp) || changed;
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

                    // Another alternative may already have resumed the caller past this
                    // site and suspended it at a later call in the same block.
                    for (const auto *site : sites) {
                        if (site->table() && site->guestTargets().size() > 1 &&
                            functions.contains(site->caller)) {
                            functions.at(site->caller).restart = true;
                            pending.insert(site->caller);
                        }
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
                             FunctionPlan &plan, const std::vector<uint32_t> &terminationTargets)
                : group(group), function(group.function(rva)), rva(rva), operands(operands),
                  imageMemory(imageMemory), plan(plan), terminationTargets(terminationTargets) {}

            void summarizeFunction(FunctionFlow &flow);
            void analyzeAddresses(CallAddresses &calls);
            void collectAddresses(CallAddresses &calls);
            bool accessesMemory = false;
            bool tracksOrigins = false;
            bool setsDirection = false;

          private:
            const RecoveredFunctionGroup &group;
            const RecoveredFunction &function;
            uint32_t rva;
            const InstructionOperands &operands;
            ImageMemory &imageMemory;
            FunctionPlan &plan;
            const std::vector<uint32_t> &terminationTargets;
            AddressFact entryAddresses;
            bool callbackFrame = false;
            std::map<uint32_t, AddressFacts> blockAddresses;

            struct AddressCursor {
                size_t index;
                AddressFacts facts;
            };

            std::map<uint32_t, AddressCursor> suspendedBlocks;
            void recordWrite(DefinitionEffect &state, RegisterView view);
            void requireMemory(const Step &s);
            void planMemoryAccess(const Step &s, unsigned width, bool write,
                                  const AddressOperand &operand, const AddressFact &address);
            void traceStackInstruction(const Step &s, StackOp op, AddressFacts &facts) const;
            AddressFact integerFact(const Step &s, const IntegerInstruction &op, RegisterView dest,
                                    const AddressFacts &facts) const;
            void traceInteger(const Step &s, const IntegerInstruction &op, AddressFacts &facts,
                              bool collect, const std::optional<RelativeTable> &table);
            void traceRepeatedStore(const Step &s, AddressFacts &facts, bool collect);
            AddressFact savedAddress(const AddressFacts &facts, const AddressFact &address) const;
            void traceProtectionArguments(const ResolvedCallSite &site, AddressFacts &facts,
                                          bool collect) const;
            void traceServiceArguments(const ResolvedCallSite &site, AddressFacts &facts,
                                       bool collect) const;
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

        void FunctionAnalyzer::planMemoryAccess(const Step &s, unsigned width, bool write,
                                                const AddressOperand &operand,
                                                const AddressFact &address) {
            if (callbackFrame && address.frameOffset()) {
                const auto offset = std::bit_cast<int64_t>(*address.frameOffset());
                if (offset > int64_t{GuestMemory::initializerHomeEnd} - width / 8) {
                    s.reject(FailureCode::UnsupportedControlFlow,
                             "initializer has no incoming Windows x64 stack arguments");
                }
            }

            if (!operand.base && !operand.index) {
                imageMemory.fixedAccess(s, operand.displacement, width, write);
                return;
            }

            if (address.stackDerived()) {
                plan.stackAccesses.insert(s.rva);
                return;
            }

            for (const auto &origin : address.continuations()) {
                imageMemory.continuationAccess(s, origin, group, width, write);
            }

            if (address.hasUnknown()) {
                imageMemory.computedAccess(s, std::nullopt, width, write);
            }

            auto onStack = [](uint64_t va) {
                return va - GuestMemory::base < GuestMemory::capacity;
            };

            if (address.known() && llvm::all_of(address.values(), onStack)) {
                plan.stackAccesses.insert(s.rva);
                return;
            }

            for (auto va : address.values()) {
                imageMemory.computedAccess(s, va, width, write);
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

            return facts.spills.read(address, entryAddresses).reloaded(entryAddresses);
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
            if (operand.gsRelative) {
                // The NT_TIB self pointer is read from process-owned guest memory.
                auto dest = operands.destination(s, op);
                facts.registers[dest.index] = {};
                return;
            }
            const auto address = addressFact(operand, facts);

            // The call-site proof already selected the guest bytes for each bounded access.
            if (collect && table && table->loadRva == s.rva) {
                imageMemory.tableRead(s, *table);
            } else if (collect && !plan.tableInstructions.contains(s.rva)) {
                planMemoryAccess(s, op.sourceWidth, memoryDestination(op.form) && op.op != Op::Cmp,
                                 operand, address);
            }

            if (writesRegister(op)) {
                auto dest = operands.destination(s, op);
                AddressFact value;
                if (op.op == Op::Mov && op.sourceWidth == 64 && dest.width == 64) {
                    value = !operand.base && !operand.index &&
                                    imageMemory.isDataImportPointer(operand.displacement)
                                ? AddressFact::processStorage()
                                : savedAddress(facts, address);
                }
                facts.registers[dest.index] = std::move(value);
            } else if (memoryDestination(op.form) && op.op != Op::Cmp) {
                AddressFact stored;

                if (op.form == Form::Store && (op.width == 64 || op.width == 32)) {
                    const auto &src = s.inst.getOperand(s.inst.getNumOperands() - 1);
                    stored = src.isReg() ? facts.registers[operands.reg(s, src, op.width).index]
                                         : AddressFact(static_cast<uint64_t>(src.getImm()));
                    if (op.width == 32) {
                        stored = stored.project(entryAddresses).masked(UINT32_MAX);
                    }
                }

                facts.spills.write(address, op.width, stored);
            }
        }

        void invalidateServiceOutput(StackSpills &spills, const AddressFact &address,
                                     const AddressFact &entryRsps, std::optional<uint64_t> size) {
            if (const auto offset = address.frameOffset();
                offset && size && *size <= GuestMemory::capacity) {
                const auto key = std::bit_cast<int64_t>(*offset);
                constexpr int64_t capacity = GuestMemory::capacity;
                if (key > -capacity && key < capacity) {
                    spills.write(address, static_cast<unsigned>(*size) * 8, {});
                    return;
                }
            }

            const auto starts = address.project(entryRsps);
            if (!starts.known()) {
                spills = {};
                return;
            }

            bool touchesStack = false;
            for (const auto va : starts.values()) {
                if (!va || va >= GuestMemory::base + GuestMemory::capacity) {
                    continue;
                }

                // An adapter can write a valid subrange even when the declared
                // extent would overflow. Compare offsets without forming an end VA.
                if (va < GuestMemory::base && size && *size <= GuestMemory::base - va) {
                    continue;
                }

                if (va < GuestMemory::base || !size || *size > GuestMemory::capacity) {
                    spills = {};
                    return;
                }

                touchesStack = true;
            }

            if (touchesStack) {
                // Keep frame-relative coordinates when available, so disjoint saves in the
                // same activation survive. A concrete write also invalidates symbolic aliases.
                spills.write(address, static_cast<unsigned>(*size) * 8, {});
            }
        }

        void FunctionAnalyzer::traceRepeatedStore(const Step &s, AddressFacts &facts,
                                                  bool collect) {
            auto &destination = facts.registers[stringDestination.index];
            auto &count = facts.registers[repeatCount.index];
            const auto starts = destination.project(entryAddresses);
            const auto counts = count.project(entryAddresses);
            const auto largest = counts.known() ? *llvm::max_element(counts.values()) : UINT64_MAX;
            count = AddressFact(0);

            if (!largest) {
                return;
            }

            // A bounded count can touch either side of RDI depending on DF. Preserve
            // disjoint saved addresses, and select the stack path only when every
            // qword of both possible traversals is within the guest stack.
            if (largest <= GuestMemory::capacity / 8) {
                const uint64_t size = largest * 8;
                const auto lowest = destination.plus(AddressFact(8 - size));
                invalidateServiceOutput(facts.spills, lowest, entryAddresses, size);
                invalidateServiceOutput(facts.spills, destination, entryAddresses, size);

                if (collect && starts.known() && llvm::all_of(starts.values(), [&](uint64_t va) {
                        const auto offset = va - GuestMemory::base;
                        return offset >= size - 8 && offset <= GuestMemory::capacity - size;
                    })) {
                    plan.stackAccesses.insert(s.rva);
                }
            } else {
                facts.spills = {};
            }

            if (collect && !plan.stackAccesses.contains(s.rva)) {
                imageMemory.computedAccess(s, std::nullopt, 64, true);
            }

            const auto forward = destination.plus(counts.times(8));
            destination = forward.joinInFrame(destination.plus(counts.times(uint64_t{0} - 8)),
                                              entryAddresses);
        }

        void FunctionAnalyzer::traceProtectionArguments(const ResolvedCallSite &site,
                                                        AddressFacts &facts, bool collect) const {
            const auto &binding = win64::virtualProtect;
            const auto target = facts.serviceValue(binding, 0, entryAddresses);
            const auto sizes =
                facts.serviceValue(binding, 1, entryAddresses).project(entryAddresses);
            const auto output = facts.serviceValue(binding, 3, entryAddresses);
            const auto outputSize = binding.arguments[3].size;
            invalidateServiceOutput(facts.spills, output, entryAddresses, outputSize);
            if (!collect) {
                return;
            }

            const auto &step = *function.instructionContaining(site.instruction);
            const auto select = [&](const AddressFact &address, auto known) {
                if (address.known()) {
                    for (const auto va : address.values()) {
                        known(va);
                    }
                } else if (!address.stackDerived() && !address.pointsToProcessStorage() &&
                           !address.frameOffset()) {
                    imageMemory.computedAccess(step, std::nullopt, 8, true);
                }
            };

            const auto selectTarget = [&](std::optional<uint64_t> size) {
                if (size != 0) {
                    select(target,
                           [&](uint64_t va) { imageMemory.protectionTarget(step, va, size); });
                }
            };

            if (sizes.known()) {
                for (const auto size : sizes.values()) {
                    selectTarget(size);
                }
            } else {
                selectTarget(std::nullopt);
            }

            select(output,
                   [&](uint64_t va) { imageMemory.protectionOutput(step, va, outputSize); });
        }

        std::optional<uint64_t> elementExtent(const AddressFact &widths,
                                              const AddressFact &counts) {
            if ((widths.known() && std::ranges::max(widths.values()) == 0) ||
                (counts.known() && std::ranges::max(counts.values()) == 0)) {
                return 0;
            }
            if (!widths.known() || !counts.known()) {
                return std::nullopt;
            }

            uint64_t largest = 0;
            for (const auto width : widths.values()) {
                for (const auto count : counts.values()) {
                    // Overflowing paths return before reading the pointer.
                    largest = std::max(largest, win64::elementBytes(width, count).value_or(0));
                }
            }
            return largest;
        }

        void FunctionAnalyzer::traceServiceArguments(const ResolvedCallSite &site,
                                                     AddressFacts &facts, bool collect) const {
            const auto &binding = site.external()->binding;
            if (binding.nativeSymbol == win64::virtualProtect.nativeSymbol) {
                traceProtectionArguments(site, facts, collect);
                return;
            }

            if (binding.nativeSymbol == win64::crtVfprintf.nativeSymbol) {
                if (collect) {
                    const auto formats =
                        facts.serviceValue(binding, 1, entryAddresses).project(entryAddresses);
                    imageMemory.formattedInputs(*function.instructionContaining(site.instruction),
                                                formats.known() ? formats.values()
                                                                : llvm::ArrayRef<uint64_t>{});
                }

                return;
            }

            // Read all arguments from the incoming state, even when an earlier parameter
            // can overwrite the stack slot that supplies another parameter or its count.
            auto outgoing = facts.spills;
            for (size_t i = 0; i < binding.arguments.size(); ++i) {
                const auto arg = binding.arguments[i];
                if (arg.access == win64::Access::None || (!collect && !arg.writes())) {
                    continue;
                }

                if (arg.extent == win64::Extent::InitializerEnd) {
                    // Recovery proves both bounds, including bounds read through
                    // immutable pointer cells. The whole table is selected at the site.
                    continue;
                }

                std::optional<uint64_t> size;
                if (arg.extent == win64::Extent::Fixed) {
                    size = arg.size;
                } else if (arg.extent == win64::Extent::ElementProduct) {
                    const auto width = facts.serviceValue(binding, arg.size, entryAddresses);
                    const auto count = facts.serviceValue(binding, arg.size + 1, entryAddresses);
                    size =
                        elementExtent(width.project(entryAddresses), count.project(entryAddresses));
                } else if (arg.extent == win64::Extent::CountArgument) {
                    const auto count = facts.serviceValue(binding, arg.size, entryAddresses)
                                           .project(entryAddresses);
                    if (count.known()) {
                        size = std::ranges::max(count.values());
                    }
                }

                if (size == 0) {
                    continue;
                }

                const auto address = facts.serviceValue(binding, i, entryAddresses);
                if (arg.writes()) {
                    invalidateServiceOutput(outgoing, address, entryAddresses, size);
                }

                // A failed allocation plus the same nonzero offset could alias PE data
                // at a low guest base. Such a string still requires image provenance.
                const auto offset = address.allocationOffset();
                const bool heapString = arg.extent == win64::Extent::CString && arg.size &&
                                        offset && !imageMemory.containsImageAddress(*offset);
                if (!collect || address.stackDerived() || address.pointsToProcessStorage() ||
                    heapString || (address.frameOffset() && !address.known())) {
                    continue;
                }

                const auto &step = *function.instructionContaining(site.instruction);
                if (!address.known()) {
                    step.reject(FailureCode::ImageMemory,
                                "argument " + std::to_string(i + 1) + " to " +
                                    std::string(binding.name) +
                                    " requires proven image/stack provenance, process storage or "
                                    "bounded address "
                                    "alternatives");
                }

                for (const auto va : address.values()) {
                    imageMemory.serviceArgument(step, va, arg, size);
                }
            }

            facts.spills = std::move(outgoing);
        }

        AddressFact serviceResult(const win64::ServiceBinding &binding, const AddressFacts &facts) {
            if (!binding.returnsProcessStorage) {
                return {};
            }

            const bool calloc = binding.nativeSymbol == win64::crtCalloc.nativeSymbol;
            if (calloc || binding.nativeSymbol == win64::crtMalloc.nativeSymbol) {
                const auto &first = facts.registers[ServiceLocation{0}.registerIndex()];
                const auto &second = facts.registers[ServiceLocation{1}.registerIndex()];
                if (first.known() && first.values().size() == 1 &&
                    (!calloc || (second.known() && second.values().size() == 1))) {
                    const auto size = win64::elementBytes(first.values().front(),
                                                          calloc ? second.values().front() : 1);
                    return AddressFact::processStorage(size.value_or(0));
                }
            }
            return AddressFact::processStorage();
        }

        bool FunctionAnalyzer::traceCall(const ResolvedCallSite &site, AddressFacts &facts,
                                         CallAddresses &calls, bool collect) const {
            if (site.external()) {
                traceServiceArguments(site, facts, collect);

                std::span<const uint32_t> targets;
                if (const auto &table = site.external()->initializers) {
                    targets = table->targets;
                } else if (site.external()->binding.callback == win64::Callback::Cleanup) {
                    targets = terminationTargets;
                }

                if (!targets.empty()) {
                    if (!collect) {
                        // Relative to the guest caller's pre-CALL RSP, the imported
                        // CALL and native callback frame both consume stack space.
                        const auto rsp = facts.registers[rspIndex]
                                             .project(entryAddresses)
                                             .plus(AddressFact(uint64_t(0) - 8 -
                                                               GuestMemory::initializerFrameSize));
                        for (auto target : targets) {
                            CallInputs callback(rsp);
                            callback.callbackFrame = true;
                            calls.enter(target, callback);
                        }
                    }

                    // A callback can change guest storage through aliases.
                    facts.spills = {};
                }

                auto result = serviceResult(site.external()->binding, facts);
                std::fill_n(facts.registers.begin(), callerSlots, AddressFact{});
                facts.registers[0] = std::move(result);
                // CALL itself overwrites the slot below the caller's RSP.
                const auto slot = facts.registers[rspIndex].plus(AddressFact(uint64_t(0) - 8));
                facts.spills.write(slot, 64, {});
                return true;
            }

            if (!collect) {
                if (site.isTailJump()) {
                    CallInputs inputs(entryAddresses);
                    inputs.callbackFrame = callbackFrame;
                    inputs.facts = facts;
                    calls.enter(site.guest().rva, inputs);
                } else {
                    const auto rsp = facts.registers[rspIndex]
                                         .project(entryAddresses)
                                         .plus(AddressFact(uint64_t(0) - 8));
                    CallInputs inputs(rsp);
                    for (size_t i = 1; i <= 4; ++i) {
                        inputs.facts.registers[i] = facts.registers[i].project(entryAddresses);
                    }
                    for (const auto target : site.guestTargets()) {
                        calls.enter(target, inputs);
                    }
                }
            }

            std::optional<AddressFact> returned;
            for (const auto target : site.guestTargets()) {
                auto &callee = calls.functions.at(target);
                if (callee.returned) {
                    returned = returned ? returned->join(*callee.returned) : *callee.returned;
                } else if (!collect) {
                    callee.waiting.emplace(site.caller, site.block);
                }
            }
            if (!returned) {
                return false;
            }

            // Checked returns preserve RSP and nonvolatiles. Any other volatile
            // or saved stack value can have changed through a register or alias.
            std::fill_n(facts.registers.begin(), callerSlots, AddressFact{});
            facts.registers[0] = *returned;
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

                if (s.isRepeatedQwordStore()) {
                    traceRepeatedStore(s, facts, collect);
                    continue;
                }

                if (s.isAtomicExchange()) {
                    const auto operand =
                        operands.decodeAddress(s, s.isLockedCompareExchange() ? 0 : 2, true);
                    const auto address = addressFact(operand, facts);
                    if (collect) {
                        planMemoryAccess(s, 64, true, operand, address);
                    }

                    const auto dest = s.isLockedCompareExchange()
                                          ? RegisterView{0, 64}
                                          : operands.reg(s, s.inst.getOperand(0), 64);
                    facts.registers[dest.index] = {};
                    facts.spills.write(address, 64, {});
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
                    result = result.joinInFrame(facts.registers[src.index], entryAddresses)
                                 .project(entryAddresses);
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

                entryAddresses = state.entry.frameRsp;
                callbackFrame = state.entry.callbackFrame;
                blockAddresses[rva] = state.entry.facts;
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

                if (block.exit == Flow::Return || block.exit == Flow::TailJump) {
                    calls.recordReturn(rva, cursor.facts.registers[0].project(entryAddresses),
                                       incoming);
                }

                for (auto successor : block.successors) {
                    auto [it, inserted] = blockAddresses.try_emplace(successor, cursor.facts);

                    if (inserted || it->second.merge(cursor.facts, entryAddresses)) {
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
            setsDirection |= s.opcode == "STD";

            if (s.isAtomicExchange()) {
                requireMemory(s);
                const auto compare = s.isLockedCompareExchange();
                const auto dest =
                    compare ? RegisterView{0, 64} : operands.reg(s, s.inst.getOperand(0), 64);
                recordWrite(state, dest);
                if (compare) {
                    state.flags.generated.set();
                    state.flags.carried.set();
                }

                return;
            }

            if (s.isRepeatedQwordStore()) {
                requireMemory(s);
                // A successful nonempty operation consumes RDI before updating it;
                // a zero count preserves its original bits and origin marks.
                plan.modified.set(stringDestination.index);
                tracksOrigins = true;
                recordWrite(state, repeatCount);
                return;
            }

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
                            if (!site->isTailJump()) {
                                requireMemory(s);
                            }
                            if (const auto *service = site->external();
                                service && service->initializers) {
                                const auto &table = *service->initializers;
                                imageMemory.initializerTable(s, table.first, table.last);
                            }
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

        void propagateTailWrites(const RecoveredFunctionGroup &group, GroupAnalysis &result) {
            // One real guest frame covers every tail successor. Only writes along such
            // edges extend its capture set; ordinary callees validate their own returns.
            std::set<uint32_t> changed;
            for (const auto &[rva, function] : group.functions()) {
                if (llvm::any_of(function.incoming,
                                 [](const auto *site) { return site->isTailJump(); })) {
                    result.hasTailJumps = true;
                    changed.insert(rva);
                }
            }

            while (!changed.empty()) {
                const auto rva = changed.extract(changed.begin()).value();
                for (const auto *site : group.function(rva).incoming) {
                    if (site->isTailJump()) {
                        auto &modified = result.functions.at(site->caller).modified;
                        const auto merged = modified | result.functions.at(rva).modified;
                        if (modified != merged) {
                            modified = merged;
                            changed.insert(site->caller);
                        }
                    }
                }
            }
        }
    } // namespace

    Defined entryRegisterDefinitions(EntryMode mode) {
        Defined registers{};
        registers[rspIndex] = UINT64_MAX;

        if (mode == EntryMode::RegisterState) {
            std::fill_n(registers.begin(), callerSlots, UINT64_MAX);
        } else if (mode == EntryMode::WindowsX64I64Pair) {
            registers[1] = registers[2] = UINT64_MAX;
        }

        return registers;
    }

    GroupAnalysis analyzeGroup(const RecoveredFunctionGroup &group, uint64_t guestBase,
                               EntryMode mode, bool checkedMemory, LiftOutput output) try {
        GroupAnalysis result;
        ImageMemory image(group.image(), guestBase,
                          checkedMemory || output == LiftOutput::ProcessArtifact, mode);

        if (output == LiftOutput::ProcessArtifact) {
            const auto &root = group.function(group.root());
            image.checkStackMapping(root.graph.at(root.entry).steps.front());
        }

        const InstructionOperands operands(group.registers(), guestBase);
        std::map<uint32_t, FunctionAnalyzer> analyzers;

        std::set<uint32_t> retainedTargets;
        for (const auto &[address, function] : group.functions()) {
            for (const auto &[instruction, call] : function.calls) {
                if (const auto *table = call.table()) {
                    image.boundedTable(*function.instructionContaining(instruction), *table);
                    auto &instructions = result.functions[address].tableInstructions;
                    if (const auto *reverse = table->reverse()) {
                        instructions.emplace(reverse->countLoad, &call);
                        instructions.emplace(reverse->scanRead, &call);
                        instructions.emplace(reverse->zeroGuard, &call);
                    } else {
                        const auto &forward = *table->forward();
                        instructions.emplace(forward.pointerLoad, &call);

                        if (forward.slotStore) {
                            instructions.emplace(*forward.slotStore, &call);
                        }
                    }
                }

                const auto *service = call.external();
                if (service && service->binding.callback == win64::Callback::Cleanup) {
                    result.usesTermination = true;
                }

                if (service && service->registration) {
                    result.usesTermination = true;
                    for (const auto &[origin, target] : service->registration->targets) {
                        if (target) {
                            retainedTargets.insert(target);
                        }
                    }
                }
            }
        }
        const std::vector<uint32_t> terminationTargets(retainedTargets.begin(),
                                                       retainedTargets.end());

        for (const auto &[address, function] : group.functions()) {
            auto &analyzer = analyzers
                                 .try_emplace(address, group, address, operands, image,
                                              result.functions[address], terminationTargets)
                                 .first->second;
            analyzer.summarizeFunction(result.flows[address]);
            result.stack |= analyzer.accessesMemory;
            result.origins |= analyzer.tracksOrigins;
            result.setsDirection |= analyzer.setsDirection;
            result.hasGuestCallbacks |= function.callbackSource != nullptr;
        }

        propagateTailWrites(group, result);
        proveCallFlow(group, result.flows, {entryRegisterDefinitions(mode), {}});
        CallAddresses calls;
        CallInputs root{AddressFact(GuestMemory::entryRsp)};
        if (group.function(group.root()).incoming.empty()) {
            root.facts.registers[rspIndex] = AddressFact(GuestMemory::entryRsp, AddressFact::Stack);
        }
        calls.enter(group.root(), root);

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
