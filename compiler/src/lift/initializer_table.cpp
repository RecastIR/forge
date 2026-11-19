#include "lift/initializer_table.h"
#include "lift/guarded_call.h"
#include "lift/service_location.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/MC/MCRegisterInfo.h"

#include <utility>

namespace forge::x86 {
    using namespace llvm;

    namespace {
        struct RangeProof {
            const RecoveredFunction &caller;
            const Step &call;
            const ParsedImage &image;
            const ImageInitialization &init;
            const MCInstrInfo &instructions;
            const MCRegisterInfo &registers;
            const InstructionOperands operands;
            std::optional<InitializerRecovery::Predecessors> &predecessors;

            const InitializerRecovery::Predecessors &blockPredecessors() {
                if (!predecessors) {
                    auto &edges = predecessors.emplace();
                    for (const auto &[rva, block] : caller.graph) {
                        for (const auto dest : block.successors) {
                            edges[dest].push_back(&block);
                        }
                    }
                }

                return *predecessors;
            }

            MCRegister argumentRegister(RegisterView view) const;
            std::optional<uint32_t> definition(ArrayRef<Step> steps, MCRegister reg,
                                               RegisterView view, unsigned &remaining) const;
            uint32_t endpoint(const GuestBlock &block, size_t argument);
        };

        MCRegister RangeProof::argumentRegister(RegisterView view) const {
            const auto name = registerName(view.index);
            for (unsigned i = 1; i < registers.getNumRegs(); ++i) {
                if (name == registers.getName(i)) {
                    return i;
                }
            }

            call.reject(FailureCode::LiftingInternal, "missing argument register " + name);
        }

        std::optional<uint32_t> RangeProof::definition(ArrayRef<Step> steps, MCRegister reg,
                                                       RegisterView view,
                                                       unsigned &remaining) const {
            for (const Step &step : llvm::reverse(steps)) {
                if (!remaining) {
                    call.reject(FailureCode::UnsupportedControlFlow,
                                "initializer range proof exceeds its instruction budget");
                }
                --remaining;
                if (!clobbersRegister(step, reg, view, instructions, registers)) {
                    continue;
                }

                const bool load = step.opcode == "MOV64rm";
                if ((load || step.opcode == "LEA64r") && step.inst.getOperand(0).getReg() == reg) {
                    const auto slot = operands.ripRva(step, 1);
                    if (slot && std::in_range<uint32_t>(*slot)) {
                        operands.decodeAddress(step, 1, load);
                        const auto rva = static_cast<uint32_t>(*slot);
                        return load ? readImmutableImagePointer(call, image, init, rva, true) : rva;
                    }
                }
                call.reject(FailureCode::UnsupportedControlFlow,
                            "cannot prove initializer table endpoint in " +
                                registerName(view.index) + " at " + hex(step.rva));
            }
            return {};
        }

        uint32_t RangeProof::endpoint(const GuestBlock &block, size_t argument) {
            const RegisterView view{ServiceLocation{argument}.registerIndex(), 64};
            const auto reg = argumentRegister(view);
            const auto name = registerName(view.index);
            using Steps = ArrayRef<Step>;
            SmallVector<Steps, 8> pending{
                Steps(block.steps).take_front(static_cast<size_t>(&call - block.steps.data()))};
            std::set<uint32_t> examinedPredecessors;
            std::optional<uint32_t> result;
            unsigned remaining = 256;

            while (!pending.empty()) {
                const auto steps = pending.pop_back_val();
                if (const auto value = definition(steps, reg, view, remaining)) {
                    if (result && *result != *value) {
                        call.reject(FailureCode::UnsupportedControlFlow,
                                    "conflicting initializer table endpoints in " + name);
                    }
                    result = value;
                    continue;
                }

                // The current block has no definition on its prefix. Every incoming
                // edge must supply the same endpoint, including loop backedges.
                const auto leader = steps.empty() ? call.rva : steps.front().rva;
                const auto &edges = blockPredecessors();
                const auto found = edges.find(leader);
                if (leader == caller.entry || found == edges.end()) {
                    call.reject(FailureCode::UnsupportedControlFlow,
                                "initializer table endpoint in " + name +
                                    " has an unproven incoming value");
                }

                for (const auto *pred : found->second) {
                    if (examinedPredecessors.insert(pred->steps.front().rva).second) {
                        pending.push_back(pred->steps);
                    }
                }
            }

            if (!result) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "initializer table has no reaching definition for " + name);
            }
            return *result;
        }

        std::optional<uint32_t> initialTarget(const Step &call, uint32_t slot,
                                              const ParsedImage &image,
                                              const ImageInitialization &init) {
            const RvaRange field{slot, uint64_t(slot) + sizeof(uint64_t)};
            const auto *section = image.sectionAtRva(slot);
            if (!section || (!section->immutable() && !section->writableData()) ||
                section->permissions[2] == 'x' ||
                field.end > uint64_t(section->rva) + section->virtualSize ||
                !init.exclusionsIn(field).empty()) {
                call.reject(FailureCode::ImageMemory,
                            "initializer table entry is outside readable PE data at " + hex(slot));
            }

            const auto value = image.initialQword(slot);
            if (!value && init.relocationsIn(field).empty()) {
                return {};
            }
            return relocatedPointerRva(call, image.module(), init, slot, value);
        }
    } // namespace

    InitializerTable
    recoverInitializerTable(const RecoveredFunction &caller, const GuestBlock &block,
                            const Step &call, const win64::ServiceBinding &binding,
                            const ParsedImage &image, const ImageInitialization &init,
                            const MCInstrInfo &instructions, const MCRegisterInfo &registers,
                            InitializerRecovery &recovery) {
        RangeProof proof{caller,
                         call,
                         image,
                         init,
                         instructions,
                         registers,
                         InstructionOperands(registers, 0),
                         recovery.predecessors};
        InitializerTable table{
            proof.endpoint(block, 0), proof.endpoint(block, binding.arguments[0].size), {}};
        const auto &module = image.module();
        if (table.last > module.sizeOfImage || table.first > module.sizeOfImage ||
            module.imageBase > UINT64_MAX - std::max(table.first, table.last) ||
            !win64::initializerRangeBytes(module.imageBase + table.first,
                                          module.imageBase + table.last)) {
            call.reject(FailureCode::ImageMemory, "invalid or excessive initializer table range [" +
                                                      hex(table.first) + ", " + hex(table.last) +
                                                      ")");
        }

        const auto count = static_cast<unsigned>((table.last - table.first) / sizeof(uint64_t));
        constexpr unsigned maxCallerEntries = 4096;
        if (count > maxCallerEntries - recovery.entries) {
            call.reject(FailureCode::UnsupportedControlFlow,
                        "function initializer table recovery budget exceeded");
        }
        recovery.entries += count;
        if (!count) {
            return table;
        }

        try {
            init.validateRelocations({table.first, table.last});
        } catch (const InspectionError &error) {
            call.reject(error.kind, error.what());
        }

        for (uint64_t slot = table.first; slot < table.last; slot += sizeof(uint64_t)) {
            if (const auto rva = initialTarget(call, static_cast<uint32_t>(slot), image, init)) {
                table.targets.push_back(*rva);
            }
        }
        llvm::sort(table.targets);
        table.targets.erase(std::unique(table.targets.begin(), table.targets.end()),
                            table.targets.end());
        return table;
    }
} // namespace forge::x86
