#include "lift/guarded_call.h"
#include "lift/service_location.h"

#include "llvm/Support/Endian.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        // The supported argument setup forms write one GPR (and optionally flags).
        // A narrow write to an alias of the target still invalidates the proof.
        bool argumentSetup(const Step &step, unsigned target, const InstructionOperands &op) {
            if (step.opcode != "MOV32ri" && step.opcode != "MOV32rr" && step.opcode != "XOR32rr") {
                return false;
            }
            const auto dest = op.reg(step, step.inst.getOperand(0), 32).index;
            return dest != target && dest >= ServiceLocation{0}.registerIndex() &&
                   dest <= ServiceLocation{3}.registerIndex();
        }

        uint32_t readImagePointer(const Step &call, const ParsedImage &image,
                                  const ImageInitialization &init, uint32_t slot) {
            const auto bytes = image.mapRva(slot, 8);
            const RvaRange field{slot, uint64_t(slot) + 8};
            try {
                init.validateRelocations(field);
            } catch (const InspectionError &error) {
                call.reject(error.kind, error.what());
            }
            if (!bytes || !bytes->section.immutable() || bytes->section.permissions[2] == 'x' ||
                !init.exclusionsIn(field).empty()) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "indirect call requires a stable read-only pointer at " + hex(slot));
            }

            const auto fixups = init.relocationsIn(field);
            if (fixups.size() != 1 || fixups.front()->rva != slot ||
                fixups.front()->type != COFF::IMAGE_REL_BASED_DIR64) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "indirect call pointer requires an exact DIR64 relocation at " +
                                hex(slot));
            }
            const auto address = support::endian::read64le(bytes->bytes.data());
            const auto base = image.module().imageBase;
            if (address < base || address - base >= image.module().sizeOfImage) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "indirect call pointer outside the image at " + hex(slot));
            }
            return static_cast<uint32_t>(address - base);
        }
    } // namespace

    std::optional<GuardedPointerCall>
    recognizeGuardedPointerCall(const std::map<uint32_t, Step> &decoded, const Step &call,
                                const InstructionOperands &op) {
        auto cursor = decoded.find(call.rva);
        auto previous = [&]() -> const Step * {
            if (cursor == decoded.begin()) {
                return nullptr;
            }

            const auto next = cursor->first;
            const auto &step = (--cursor)->second;
            return step.next == next ? &step : nullptr;
        };

        const auto reg = call.inst.getOperand(0).getReg();
        const auto target = op.reg(call, call.inst.getOperand(0), 64);
        const Step *guard = previous();
        // Win64 has at most four integer register arguments. This bound keeps this
        // local proof independent of the size of a function or a preceding loop.
        for (unsigned i = 0; i < 4 && guard && argumentSetup(*guard, target.index, op); ++i) {
            guard = previous();
        }
        if (!guard || guard->flow != Flow::Conditional || guard->inst.getOperand(1).getImm() != 4 ||
            int64_t(guard->next) + guard->inst.getOperand(0).getImm() != call.next) {
            return {};
        }

        const auto *test = previous();
        if (!test || test->opcode != "TEST64rr" || test->inst.getOperand(0).getReg() != reg ||
            test->inst.getOperand(1).getReg() != reg) {
            return {};
        }

        const auto *load = previous();
        if (!load || load->opcode != "MOV64rm" || load->inst.getOperand(0).getReg() != reg) {
            return {};
        }
        const auto source = op.decodeAddress(*load, 1, true);
        if (!source.base || source.base->index != target.index || source.index ||
            source.displacement) {
            return {};
        }

        const auto *producer = previous();
        if (!producer || producer->opcode != "MOV64rm" ||
            producer->inst.getOperand(0).getReg() != reg) {
            return {};
        }
        const auto slot = op.ripRva(*producer, 1);
        if (!slot || *slot < 0 || *slot > UINT32_MAX) {
            return {};
        }
        op.decodeAddress(*producer, 1, true);
        return GuardedPointerCall{producer->rva, static_cast<uint32_t>(*slot)};
    }

    uint32_t guardedCallTarget(const Step &call, uint32_t slot, const ParsedImage &image,
                               const ImageInitialization &init) {
        const auto cell = readImagePointer(call, image, init, slot);
        return readImagePointer(call, image, init, cell);
    }
} // namespace forge::x86
