#include "lift/jump_table.h"

#include "llvm/Support/Endian.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        constexpr unsigned maxTableEntries = 1024;

        // Walk only contiguous instructions already decoded by CFG discovery.
        class Prefix {
          public:
            Prefix(const std::map<uint32_t, Step> &decoded, const Step &jump)
                : first(decoded.begin()), cursor(decoded.find(jump.rva)), jump(jump) {}

            const Step &take(StringRef failure) {
                if (cursor == first || std::prev(cursor)->second.next != cursor->first) {
                    jump.reject(FailureCode::UnsupportedControlFlow, failure);
                }

                return (--cursor)->second;
            }

          private:
            std::map<uint32_t, Step>::const_iterator first, cursor;
            const Step &jump;
        };

        constexpr StringLiteral unknown =
            "unsupported control transfer: unrecognized relative jump-table dispatch";
        constexpr unsigned unsignedAbove = 7;

        RelativeTable boundedTable(Prefix &prefix, const Step &jump,
                                   const InstructionOperands &operands, unsigned index,
                                   const Step &load, uint32_t tableRva) {
            const auto unbounded =
                "unproven jump-table index bounds for relative table at " + hex(tableRva);
            auto *guard = &prefix.take(unbounded);
            unsigned width = 64;

            // A 32-bit CMP reads only the low half. A MOV on its in-range edge must
            // explicitly zero-extend that same value into the index used by the load.
            if (guard->opcode == "MOV32rr" || guard->opcode == "MOV32rr_REV") {
                if (operands.reg(*guard, guard->inst.getOperand(0), 32).index != index) {
                    jump.reject(FailureCode::UnsupportedControlFlow, unbounded);
                }

                index = operands.reg(*guard, guard->inst.getOperand(1), 32).index;
                width = 32;
                guard = &prefix.take(unbounded);
            }

            const auto &cmp = prefix.take(unbounded);
            const auto op = integerInstruction(cmp.opcode);

            if ((guard->opcode != "JCC_1" && guard->opcode != "JCC_4") ||
                guard->inst.getOperand(1).getImm() != unsignedAbove || !op || op->op != Op::Cmp ||
                op->width != width ||
                (op->form != Form::Immediate && op->form != Form::Accumulator) ||
                operands.destination(cmp, *op).index != index) {
                jump.reject(FailureCode::UnsupportedControlFlow, unbounded);
            }

            const auto imm = cmp.inst.getOperand(cmp.inst.getNumOperands() - 1).getImm();
            const auto bound = static_cast<uint64_t>(imm) & maskTrailingOnes<uint64_t>(width);

            if (bound >= maxTableEntries) {
                jump.reject(FailureCode::UnsupportedControlFlow,
                            "relative table at " + hex(tableRva) + ": index bound " + Twine(bound) +
                                " exceeds recovery budget");
            }

            return {cmp.rva, guard->rva, load.rva, tableRva, static_cast<unsigned>(bound) + 1};
        }
    } // namespace

    std::string RelativeTable::describe() const {
        return "signed 4-byte relative table at RVA " + hex(tableRva) + " indices 0.." +
               std::to_string(count - 1);
    }

    void RelativeTable::rejectEntry(const Step &jump, unsigned index, FailureCode kind,
                                    const Twine &reason, std::optional<int64_t> target) const {
        jump.reject(kind, describe() + ", entry " + Twine(index) + ": " + reason, target);
    }

    RelativeTable JumpTableReader::recognize(const std::map<uint32_t, Step> &decoded,
                                             const Step &jump) const {
        Prefix prefix(decoded, jump);
        const auto &add = prefix.take(unknown);
        const auto &load = prefix.take(unknown);
        const auto &lea = prefix.take(unknown);
        const auto target = jump.inst.getOperand(0).getReg();

        if ((add.opcode != "ADD64rr" && add.opcode != "ADD64rr_REV") ||
            load.opcode != "MOVSX64rm32" || lea.opcode != "LEA64r") {
            jump.reject(FailureCode::UnsupportedControlFlow, unknown);
        }

        const auto base = lea.inst.getOperand(0).getReg();
        const auto &address = operands.decodeAddress(load, 1, true);

        if (base == target || add.inst.getOperand(0).getReg() != target ||
            add.inst.getOperand(2).getReg() != base || load.inst.getOperand(0).getReg() != target ||
            load.inst.getOperand(1).getReg() != base || !address.index ||
            load.inst.getOperand(3).getReg() == base || address.scale != 4 ||
            address.displacement != 0) {
            jump.reject(FailureCode::UnsupportedControlFlow, unknown);
        }

        const auto table = operands.ripAddress(lea, 1);

        if (!table || *table > UINT32_MAX) {
            jump.reject(FailureCode::UnsupportedControlFlow, "unresolved relative jump-table base");
        }

        operands.decodeAddress(lea, 1, false);
        return boundedTable(prefix, jump, operands, address.index->index, load,
                            static_cast<uint32_t>(*table));
    }

    SmallVector<uint32_t, 2> JumpTableReader::targets(const Step &jump, RelativeTable table,
                                                      RvaRange function) {
        const auto description = table.describe();
        const auto *section = image.sectionAtRva(table.tableRva);

        if (!section || !section->immutable() || section->permissions[2] == 'x') {
            jump.reject(FailureCode::UnsupportedControlFlow,
                        description + " requires stable, read-only image data");
        }

        if (!initialization) {
            initialization = image.imageInitialization();
        }

        const auto *codeSection = image.sectionAtRva(function.begin);

        if (!codeSection || !codeSection->immutable() ||
            !initialization->exclusionsIn(function).empty()) {
            jump.reject(FailureCode::UnsupportedControlFlow,
                        description + ": dispatch function bytes are not stable");
        }

        SmallVector<uint32_t, 2> targets;
        targets.reserve(table.count);

        for (unsigned i = 0; i < table.count; ++i) {
            const uint64_t entry = uint64_t(table.tableRva) + 4ULL * i;
            const RvaRange field{entry, entry + 4};
            auto mapped = image.mapRva(entry, 4);

            if (!mapped || &mapped->section != section) {
                table.rejectEntry(jump, i, FailureCode::UnsupportedControlFlow,
                                  "unmapped or truncated table entry");
            }

            try {
                initialization->validateRelocations(field);
            } catch (const InspectionError &error) {
                table.rejectEntry(jump, i, error.kind, error.what());
            }

            if (!initialization->exclusionsIn(field).empty() ||
                !initialization->relocationsIn(field).empty()) {
                table.rejectEntry(jump, i, FailureCode::UnsupportedControlFlow,
                                  "loader-written or relocated table entry");
            }

            const auto offset = SignExtend64<32>(support::endian::read32le(mapped->bytes.data()));
            const int64_t dest = int64_t(table.tableRva) + offset;
            const auto rva = static_cast<uint64_t>(dest);
            const auto *code = image.sectionAtRva(rva);

            if (!code || code->permissions[2] != 'x' || !image.mapRva(rva, 1)) {
                table.rejectEntry(jump, i, FailureCode::InvalidBranchTarget,
                                  "destination outside executable image", dest);
            }

            if (rva < function.begin || rva >= function.end) {
                table.rejectEntry(jump, i, FailureCode::UnsupportedControlFlow,
                                  "destination outside validated function", dest);
            }

            targets.push_back(static_cast<uint32_t>(dest));
        }

        return targets;
    }
} // namespace forge::x86
