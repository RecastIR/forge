#include "lift/bounded_table.h"
#include "lift/guarded_call.h"

#include <set>

namespace forge::x86 {
    namespace {
        // Walk decoded instructions, including padding in the adjacency proof. A gap,
        // an unrecognized definition, or an unexpected transfer ends the proof.
        struct Sequence {
            const Step &call;
            llvm::function_ref<const Step *(uint32_t, bool)> lookup;
            uint32_t position;
            unsigned budget = 256;
            bool forward = false;

            void seekForward(uint32_t rva) {
                forward = true;
                position = rva;
            }

            [[noreturn]] void reject() const {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "unproven bounded table-call loop at " + hex(position));
            }

            const Step &take() {
                while (budget) {
                    --budget;
                    const auto *step = lookup(position, forward);
                    if (!step || (forward ? step->rva : step->next) != position) {
                        reject();
                    }

                    position = forward ? step->next : step->rva;

                    if (!isNoop(*step)) {
                        return *step;
                    }
                }

                reject();
            }

            const Step &expect(llvm::StringRef name) {
                const auto &step = take();
                if (step.opcode != name) {
                    reject();
                }

                return step;
            }
        };

        bool branch(const Step &s, unsigned condition) {
            return (s.opcode == "JCC_1" || s.opcode == "JCC_4") &&
                   s.inst.getOperand(1).getImm() == condition;
        }

        unsigned reg(const InstructionOperands &ops, const Step &s, unsigned operand,
                     unsigned width) {
            return ops.reg(s, s.inst.getOperand(operand), width).index;
        }

        bool address(const AddressOperand &mem, unsigned base, std::optional<unsigned> index,
                     unsigned scale, int displacement) {
            return !mem.gsRelative && mem.base && mem.base->index == base &&
                   (mem.index ? std::optional{mem.index->index} : std::nullopt) == index &&
                   mem.scale == scale && mem.displacement == static_cast<uint64_t>(displacement);
        }

        struct Loop {
            const Step &source, &countLoad, &zeroTest, &empty, &sentinelBranch;
            unsigned base, accumulator, count, cursor, limit;
        };

        Loop prefix(Sequence &seq, const InstructionOperands &ops) {
            const auto &limitAddress = seq.expect("LEA64r");
            const auto &difference = seq.expect("SUB64rr");
            const auto &cursorAddress = seq.expect("LEA64r");
            const auto &subtract = seq.expect("SUB32ri8");
            const auto &extend = seq.expect("MOV32rr");
            const auto &empty = seq.take();
            const auto &zero = seq.expect("TEST32rr");
            const auto &sentinel = seq.take();
            const auto &compare = seq.expect("CMP32ri8");
            const auto &copy = seq.expect("MOV32rr");
            const auto &load = seq.expect("MOV64rm");
            const auto &source = seq.take();

            if (source.opcode != "MOV64rm" && source.opcode != "LEA64r") {
                seq.reject();
            }

            const auto base = reg(ops, source, 0, 64);
            const auto acc = reg(ops, load, 0, 64);
            const auto count = reg(ops, copy, 0, 32);
            const auto cursor = reg(ops, cursorAddress, 0, 64);
            const auto limit = reg(ops, limitAddress, 0, 64);
            const std::set<unsigned> roles{base, acc, count, cursor, limit};

            if (roles.size() != 5 || roles.contains(rspIndex) || !nonvolatile(cursor) ||
                !nonvolatile(limit) || !address(ops.decodeAddress(load, 1, true), base, {}, 1, 0) ||
                reg(ops, copy, 1, 32) != acc || reg(ops, compare, 0, 32) != acc ||
                compare.inst.getOperand(1).getImm() != -1 || !branch(sentinel, 4) ||
                reg(ops, zero, 0, 32) != count || reg(ops, zero, 1, 32) != count ||
                !branch(empty, 4)) {
                seq.reject();
            }

            // For a nonzero DWORD n, zero_extend(n) - zero_extend(n-1) is one.
            // The two LEAs therefore produce base+8*n and base, respectively.
            if (reg(ops, extend, 0, 32) != acc || reg(ops, extend, 1, 32) != count ||
                reg(ops, subtract, 0, 32) != count || subtract.inst.getOperand(2).getImm() != 1 ||
                !address(ops.decodeAddress(cursorAddress, 1, false), base, acc, 8, 0) ||
                reg(ops, difference, 0, 64) != acc || reg(ops, difference, 2, 64) != count ||
                !address(ops.decodeAddress(limitAddress, 1, false), base, acc, 8, -8) ||
                !address(ops.decodeAddress(seq.call, 0, true), cursor, {}, 1, 0)) {
                seq.reject();
            }

            return {source, load, zero, empty, sentinel, base, acc, count, cursor, limit};
        }

        struct Scan {
            uint32_t start, increment, read, backedge, finish, end;
        };

        Scan scan(Sequence &seq, const Loop &loop, const InstructionOperands &ops) {
            const auto start = loop.sentinelBranch.relativeTarget();
            if (!std::in_range<uint32_t>(start)) {
                seq.reject();
            }

            seq.seekForward(static_cast<uint32_t>(start));
            const auto &clear = seq.expect("XOR32rr");
            const auto &inc = seq.expect("LEA64_32r");
            const auto index = reg(ops, inc, 0, 32);
            const auto &copy = seq.expect("MOV32rr");
            const auto &test = seq.expect("CMP64mi8");
            const auto &advance = seq.expect("MOV64rr");
            const auto &again = seq.take();
            const auto &finish = seq.take();

            if (index == loop.base || index == loop.accumulator || index == loop.count ||
                index == rspIndex || reg(ops, clear, 0, 32) != loop.accumulator ||
                reg(ops, clear, 1, 32) != reg(ops, clear, 2, 32) ||
                !address(ops.decodeAddress(inc, 1, false), loop.accumulator, {}, 1, 1) ||
                reg(ops, copy, 0, 32) != loop.count || reg(ops, copy, 1, 32) != loop.accumulator ||
                !address(ops.decodeAddress(test, 0, true), loop.base, index, 8, 0) ||
                test.inst.getOperand(5).getImm() != 0 ||
                reg(ops, advance, 0, 64) != loop.accumulator || reg(ops, advance, 1, 64) != index ||
                !branch(again, 5) || again.relativeTarget() != inc.rva ||
                finish.flow != Flow::Jump || finish.relativeTarget() != loop.zeroTest.rva) {
                seq.reject();
            }

            return {static_cast<uint32_t>(start),
                    inc.rva,
                    test.rva,
                    again.rva,
                    finish.rva,
                    finish.next};
        }

        void reserveTableEntries(const BoundedTableCall &table, const Step &call, unsigned count,
                                 unsigned &remainingEntries) {
            const uint64_t used = (table.last - table.first) / 8;
            if (used + count > win64::maxInitializerEntries) {
                if (table.sentinel) {
                    call.reject(FailureCode::UnsupportedControlFlow,
                                "missing bounded table terminator at " + hex(table.last));
                }

                call.reject(FailureCode::UnsupportedControlFlow,
                            "bounded table count exceeds budget at " + hex(table.header));
            }

            if (count > remainingEntries) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "bounded table entry budget exceeded at " + hex(table.header));
            }

            // Discovery can continue at another site after a deferred failure.
            remainingEntries -= count;
        }

        void readTable(BoundedTableCall &table, const Step &call, const ParsedImage &image,
                       const ImageInitialization &init, llvm::ArrayRef<RvaRange> functions,
                       unsigned &remainingEntries) {
            const auto *section = image.sectionAtRva(table.header);
            if (!section || (!section->immutable() && !section->writableData()) ||
                section->shared || table.header % 8 || image.advertisesDynamicRelocations()) {
                call.reject(FailureCode::ImageMemory,
                            "invalid guest pointer table at " + hex(table.header));
            }
            const auto sectionEnd = uint64_t(section->rva) + section->virtualSize;
            const auto slotRange = [&](uint64_t slot) {
                RvaRange field{slot, slot + 8};
                if (field.end > sectionEnd || field.end > image.module().sizeOfImage ||
                    !rangesIn(functions, field).empty()) {
                    call.reject(FailureCode::ImageMemory,
                                "invalid bounded table extent at " + hex(slot));
                }
                return field;
            };

            const auto head = slotRange(table.header);
            init.validateRelocations(head);
            if (!init.exclusionsIn(head).empty() || !init.relocationsIn(head).empty()) {
                call.reject(FailureCode::ImageMemory,
                            "unstable bounded table header at " + hex(table.header));
            }

            const auto count = static_cast<uint32_t>(image.initialQword(table.header));
            table.sentinel = count == UINT32_MAX;
            table.first = static_cast<uint32_t>(head.end);
            table.last = table.first;
            if (!table.sentinel) {
                reserveTableEntries(table, call, count, remainingEntries);
            }

            for (unsigned i = 0; table.sentinel || i < count; ++i) {
                const uint32_t slot = table.last;
                const auto field = slotRange(slot);
                const auto value = image.initialQword(slot);
                const bool nullSlot = !value && init.relocationsIn(field).empty();
                if (table.sentinel && !nullSlot) {
                    reserveTableEntries(table, call, 1, remainingEntries);
                }

                init.validateRelocations(field);
                if (nullSlot) {
                    if (!init.exclusionsIn(field).empty()) {
                        call.reject(FailureCode::ImageMemory,
                                    "unstable NULL table slot at " + hex(slot));
                    }
                    if (table.sentinel) {
                        break;
                    }
                } else {
                    table.targets.push_back(
                        relocatedPointerRva(call, image.module(), init, slot, value));
                }

                table.last += 8;
            }

            if (image.overlapsDirectory(table.extent())) {
                call.reject(FailureCode::ImageMemory,
                            "bounded pointer table overlaps a PE directory at " +
                                hex(table.header));
            }

            llvm::sort(table.targets);
            table.targets.erase(std::unique(table.targets.begin(), table.targets.end()),
                                table.targets.end());
        }
    } // namespace

    BoundedTableCall recoverTableCall(const std::map<uint32_t, Step> &steps, const Step &call,
                                      const InstructionOperands &ops, const ParsedImage &image,
                                      const ImageInitialization &init,
                                      llvm::ArrayRef<RvaRange> functions,
                                      unsigned &remainingEntries) try {
        const auto lookup = [&](uint32_t rva, bool forward) -> const Step * {
            auto it = steps.lower_bound(rva);
            if (!forward) {
                if (it == steps.begin()) {
                    return nullptr;
                }
                --it;
            }
            return it == steps.end() ? nullptr : &it->second;
        };
        Sequence seq{call, lookup, call.rva};
        const auto loop = prefix(seq, ops);
        const auto scanner = scan(seq, loop, ops);
        const auto rva = ops.ripRva(loop.source, 1);
        if (!rva || !std::in_range<uint32_t>(*rva)) {
            seq.reject();
        }
        ops.decodeAddress(loop.source, 1, loop.source.opcode == "MOV64rm");
        const auto slot = static_cast<uint32_t>(*rva);
        const auto header = loop.source.opcode == "LEA64r"
                                ? slot
                                : readImmutableImagePointer(call, image, init, slot);
        BoundedTableCall table{header,
                               0,
                               0,
                               loop.source.rva,
                               loop.countLoad.rva,
                               loop.zeroTest.rva,
                               scanner.read,
                               loop.cursor,
                               false,
                               {}};
        readTable(table, call, image, init, functions, remainingEntries);
        return table;
    } catch (InspectionError &error) {
        if (error.context.instructionRva != call.rva) {
            call.reject(error.kind, error.what());
        }
        throw;
    }

    void validateTableLoop(const RecoveredFunction &function, const Step &call,
                           const BoundedTableCall &table, const InstructionOperands &ops) {
        const auto lookup = [&](uint32_t rva, bool forward) -> const Step * {
            if (!forward && !rva) {
                return nullptr;
            }
            return function.instructionContaining(forward ? rva : rva - 1);
        };
        Sequence seq{call, lookup, call.rva};
        const auto loop = prefix(seq, ops);
        const auto scanner = scan(seq, loop, ops);
        uint32_t end = call.next;
        std::set<std::pair<uint32_t, uint32_t>> branches{{loop.sentinelBranch.rva, scanner.start},
                                                         {scanner.finish, table.zeroGuard},
                                                         {scanner.backedge, scanner.increment}};
        if (call.flow != Flow::TerminalCall) {
            seq.seekForward(call.next);
            const auto &sub = seq.expect("SUB64ri8");
            const auto &compare = seq.expect("CMP64rr");
            const auto &again = seq.take();
            if (reg(ops, sub, 0, 64) != loop.cursor || sub.inst.getOperand(2).getImm() != 8 ||
                reg(ops, compare, 0, 64) != loop.cursor || reg(ops, compare, 1, 64) != loop.limit ||
                !branch(again, 5) || again.relativeTarget() != call.rva ||
                loop.empty.relativeTarget() != again.next) {
                seq.reject();
            }
            branches.emplace(again.rva, call.rva);
            end = again.next;
        }
        const auto protectedAddress = [&](uint32_t rva) {
            return (rva > table.baseDefinition && rva < end) ||
                   (rva >= scanner.start && rva < scanner.end);
        };
        if (protectedAddress(function.entry) ||
            protectedAddress(static_cast<uint32_t>(loop.empty.relativeTarget())) ||
            (table.baseDefinition < scanner.end && scanner.start < end)) {
            seq.reject();
        }

        for (const auto &[leader, block] : function.graph) {
            const auto &last = block.steps.back();
            for (const auto dest : block.successors) {
                if (!protectedAddress(dest)) {
                    continue;
                }
                const bool sequential =
                    last.next == dest && dest != scanner.start &&
                    (last.flow == Flow::Conditional || last.flow == Flow::Fallthrough);
                if (!sequential && !branches.contains({last.rva, dest})) {
                    call.reject(FailureCode::UnsupportedControlFlow,
                                "edge bypasses bounded table proof from " + hex(last.rva) + " to " +
                                    hex(dest));
                }
            }
        }
    }
} // namespace forge::x86
