#include "lift/recovery.h"

#include "analysis/analysis.h"
#include "lift/asm_info.h"
#include "lift/jump_table.h"
#include "lift/leaf_recovery.h"

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetSelect.h"

#include <mutex>
#include <utility>

namespace forge::x86 {
    using namespace llvm;

    namespace {
        InspectionError atRva(FailureCode kind, uint32_t rva, const Twine &why) {
            return InspectionError(hex(rva) + ": " + why.str(), kind);
        }

        FailureContext entryLocation(const ParsedImage &source, uint32_t rva) {
            FailureContext location;
            location.input = source.module().path;
            location.entryRva = rva;
            return location;
        }

        FailureContext entryLocation(const ParsedImage &source, uint32_t rva, MappedRange code) {
            auto location = entryLocation(source, rva);
            location.endRva = rva + static_cast<uint32_t>(code.bytes.size());
            location.fileOffset = code.fileOffset;
            return location;
        }

        void addLocation(InspectionError &failure, const ParsedImage &source,
                         const FailureContext &location) {
            failure.context.input = location.input;
            failure.context.entryRva = location.entryRva;

            if (failureKind(failure.kind).stage == "pe" && !failure.context.instructionRva) {
                return;
            }

            failure.context.endRva = location.endRva;
            if (failure.context.fileOffset) {
                return;
            }

            failure.context.fileOffset = location.fileOffset;
            const auto rva = failure.context.instructionRva ? failure.context.instructionRva
                                                            : failure.context.functionRva;
            if (rva && rva != location.entryRva) {
                if (auto code = source.mapRva(*rva)) {
                    failure.context.fileOffset = code->fileOffset;
                }
            }
        }

        template <class Work>
        decltype(auto) withLocation(const ParsedImage &source, const FailureContext &location,
                                    FailureCode internal, Work work) {
            try {
                return work();
            } catch (InspectionError &failure) {
                addLocation(failure, source, location);
                throw;
            } catch (const std::exception &error) {
                InspectionError failure(error.what(), internal);
                failure.context = location;
                throw failure;
            }
        }

        constexpr StringLiteral invalidFunctionStart =
            "expected an exact, valid, unambiguous discovered function start";

        std::optional<MappedRange> validateFunction(const AnalyzedImage &analysis, uint32_t rva,
                                                    const RelocationIndex &relocations,
                                                    FailureContext &location) {
            const auto &functions = analysis.functions();
            auto it = llvm::lower_bound(functions, rva, [](const auto &function, uint32_t address) {
                return function.record.begin < address;
            });

            const auto first = it;
            // An invalid empty record can share its start with a valid, disjoint record.
            while (it != functions.end() && it->record.begin == rva &&
                   (it->defect || it->overlapGroup)) {
                ++it;
            }

            if (it == functions.end() || it->record.begin != rva) {
                if (first == it) {
                    return std::nullopt;
                }

                auto kind = FailureCode::InvalidEntry;

                if (it - first == 1 && !first->overlapGroup &&
                    first->defect == RecordDefect::UnmappedCode) {
                    kind = FailureCode::UnmappedCode;
                    location.endRva = first->record.end;
                }

                throw atRva(kind, rva, invalidFunctionStart);
            }

            const auto end = it->record.end;
            location.endRva = end;

            if (const auto version = it->unsupportedUnwindVersion) {
                throw atRva(FailureCode::UnsupportedUnwind, rva,
                            "unsupported unwind version " + Twine(*version));
            }

            if (it->chainedFragment) {
                throw atRva(FailureCode::ChainedEntry, rva,
                            "chained unwind fragment has no independent function entry");
            }

            auto code = analysis.image().mapRva(rva, end - rva);

            if (!code) {
                throw atRva(FailureCode::UnmappedCode, rva,
                            "function bytes outside file-backed sections");
            }

            location.fileOffset = code->fileOffset;

            if (const auto *rel = relocations.firstOverlap({rva, end})) {
                throw atRva(FailureCode::RelocationOverlap, rva,
                            "function bytes overlap base relocation at " + hex(rel->rva));
            }

            return code;
        }

        std::optional<MappedRange> validateCallee(const AnalyzedImage &analysis,
                                                  const RelocationIndex &relocations,
                                                  const Step &step, uint32_t target) {
            const auto *section = analysis.image().sectionAtRva(target);

            if (!section || section->permissions[2] != 'x') {
                step.reject(FailureCode::InvalidCallTarget,
                            "direct call target outside executable image sections", target);
            }

            FailureContext location;
            try {
                return validateFunction(analysis, target, relocations, location);
            } catch (const InspectionError &error) {
                const auto kind = failureKind(error.kind).category == "invalid_input"
                                      ? FailureCode::InvalidCallTarget
                                      : FailureCode::UnsupportedControlFlow;
                step.reject(kind, error.what(), target);
            }
        }

        struct GroupDiscovery {
            const ValidatedEntry &entry;
            std::map<uint32_t, RecoveredFunction> &functions;
            std::map<uint32_t, MappedRange> pending;
            std::map<uint32_t, const DirectCall *> deferred;

            bool schedule(uint32_t target, const Step &step);
            void scanCalls(uint32_t rva, RecoveredFunction &caller, const GuestBlock &block);
            void run(const MCDisassembler &dis, const MCInstrInfo &instructions,
                     const MCRegisterInfo &regs);
        };

        bool GroupDiscovery::schedule(uint32_t target, const Step &step) {
            if (functions.contains(target) || pending.contains(target)) {
                return true;
            }

            const auto code = validateCallee(entry.analysis, entry.relocations, step, target);
            if (!code) {
                const auto &table = entry.analysis.module().exceptions;
                if (table && table->trailingBytes()) {
                    step.reject(
                        FailureCode::UnsupportedControlFlow,
                        "insufficient evidence for leaf recovery: partial runtime function record",
                        target);
                }

                return false;
            }

            pending.emplace(target, *code);
            return true;
        }

        void GroupDiscovery::scanCalls(uint32_t rva, RecoveredFunction &caller,
                                       const GuestBlock &block) try {
            const auto leader = block.steps.front().rva;
            for (const auto &step : block.steps) {
                if (!step.isDirectCall()) {
                    continue;
                }

                const int64_t target = int64_t(step.next) + step.inst.getOperand(0).getImm();
                if (target < 0 || target > UINT32_MAX) {
                    step.reject(FailureCode::InvalidCallTarget,
                                "direct call target outside the guest RVA space", target);
                }

                const auto address = static_cast<uint32_t>(target);
                const auto &site =
                    caller.calls
                        .emplace(step.rva, DirectCall{rva, leader, step.rva, address, step.next})
                        .first->second;

                if (!deferred.contains(address) && !schedule(address, step)) {
                    deferred.emplace(address, &site);
                }
            }
        } catch (InspectionError &error) {
            error.context.blockRva = block.steps.front().rva;
            throw;
        }

        void GroupDiscovery::run(const MCDisassembler &dis, const MCInstrInfo &instructions,
                                 const MCRegisterInfo &regs) {
            JumpTableReader tables(entry.analysis.image(), regs);
            pending.emplace(entry.rva, entry.code);
            while (!pending.empty()) {
                auto scheduled = pending.extract(pending.begin());
                const auto rva = scheduled.key();
                auto &function =
                    functions
                        .try_emplace(rva, rva, RecoveryOrigin::UnwindBacked, scheduled.mapped())
                        .first->second;

                try {
                    function.graph =
                        discoverCFG(function.code.bytes, rva, dis, instructions, tables);
                    for (const auto &[leader, block] : function.graph) {
                        scanCalls(rva, function, block);
                    }
                } catch (InspectionError &error) {
                    if (rva != entry.rva) {
                        error.context.functionRva = rva;
                    }

                    throw;
                }
            }

            if (!deferred.empty()) {
                recoverLeaves(entry, functions, deferred, dis, instructions, regs);
            }

            // Incoming indices follow source order even when discovery began at a higher RVA.
            for (const auto &[caller, function] : functions) {
                for (const auto &[instruction, call] : function.calls) {
                    functions.at(call.callee).incoming.push_back(&call);
                }
            }
        }
    } // namespace

    ValidatedEntry::ValidatedEntry(const AnalyzedImage &analysis, uint32_t rva, MappedRange code,
                                   RelocationIndex &&relocations)
        : analysis(analysis), rva(rva), code(code), relocations(std::move(relocations)) {}

    ValidatedEntry validateEntry(const AnalyzedImage &analysis, uint32_t rva) {
        auto location = entryLocation(analysis.image(), rva);
        return withLocation(analysis.image(), location, FailureCode::EntryInternal, [&] {
            const auto &module = analysis.module();
            if (module.dll) {
                throw atRva(FailureCode::DllLift, rva, "DLL lifting is unsupported");
            }

            RelocationIndex relocations(module.relocations);
            auto code = validateFunction(analysis, rva, relocations, location);
            if (!code) {
                throw atRva(FailureCode::InvalidEntry, rva, invalidFunctionStart);
            }

            return ValidatedEntry{analysis, rva, *code, std::move(relocations)};
        });
    }

    uint64_t validateGuestBase(const ValidatedEntry &entry, std::optional<uint64_t> requested) {
        const auto &source = entry.analysis.image();
        const auto location = entryLocation(source, entry.rva, entry.code);
        return withLocation(source, location, FailureCode::EntryInternal, [&] {
            const auto &module = source.module();
            const auto guestBase = requested.value_or(module.imageBase);
            if (module.relocationsStripped && guestBase != module.imageBase) {
                throw atRva(FailureCode::ImageMemory, entry.rva,
                            "base relocations are stripped: selected guest base " + hex(guestBase) +
                                " differs from preferred image base " + hex(module.imageBase));
            }

            for (const auto &section : module.sections) {
                const uint64_t endRva = uint64_t(section.rva) + section.virtualSize;
                if (section.virtualSize && endRva - 1 > UINT64_MAX - guestBase) {
                    throw atRva(FailureCode::ImageMemory, entry.rva,
                                "selected guest load base overflows section " + section.name);
                }
            }

            return guestBase;
        });
    }

    const Step *RecoveredFunction::instructionContaining(uint32_t rva) const {
        const auto after = graph.upper_bound(rva);
        if (after == graph.begin()) {
            return nullptr;
        }

        const auto &steps = std::prev(after)->second.steps;
        const auto it = std::partition_point(steps.begin(), steps.end(),
                                             [rva](const Step &s) { return s.next <= rva; });
        return it == steps.end() ? nullptr : &*it;
    }

    const DirectCall *RecoveredFunction::callAt(uint32_t instructionRva) const {
        const auto found = calls.find(instructionRva);
        return found == calls.end() ? nullptr : &found->second;
    }

    struct RecoveredFunctionGroup::Decoder {
        explicit Decoder(uint32_t rva);

        const Triple guestTriple{"x86_64-pc-windows-msvc"};
        std::unique_ptr<MCRegisterInfo> regs;
        std::unique_ptr<MCInstrInfo> instructions;
        std::unique_ptr<MCSubtargetInfo> sub;
        // LLVM's assembly info borrows options, and the disassembler borrows the MC context.
        const MCTargetOptions options;
        std::unique_ptr<MCAsmInfo> assembly;
        std::optional<MCContext> context;
        std::unique_ptr<MCDisassembler> dis;
    };

    RecoveredFunctionGroup::Decoder::Decoder(uint32_t rva) {
        // LLVM registry writes must finish before another lift looks up its decoder.
        static std::once_flag registerAmd64;
        std::call_once(registerAmd64, [] {
            LLVMInitializeX86TargetInfo();
            LLVMInitializeX86TargetMC();
            LLVMInitializeX86Disassembler();
        });

        std::string error;
        const auto *target = TargetRegistry::lookupTarget(guestTriple, error);

        if (!target) {
            throw atRva(FailureCode::BackendSetup, rva, error);
        }

        regs.reset(target->createMCRegInfo(guestTriple));
        instructions.reset(target->createMCInstrInfo());
        sub.reset(target->createMCSubtargetInfo(guestTriple, "generic", ""));

        if (!regs || !instructions || !sub) {
            throw atRva(FailureCode::BackendSetup, rva, "AMD64 decoder metadata unavailable");
        }

        assembly = createAsmInfo(*target, *regs, guestTriple, options);

        if (!assembly) {
            throw atRva(FailureCode::BackendSetup, rva, "AMD64 assembly information unavailable");
        }

        context.emplace(guestTriple, *assembly, *regs, *sub);
        dis.reset(target->createMCDisassembler(*sub, *context));

        if (!dis) {
            throw atRva(FailureCode::BackendSetup, rva, "AMD64 disassembler unavailable");
        }
    }

    RecoveredFunctionGroup::RecoveredFunctionGroup(const AnalyzedImage &analysis, uint32_t rva)
        : RecoveredFunctionGroup(validateEntry(analysis, rva)) {}

    RecoveredFunctionGroup::RecoveredFunctionGroup(const ValidatedEntry &entry)
        : source(entry.analysis.image()), entryRva(entry.rva) {
        const auto location = entryLocation(source, entryRva, entry.code);
        withLocation(source, location, FailureCode::LiftingInternal, [&] {
            decoder = std::make_unique<Decoder>(entryRva);
            GroupDiscovery discovery{entry, recovered, {}, {}};
            discovery.run(*decoder->dis, *decoder->instructions, *decoder->regs);
        });
    }

    RecoveredFunctionGroup::~RecoveredFunctionGroup() = default;

    const MCRegisterInfo &RecoveredFunctionGroup::registers() const & { return *decoder->regs; }

    void RecoveredFunctionGroup::annotateFailure(InspectionError &failure) const {
        addLocation(failure, source, entryLocation(source, entryRva, function(entryRva).code));
        const auto instruction = failure.context.instructionRva;

        if (!instruction) {
            return;
        }

        for (const auto &[rva, owner] : recovered) {
            if (rva == entryRva || !owner.instructionContaining(*instruction)) {
                continue;
            }

            failure.context.functionRva = rva;

            if (owner.origin == RecoveryOrigin::InferredLeaf) {
                const auto &site = *owner.incoming.front();
                failure.context.sourceCall = CallLocation{site.caller, site.instruction};
            }

            return;
        }
    }
} // namespace forge::x86
