#include "lift/recovery.h"

#include "analysis/analysis.h"
#include "forge/guest_range.h"
#include "lift/asm_info.h"
#include "lift/jump_table.h"
#include "lift/leaf_recovery.h"

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetSelect.h"

#include <algorithm>
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
                            "call target outside executable image sections", target);
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
            std::span<const win64::ServiceBinding> services;
            std::map<uint32_t, RecoveredFunction> &functions;
            std::map<uint32_t, MappedRange> pending;
            std::map<uint32_t, const ResolvedCallSite *> deferred;

            const InstructionOperands operands;
            std::optional<std::vector<RvaRange>> loaderWrites;

            ArrayRef<RvaRange> loaderWrittenRanges();
            std::optional<uint64_t> firstLoaderWrite(uint32_t start, const MappedRange &code);
            void checkCalledExtent(uint32_t target, const MappedRange &code, const Step &step);
            void validateCallEvidence(const RecoveredFunction &caller, const Step &call,
                                      int64_t target);
            ExternalCallTarget bindImport(const RecoveredFunction &caller, const Step &step);
            bool schedule(uint32_t target, const Step &step);
            void scanCalls(RecoveredFunction &caller, const GuestBlock &block);
            void run(const MCDisassembler &dis, const MCInstrInfo &instructions,
                     const MCRegisterInfo &regs);
        };

        ArrayRef<RvaRange> GroupDiscovery::loaderWrittenRanges() {
            if (!loaderWrites) {
                loaderWrites = entry.analysis.image().loaderWrittenRanges();
            }

            return *loaderWrites;
        }

        std::optional<uint64_t> GroupDiscovery::firstLoaderWrite(uint32_t start,
                                                                 const MappedRange &code) {
            const RvaRange extent{start, uint64_t(start) + code.bytes.size()};
            const auto overlaps = rangesIn(loaderWrittenRanges(), extent);
            if (overlaps.empty()) {
                return {};
            }

            return std::max(extent.begin, overlaps.front().begin);
        }

        void GroupDiscovery::checkCalledExtent(uint32_t target, const MappedRange &code,
                                               const Step &step) {
            if (const auto write = firstLoaderWrite(target, code)) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "callee overlaps loader-written bytes at " + hex(*write), target);
            }
        }

        bool GroupDiscovery::schedule(uint32_t target, const Step &step) {
            // The selected root was seeded without an incoming call. A recursive call
            // can reach it before the root's final extent check.
            if (target == entry.rva) {
                checkCalledExtent(target, entry.code, step);
                return true;
            }

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

            checkCalledExtent(target, *code, step);
            pending.emplace(target, *code);
            return true;
        }

        void GroupDiscovery::validateCallEvidence(const RecoveredFunction &caller, const Step &call,
                                                  int64_t target) {
            const auto &image = entry.analysis.image();
            if (image.advertisesDynamicRelocations() || !caller.code.section.immutable()) {
                call.reject(
                    FailureCode::UnsupportedControlFlow,
                    "cannot prove a stable indirect call in mutable or dynamically relocated code",
                    target);
            }

            // Nested recorded extents have already passed the loader-write check at admission.
            if (caller.entry != entry.rva) {
                return;
            }

            std::optional<uint64_t> write;
            try {
                write = firstLoaderWrite(caller.entry, caller.code);
            } catch (const InspectionError &error) {
                call.reject(error.kind, error.what(), target);
            }

            if (write) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "indirect call proof depends on loader-written code at " + hex(*write),
                            target);
            }
        }

        ExternalCallTarget GroupDiscovery::bindImport(const RecoveredFunction &caller,
                                                      const Step &step) {
            const auto target = operands.ripRva(step, 0);
            if (!target || *target < 0 || *target > UINT32_MAX) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "expected RIP-relative call through a mapped IAT slot");
            }

            operands.decodeAddress(step, 0, true);
            const auto slot = static_cast<uint32_t>(*target);
            std::string identity;

            const auto imported = [&] {
                try {
                    return entry.analysis.image().importBindings().at(slot);
                } catch (const InspectionError &error) {
                    step.reject(error.kind, error.what(), {}, slot, error.context.importOwnership);
                }
            }();
            try {
                if (!imported) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "no complete validated IAT slot at " + hex(slot));
                }

                const auto &descriptor = imported->descriptor;
                const auto &symbol = imported->symbol;
                identity = symbol.ordinal ? "#" + std::to_string(*symbol.ordinal) : symbol.name;
                if (descriptor.bound && !descriptor.lookupRva) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "bound IAT has no independent import lookup table");
                }

                const auto binding = std::ranges::find_if(services, [&](const auto &service) {
                    return service.dll == descriptor.normalizedName && service.name == symbol.name;
                });
                if (descriptor.delayed || binding == services.end()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                Twine(descriptor.delayed ? "unsupported delay import "
                                                         : "unsupported import ") +
                                    descriptor.name + "!" + identity + " at IAT slot " + hex(slot));
                }

                validateCallEvidence(caller, step, slot);
                if (const auto error = binding->error(); !error.empty()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "unsupported native service signature for " + descriptor.name +
                                    "!" + identity + ": " + std::string(error));
                }
                if (const auto changed =
                        imported->unstableIdentityRva(entry.relocations, loaderWrittenRanges())) {
                    step.reject(
                        FailureCode::UnsupportedControlFlow,
                        "import identity overlaps loader-written or relocated bytes at RVA " +
                            hex(*changed));
                }

                if (step.next >= uint64_t(caller.entry) + caller.code.bytes.size()) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                "external call has no in-function continuation");
                }

                return {slot, descriptor, *binding};
            } catch (InspectionError &error) {
                error.context.branchTarget.reset();
                error.context.importSlot = slot;
                if (imported) {
                    error.context.importDll = imported->descriptor.name;
                    error.context.importSymbol = identity;
                }

                throw;
            }
        }

        void GroupDiscovery::scanCalls(RecoveredFunction &caller, const GuestBlock &block) try {
            const auto leader = block.steps.front().rva;
            // Partitioning has already placed every possible entry to the sequence at a leader.
            const Step *previous = nullptr;
            for (const auto &step : block.steps) {
                if (isNoop(step)) {
                    continue;
                }

                const auto *producer = std::exchange(previous, &step);
                if (step.isMemoryCall()) {
                    caller.calls.emplace(step.rva,
                                         ResolvedCallSite{caller.entry, leader, step.rva, step.next,
                                                          bindImport(caller, step)});
                    continue;
                }

                CallKind kind;
                int64_t target;
                uint32_t evidence;
                if (step.isDirectCall()) {
                    kind = CallKind::Direct;
                    target = int64_t(step.next) + step.inst.getOperand(0).getImm();
                    evidence = step.rva;
                } else if (step.isRegisterCall()) {
                    target = operands.registerCallRva(step, producer);
                    validateCallEvidence(caller, step, target);
                    kind = CallKind::RipRelativeRegister;
                    evidence = producer->rva;
                } else {
                    continue;
                }

                if (target < 0 || target > UINT32_MAX) {
                    step.reject(FailureCode::InvalidCallTarget,
                                "call target outside the guest RVA space", target);
                }

                const auto address = static_cast<uint32_t>(target);
                const auto &site =
                    caller.calls
                        .emplace(step.rva,
                                 ResolvedCallSite{caller.entry, leader, step.rva, step.next,
                                                  GuestCallTarget{address, kind, evidence}})
                        .first->second;

                if (!deferred.contains(address) && !schedule(address, step)) {
                    deferred.emplace(address, &site);
                }
            }
        } catch (InspectionError &error) {
            if (error.context.instructionRva) {
                error.context.blockRva = block.steps.front().rva;
            }

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
                        scanCalls(function, block);
                    }

                    // Give a register CALL or table JMP its more specific proof diagnostic first.
                    if (rva == entry.rva) {
                        if (const auto write = firstLoaderWrite(rva, function.code)) {
                            throw atRva(FailureCode::ImageMemory, rva,
                                        "function overlaps loader-written bytes at " + hex(*write));
                        }
                    }
                } catch (InspectionError &error) {
                    if (rva != entry.rva) {
                        error.context.functionRva = rva;
                    }

                    throw;
                }
            }

            if (!deferred.empty()) {
                recoverLeaves(entry, functions, deferred, loaderWrittenRanges(), dis, instructions,
                              regs);
            }

            // Incoming indices follow source order even when discovery began at a higher RVA.
            for (const auto &[caller, function] : functions) {
                for (const auto &[instruction, call] : function.calls) {
                    if (!call.external()) {
                        functions.at(call.guest().rva).incoming.push_back(&call);
                    }
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
                if (section.virtualSize &&
                    !GuestRange::fromOffset({guestBase}, section.rva, section.virtualSize)) {
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

    const ResolvedCallSite *RecoveredFunction::callAt(uint32_t instructionRva) const {
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

    RecoveredFunctionGroup::RecoveredFunctionGroup(const ValidatedEntry &entry,
                                                   std::span<const win64::ServiceBinding> services)
        : source(entry.analysis.image()), entryRva(entry.rva) {
        const auto location = entryLocation(source, entryRva, entry.code);
        withLocation(source, location, FailureCode::LiftingInternal, [&] {
            decoder = std::make_unique<Decoder>(entryRva);
            GroupDiscovery discovery{
                entry, services, recovered, {}, {}, InstructionOperands(*decoder->regs, 0), {}};
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
            if (const auto *site = owner.callAt(*instruction); site && site->external()) {
                const auto &target = *site->external();
                failure.context.blockRva = site->block;
                failure.context.importSlot = target.slot;
                failure.context.importDll = target.descriptor.name;
                failure.context.importSymbol = std::string(target.binding.name);
            }

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
