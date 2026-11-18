#include "lift/recovery.h"

#include "analysis/analysis.h"
#include "forge/guest_range.h"
#include "lift/asm_info.h"
#include "lift/guarded_call.h"
#include "lift/jump_table.h"
#include "lift/leaf_recovery.h"

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/TargetSelect.h"

#include <algorithm>
#include <exception>
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

        // A guest call needs an entry here only if its target failed admission. Replay that
        // error at publication so earlier call sites remain available to diagnostics.
        using CallResolutions =
            std::map<uint32_t, std::variant<ExternalCallTarget, std::exception_ptr>>;

        struct FunctionDiscovery {
            FunctionDiscovery(uint32_t rva, MappedRange code, const MCDisassembler &dis,
                              const MCInstrInfo &instructions, JumpTableReader &tables,
                              bool registerImports)
                : code(code), cfg(code.bytes, rva, dis, instructions, tables, registerImports) {}

            MappedRange code;
            RecordedCFG cfg;
            CallResolutions resolutions;
            std::exception_ptr failure;
            bool mayReturn = false;
            std::vector<CallLocation> waiting;
        };

        struct GroupDiscovery {
            GroupDiscovery(const ValidatedEntry &entry,
                           std::span<const win64::ServiceBinding> services,
                           std::map<uint32_t, RecoveredFunction> &functions,
                           const MCDisassembler &dis, const MCInstrInfo &instructions,
                           const MCRegisterInfo &regs, bool registerImports)
                : entry(entry), services(services), functions(functions), dis(dis),
                  instructions(instructions), regs(regs), tables(entry.analysis.image(), regs),
                  operands(regs, 0), registerImports(registerImports) {}

            const ValidatedEntry &entry;
            std::span<const win64::ServiceBinding> services;
            std::map<uint32_t, RecoveredFunction> &functions;
            std::set<uint32_t> pending;
            std::map<uint32_t, const ResolvedCallSite *> deferred;

            const MCDisassembler &dis;
            const MCInstrInfo &instructions;
            const MCRegisterInfo &regs;
            JumpTableReader tables;
            std::map<uint32_t, FunctionDiscovery> staging;
            std::set<uint32_t> ready, leafCandidates;
            const InstructionOperands operands;
            bool registerImports;
            std::optional<std::vector<RvaRange>> loaderWrites;
            std::optional<std::vector<RvaRange>> recordedRanges;
            std::optional<ImageInitialization> pointerInitialization;
            std::set<uint32_t> thunkStarts;

            ArrayRef<RvaRange> loaderWrittenRanges();
            ArrayRef<RvaRange> functionRanges();
            RegisterCallEvidence pointerTarget(const Step &step, GuardedPointerCall proof);
            std::optional<uint64_t> firstLoaderWrite(uint32_t start, const MappedRange &code);
            void checkCalledExtent(uint32_t target, const MappedRange &code, const Step &step);
            void validateCallEvidence(uint32_t caller, const MappedRange &code, const Step &call,
                                      int64_t target);
            ExternalCallTarget bindImport(uint32_t caller, const MappedRange &code,
                                          const Step &step, uint32_t slot);
            std::optional<ExternalCallTarget> bindImportThunk(uint32_t caller, const Step &step,
                                                              uint32_t target);
            std::optional<MappedRange> calleeCode(uint32_t target, const Step &step);
            bool schedule(uint32_t target, const Step &step, const CallResolutions &resolutions);
            void stage(uint32_t rva, MappedRange code);
            Flow guestCallFlow(uint32_t caller, const Step &step, std::optional<int64_t> target);
            bool advance(uint32_t rva, FunctionDiscovery &active);
            void resumeCallers(FunctionDiscovery &callee);
            void discoverReturns();
            void scanCalls(RecoveredFunction &caller, const GuestBlock &block,
                           const CallResolutions &resolutions);
            Flow importFlow(uint32_t rva, FunctionDiscovery &caller, const Step &step);
            void run();
        };

        ArrayRef<RvaRange> GroupDiscovery::loaderWrittenRanges() {
            if (!loaderWrites) {
                loaderWrites = entry.analysis.image().loaderWrittenRanges();
            }

            return *loaderWrites;
        }

        ArrayRef<RvaRange> GroupDiscovery::functionRanges() {
            if (!recordedRanges) {
                recordedRanges = recordedFunctionRanges(entry.analysis);
            }
            return *recordedRanges;
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

        std::optional<MappedRange> GroupDiscovery::calleeCode(uint32_t target, const Step &step) {
            const auto code = validateCallee(entry.analysis, entry.relocations, step, target);

            if (code) {
                checkCalledExtent(target, *code, step);
            } else if (const auto &table = entry.analysis.module().exceptions;
                       table && table->trailingBytes()) {
                step.reject(
                    FailureCode::UnsupportedControlFlow,
                    "insufficient evidence for leaf recovery: partial runtime function record",
                    target);
            }

            return code;
        }

        bool GroupDiscovery::schedule(uint32_t target, const Step &step,
                                      const CallResolutions &resolutions) {
            // The selected root was seeded without an incoming call. A recursive call
            // can reach it before the root's final extent check.
            if (target == entry.rva) {
                checkCalledExtent(target, entry.code, step);
                return true;
            }

            if (const auto failed = resolutions.find(step.rva); failed != resolutions.end()) {
                std::rethrow_exception(std::get<std::exception_ptr>(failed->second));
            }

            if (leafCandidates.contains(target)) {
                return false;
            }

            if (!functions.contains(target)) {
                pending.insert(target);
            }

            return true;
        }

        void GroupDiscovery::stage(uint32_t rva, MappedRange code) {
            staging.try_emplace(rva, rva, code, dis, instructions, tables, registerImports);
            ready.insert(rva);
        }

        RegisterCallEvidence GroupDiscovery::pointerTarget(const Step &step,
                                                           GuardedPointerCall proof) {
            const auto &image = entry.analysis.image();
            if (!pointerInitialization) {
                pointerInitialization = image.imageInitialization();
            }
            return {guardedCallTarget(step, proof.slot, image, *pointerInitialization),
                    proof.producer};
        }

        Flow GroupDiscovery::guestCallFlow(uint32_t caller, const Step &step,
                                           std::optional<int64_t> immediate) try {
            int64_t target;
            if (immediate) {
                target = *immediate;
            } else if (step.guardedPointerCall) {
                target = pointerTarget(step, *step.guardedPointerCall).target;
            } else {
                step.reject(FailureCode::LiftingInternal, "guest call lacks target evidence");
            }
            if (step.isRegisterCall()) {
                validateCallEvidence(caller, staging.at(caller).code, step, target);
            }

            if (target < 0 || target > UINT32_MAX) {
                step.reject(FailureCode::InvalidCallTarget,
                            "call target outside the guest RVA space", target);
            }

            const auto address = static_cast<uint32_t>(target);
            if (leafCandidates.contains(address)) {
                return Flow::Fallthrough;
            }

            if (address == entry.rva) {
                checkCalledExtent(address, entry.code, step);
            } else if (!staging.contains(address)) {
                const auto code = calleeCode(address, step);
                if (!code) {
                    if (step.isDirectCall()) {
                        if (const auto service = bindImportThunk(caller, step, address)) {
                            staging.at(caller).resolutions.emplace(step.rva, *service);
                            return service->binding.control == win64::Control::Terminates
                                       ? Flow::TerminalCall
                                       : Flow::Fallthrough;
                        }
                    }

                    // The existing leaf proof requires a reachable normal return.
                    leafCandidates.insert(address);
                    return Flow::Fallthrough;
                }

                stage(address, *code);
            }

            auto &callee = staging.at(address);
            if (callee.mayReturn) {
                return Flow::Fallthrough;
            }

            callee.waiting.push_back({caller, step.rva});
            return Flow::TerminalCall;
        } catch (const InspectionError &) {
            staging.at(caller).resolutions.emplace(step.rva, std::current_exception());
            return Flow::Fallthrough;
        }

        bool GroupDiscovery::advance(uint32_t rva, FunctionDiscovery &active) try {
            const auto classify = [&](const Step &step, std::optional<int64_t> target) {
                return step.isMemoryCall() || step.registerImportSlot
                           ? importFlow(rva, active, step)
                           : guestCallFlow(rva, step, target);
            };
            return active.cfg.advance(classify);
        } catch (const InspectionError &) {
            // Preserve the failed body for publication in caller-first order.
            active.failure = std::current_exception();
            return true;
        }

        void GroupDiscovery::resumeCallers(FunctionDiscovery &callee) {
            callee.mayReturn = true;
            for (const auto &site : callee.waiting) {
                auto &caller = staging.at(site.caller);
                if (!caller.failure) {
                    caller.cfg.resume(site.instruction);
                    ready.insert(site.caller);
                }
            }

            callee.waiting.clear();
        }

        void GroupDiscovery::discoverReturns() {
            stage(entry.rva, entry.code);

            while (!ready.empty()) {
                std::set<uint32_t> closed;
                while (!ready.empty()) {
                    const auto rva = ready.extract(ready.begin()).value();
                    auto &active = staging.at(rva);
                    const bool returned = advance(rva, active);
                    if (active.mayReturn) {
                        continue;
                    }

                    if (returned) {
                        resumeCallers(active);
                    } else {
                        closed.insert(rva);
                    }
                }

                // A closed recursive cycle can prove non-return. A failed target or a
                // bypassed proof cannot. Check changed bodies after the RET worklist settles,
                // so an ordinary returning callee never forces a rescan of its caller's proofs.
                for (auto rva : closed) {
                    auto &body = staging.at(rva);
                    if (!body.mayReturn &&
                        (llvm::any_of(body.resolutions,
                                      [](const auto &site) {
                                          return std::holds_alternative<std::exception_ptr>(
                                              site.second);
                                      }) ||
                         body.cfg.hasBypassedProof())) {
                        resumeCallers(body);
                    }
                }
            }
        }

        void GroupDiscovery::validateCallEvidence(uint32_t caller, const MappedRange &code,
                                                  const Step &call, int64_t target) {
            const auto &image = entry.analysis.image();
            if (image.advertisesDynamicRelocations() || !code.section.immutable()) {
                call.reject(
                    FailureCode::UnsupportedControlFlow,
                    "cannot prove a stable indirect call in mutable or dynamically relocated code",
                    target);
            }

            // Nested recorded extents have already passed the loader-write check at admission.
            if (caller != entry.rva) {
                return;
            }

            std::optional<uint64_t> write;
            try {
                write = firstLoaderWrite(caller, code);
            } catch (const InspectionError &error) {
                call.reject(error.kind, error.what(), target);
            }

            if (write) {
                call.reject(FailureCode::UnsupportedControlFlow,
                            "indirect call proof depends on loader-written code at " + hex(*write),
                            target);
            }
        }

        std::optional<ExternalCallTarget>
        GroupDiscovery::bindImportThunk(uint32_t caller, const Step &step, uint32_t target) try {
            const auto code = entry.analysis.image().mapRva(target, amd64ImportThunkSize);
            const auto slot = code ? amd64ImportThunkSlot(target, code->bytes) : std::nullopt;
            if (!slot) {
                return {};
            }

            const RvaRange extent{target, uint64_t(target) + amd64ImportThunkSize};
            if (!code->section.immutable() || !rangesIn(functionRanges(), extent).empty() ||
                entry.relocations.firstOverlap(extent) ||
                !rangesIn(loaderWrittenRanges(), extent).empty()) {
                step.reject(
                    FailureCode::UnsupportedControlFlow,
                    "import thunk overlaps mutable, loader-written, relocated or recorded code",
                    target);
            }

            const auto next = thunkStarts.lower_bound(target);
            if ((next != thunkStarts.end() && *next != target && *next < extent.end) ||
                (next != thunkStarts.begin() &&
                 uint64_t(*std::prev(next)) + amd64ImportThunkSize > target)) {
                step.reject(FailureCode::UnsupportedControlFlow, "overlapping import thunks",
                            target);
            }

            if (!std::in_range<uint32_t>(*slot)) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "import thunk target outside guest RVA space", target);
            }
            const auto binding =
                bindImport(caller, staging.at(caller).code, step, static_cast<uint32_t>(*slot));
            thunkStarts.insert(next, target);
            return binding;
        } catch (InspectionError &error) {
            error.context.branchTarget = target;
            throw;
        }

        ExternalCallTarget GroupDiscovery::bindImport(uint32_t caller, const MappedRange &code,
                                                      const Step &step, uint32_t slot) {
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

                const auto *binding = findService(services, descriptor, symbol);
                if (descriptor.delayed || !binding) {
                    step.reject(FailureCode::UnsupportedControlFlow,
                                Twine(descriptor.delayed ? "unsupported delay import "
                                                         : "unsupported import ") +
                                    descriptor.name + "!" + identity + " at IAT slot " + hex(slot));
                }

                validateCallEvidence(caller, code, step, slot);
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

                if (binding->control == win64::Control::Returns &&
                    step.next >= uint64_t(caller) + code.bytes.size()) {
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

        Flow GroupDiscovery::importFlow(uint32_t rva, FunctionDiscovery &caller, const Step &step) {
            try {
                auto slot = step.registerImportSlot;
                if (!slot) {
                    const auto target = operands.ripRva(step, 0);
                    if (!target || !std::in_range<uint32_t>(*target)) {
                        step.reject(FailureCode::UnsupportedControlFlow,
                                    "expected RIP-relative call through a mapped IAT slot");
                    }

                    operands.decodeAddress(step, 0, true);
                    slot = static_cast<uint32_t>(*target);
                }

                const auto imported = bindImport(rva, caller.code, step, *slot);
                caller.resolutions.emplace(step.rva, imported);
                return imported.binding.control == win64::Control::Terminates ? Flow::TerminalCall
                                                                              : Flow::Fallthrough;
            } catch (const InspectionError &) {
                // Only a proven non-returning import stops decoding. Report failed proofs in
                // the ordered call scan, after recording every preceding call in that block.
                caller.resolutions.emplace(step.rva, std::current_exception());
                return Flow::Fallthrough;
            }
        }

        void GroupDiscovery::scanCalls(RecoveredFunction &caller, const GuestBlock &block,
                                       const CallResolutions &resolutions) try {
            const auto leader = block.steps.front().rva;
            // Partitioning has already placed every possible entry to the sequence at a leader.
            const Step *previous = nullptr;
            for (const auto &step : block.steps) {
                if (isNoop(step)) {
                    continue;
                }

                const auto *producer = std::exchange(previous, &step);
                const auto found = resolutions.find(step.rva);
                if (found != resolutions.end() &&
                    (step.isMemoryCall() || step.registerImportSlot ||
                     std::holds_alternative<ExternalCallTarget>(found->second))) {
                    const auto &resolution = found->second;

                    if (const auto *error = std::get_if<std::exception_ptr>(&resolution)) {
                        std::rethrow_exception(*error);
                    }

                    caller.calls.emplace(
                        step.rva, ResolvedCallSite{caller.entry, leader, step.rva, step.next,
                                                   std::get<ExternalCallTarget>(resolution)});
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
                    const auto proof = step.guardedPointerCall
                                           ? pointerTarget(step, *step.guardedPointerCall)
                                           : operands.leaCallTarget(step, producer);
                    target = proof.target;
                    evidence = proof.producer;
                    validateCallEvidence(caller.entry, caller.code, step, target);
                    kind = CallKind::RipRelativeRegister;
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

                if (!deferred.contains(address) && !schedule(address, step, resolutions)) {
                    deferred.emplace(address, &site);
                }
            }
        } catch (InspectionError &error) {
            if (error.context.instructionRva) {
                error.context.blockRva = block.steps.front().rva;
            }

            throw;
        }

        void GroupDiscovery::run() {
            discoverReturns();

            pending.insert(entry.rva);
            while (!pending.empty()) {
                const auto rva = pending.extract(pending.begin()).value();
                auto staged = staging.extract(rva);
                auto &state = staged.mapped();
                auto &function =
                    functions.try_emplace(rva, rva, RecoveryOrigin::UnwindBacked, state.code)
                        .first->second;

                try {
                    if (state.failure) {
                        std::rethrow_exception(state.failure);
                    }

                    function.graph = state.cfg.finish();
                    for (const auto &[leader, block] : function.graph) {
                        scanCalls(function, block, state.resolutions);
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
                std::vector<RvaRange> thunks;
                for (const auto start : thunkStarts) {
                    thunks.push_back({start, uint64_t(start) + amd64ImportThunkSize});
                }
                recoverLeaves(entry, functions, deferred, functionRanges(), thunks,
                              loaderWrittenRanges(), dis, instructions, regs);
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

    const win64::ServiceBinding *findService(std::span<const win64::ServiceBinding> services,
                                             const Import &descriptor, const Symbol &symbol) {
        const auto binding = std::ranges::find_if(services, [&](const auto &service) {
            return service.dll == descriptor.normalizedName && service.name == symbol.name;
        });

        return binding == services.end() ? nullptr : &*binding;
    }

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

    RecoveredFunctionGroup::RecoveredFunctionGroup(
        const ValidatedEntry &entry, std::span<const win64::ServiceBinding> services,
        llvm::function_ref<void(const RecoveredFunctionGroup &, const InspectionError &)> onFailure,
        bool registerImports)
        : source(entry.analysis.image()), entryRva(entry.rva) {
        const auto location = entryLocation(source, entryRva, entry.code);
        withLocation(source, location, FailureCode::LiftingInternal, [&] {
            decoder = std::make_unique<Decoder>(entryRva);
            GroupDiscovery discovery(entry, services, recovered, *decoder->dis,
                                     *decoder->instructions, *decoder->regs, registerImports);
            try {
                discovery.run();
            } catch (const InspectionError &failure) {
                if (onFailure) {
                    onFailure(*this, failure);
                }

                throw;
            }
        });
    }

    RecoveredFunctionGroup::~RecoveredFunctionGroup() = default;

    const MCRegisterInfo &RecoveredFunctionGroup::registers() const & { return *decoder->regs; }

    std::set<std::pair<std::string_view, std::string_view>>
    RecoveredFunctionGroup::requiredImports() const & {
        std::set<std::pair<std::string_view, std::string_view>> names;

        for (const auto &[rva, function] : recovered) {
            for (const auto &[site, call] : function.calls) {
                if (const auto *service = call.external()) {
                    names.emplace(service->binding.dll, service->binding.name);
                }
            }
        }

        return names;
    }

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
