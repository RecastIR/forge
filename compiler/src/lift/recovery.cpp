#include "lift/recovery.h"
#include "lift/bounded_table.h"

#include "analysis/analysis.h"
#include "forge/guest_range.h"
#include "lift/asm_info.h"
#include "lift/guarded_call.h"
#include "lift/initializer_table.h"
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

        struct RecordedCode {
            const FunctionRange &range;
            MappedRange code;
        };

        std::optional<RecordedCode> validateFunction(const AnalyzedImage &analysis, uint32_t rva,
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

            return RecordedCode{*it, *code};
        }

        std::optional<RecordedCode> validateCallee(const AnalyzedImage &analysis,
                                                   const RelocationIndex &relocations,
                                                   const Step &step, uint32_t target) {
            const auto *section = analysis.image().sectionAtRva(target);

            const auto invalid = step.flow == Flow::TailJump ? FailureCode::InvalidBranchTarget
                                                             : FailureCode::InvalidCallTarget;
            if (!section || section->permissions[2] != 'x') {
                step.reject(invalid, "target outside executable image sections", target);
            }

            if (step.flow == Flow::TailJump && !section->immutable()) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "tail jump requires immutable target code", target);
            }

            FailureContext location;
            try {
                return validateFunction(analysis, target, relocations, location);
            } catch (const InspectionError &error) {
                const auto kind = failureKind(error.kind).category == "invalid_input"
                                      ? invalid
                                      : FailureCode::UnsupportedControlFlow;
                step.reject(kind, error.what(), target);
            }
        }

        // A guest call needs an entry here only if its target failed admission. Replay that
        // error at publication so earlier call sites remain available to diagnostics.
        using CallResolutions =
            std::map<uint32_t,
                     std::variant<ExternalCallTarget, BoundedTableCall, std::exception_ptr>>;

        struct FunctionDiscovery {
            FunctionDiscovery(uint32_t rva, MappedRange code, const MCDisassembler &dis,
                              const MCInstrInfo &instructions, JumpTableReader &tables,
                              bool registerImports)
                : code(code), cfg(code.bytes, rva, dis, instructions, tables, registerImports) {}

            MappedRange code;
            RecordedCFG cfg;
            CallResolutions resolutions;
            unsigned tableEntries = 0;
            std::exception_ptr failure;
            bool mayReturn = false;
            std::vector<CallLocation> waiting;
        };

        struct GroupDiscovery {
            GroupDiscovery(const ValidatedEntry &entry,
                           std::span<const win64::ServiceBinding> services,
                           std::map<uint32_t, RecoveredFunction> &functions,
                           const MCDisassembler &dis, const MCInstrInfo &instructions,
                           const MCRegisterInfo &regs, RecoveryMode mode)
                : entry(entry), services(services), functions(functions), dis(dis),
                  instructions(instructions), regs(regs), tables(entry.analysis.image(), regs),
                  operands(regs, 0), mode(mode) {}

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
            std::map<uint32_t, const ResolvedCallSite *> callbackSources;
            const InstructionOperands operands;
            RecoveryMode mode;
            std::optional<std::vector<RvaRange>> loaderWrites;
            std::optional<std::vector<RvaRange>> recordedRanges;
            std::optional<ImageInitialization> pointerInitialization;
            std::set<uint32_t> thunkStarts;
            std::vector<RvaRange> tableData;
            std::map<uint32_t, const ResolvedCallSite *> tableSources;

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
            std::optional<RecordedCode> calleeCode(uint32_t target, const Step &step);
            RecordedCode validateTailTarget(uint32_t target, const Step &step);
            bool schedule(uint32_t target, const Step &step, const CallResolutions &resolutions);
            void stage(uint32_t rva, MappedRange code);
            Flow guestCallFlow(uint32_t caller, const Step &step, std::optional<int64_t> target);
            Flow stageGuestTarget(uint32_t caller, const Step &step, std::optional<int64_t> target);
            bool advance(uint32_t rva, FunctionDiscovery &active);
            void resumeCallers(FunctionDiscovery &callee);
            void discoverReturns();
            void publishImport(RecoveredFunction &caller, const GuestBlock &block, const Step &step,
                               const ExternalCallTarget &service,
                               InitializerRecovery &initializers);
            void admitCallback(const ResolvedCallSite &site, const Step &step, uint32_t rva);
            void scanCalls(RecoveredFunction &caller, const GuestBlock &block,
                           const CallResolutions &resolutions, InitializerRecovery &initializers);
            Flow admitTableTarget(uint32_t caller, const Step &step, uint32_t header,
                                  uint32_t target);
            Flow tableFlow(uint32_t caller, FunctionDiscovery &active, const Step &step);
            Flow importFlow(uint32_t rva, FunctionDiscovery &caller, const Step &step);
            std::vector<ResolvedCallSite *> forwardedRegistrations;

            void resolveRegistrationOrigin(ResolvedCallSite &site,
                                           const ResolvedCallSite &incoming);
            void resolveForwardedRegistrations();
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

        std::optional<RecordedCode> GroupDiscovery::calleeCode(uint32_t target, const Step &step) {
            const auto code = validateCallee(entry.analysis, entry.relocations, step, target);

            if (code) {
                checkCalledExtent(target, code->code, step);
                return code;
            }

            if (const auto &table = entry.analysis.module().exceptions;
                table && table->trailingBytes()) {
                step.reject(
                    FailureCode::UnsupportedControlFlow,
                    "insufficient evidence for leaf recovery: partial runtime function record",
                    target);
            }

            return {};
        }

        RecordedCode GroupDiscovery::validateTailTarget(uint32_t target, const Step &step) {
            const auto code = calleeCode(target, step);
            if (!code) {
                const auto recorded = rangesIn(functionRanges(), {target, uint64_t(target) + 1});
                step.reject(FailureCode::UnsupportedControlFlow,
                            recorded.empty()
                                ? "tail jump requires an unwind-backed function entry"
                                : "tail jump enters the interior of a recorded function",
                            target);
            }

            const StableMetadata stable{entry.analysis.image(), entry.relocations,
                                        loaderWrittenRanges()};
            if (!stable.containsUnwindRecord(code->range)) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "tail jump requires stable target function table and unwind metadata",
                            target);
            }

            return *code;
        }

        bool GroupDiscovery::schedule(uint32_t target, const Step &step,
                                      const CallResolutions &resolutions) {
            // The selected root was seeded without an incoming call. A recursive call
            // can reach it before the root's final extent check.
            if (target == entry.rva) {
                checkCalledExtent(target, entry.code, step);
                return true;
            }

            if (const auto failed = resolutions.find(step.rva);
                failed != resolutions.end() &&
                std::holds_alternative<std::exception_ptr>(failed->second)) {
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
            staging.try_emplace(rva, rva, code, dis, instructions, tables,
                                mode == RecoveryMode::PeEntry);
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
            return stageGuestTarget(caller, step, immediate);
        } catch (const InspectionError &) {
            staging.at(caller).resolutions.emplace(step.rva, std::current_exception());
            return Flow::Fallthrough;
        }

        Flow GroupDiscovery::stageGuestTarget(uint32_t caller, const Step &step,
                                              std::optional<int64_t> immediate) {
            int64_t target;
            if (immediate) {
                target = *immediate;
            } else if (step.guardedPointerCall) {
                target = pointerTarget(step, *step.guardedPointerCall).target;
            } else {
                step.reject(FailureCode::LiftingInternal, "guest call lacks target evidence");
            }
            const bool tail = step.flow == Flow::TailJump;
            if (step.isRegisterCall() || tail) {
                validateCallEvidence(caller, staging.at(caller).code, step, target);
            }

            if (target < 0 || target > UINT32_MAX) {
                step.reject(step.flow == Flow::TailJump ? FailureCode::UnsupportedControlFlow
                                                        : FailureCode::InvalidCallTarget,
                            "transfer target outside the guest RVA space", target);
            }

            const auto address = static_cast<uint32_t>(target);
            const auto tailCode =
                tail ? std::optional{validateTailTarget(address, step)} : std::nullopt;

            if (leafCandidates.contains(address)) {
                return Flow::Fallthrough;
            }

            // An initializer discovered during publication can call a previously
            // published body. Its return proof has already reached the fixed point.
            if (const auto published = functions.find(address); published != functions.end()) {
                return published->second.mayReturn ? Flow::Fallthrough : Flow::TerminalCall;
            }

            if (address == entry.rva) {
                checkCalledExtent(address, entry.code, step);
            } else if (!staging.contains(address)) {
                const auto code = tail ? tailCode : calleeCode(address, step);
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

                stage(address, code->code);
            }

            auto &callee = staging.at(address);
            if (callee.mayReturn) {
                return Flow::Fallthrough;
            }

            callee.waiting.push_back({caller, step.rva});
            return Flow::TerminalCall;
        }

        Flow GroupDiscovery::admitTableTarget(uint32_t caller, const Step &step, uint32_t header,
                                              uint32_t target) try {
            const auto &image = entry.analysis.image();
            const auto *section = image.sectionAtRva(target);
            if (!section || !section->immutable() || section->permissions[2] != 'x') {
                step.reject(FailureCode::InvalidCallTarget,
                            "bounded table target outside immutable executable code at table " +
                                hex(header),
                            target);
            }
            const auto code = calleeCode(target, step);
            if (code && !StableMetadata{image, entry.relocations, loaderWrittenRanges()}
                             .containsUnwindRecord(code->range)) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "unstable bounded target function record", target);
            }
            return stageGuestTarget(caller, step, target);
        } catch (InspectionError &failure) {
            failure.context.tableHeaderRva = header;
            failure.context.tableTargetRva = target;
            throw;
        }

        Flow GroupDiscovery::tableFlow(uint32_t caller, FunctionDiscovery &active,
                                       const Step &step) try {
            const auto &image = entry.analysis.image();
            if (!pointerInitialization) {
                pointerInitialization = image.imageInitialization();
            }
            validateCallEvidence(caller, active.code, step, step.rva);
            auto table = recoverTableCall(active.cfg.steps(), step, operands, image,
                                          *pointerInitialization, functionRanges());
            if (!rangesIn(loaderWrittenRanges(), table.extent()).empty()) {
                step.reject(FailureCode::ImageMemory,
                            "loader write overlaps bounded table at " + hex(table.header));
            }
            const unsigned count = (table.last - table.first) / 8;
            if (count > 4096 - active.tableEntries) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "bounded table entry budget exceeded at " + hex(table.header));
            }
            active.tableEntries += count;
            bool returns = false;
            for (const auto target : table.targets) {
                returns |=
                    admitTableTarget(caller, step, table.header, target) == Flow::Fallthrough;
            }

            active.resolutions.emplace(step.rva, std::move(table));
            return returns ? Flow::Fallthrough : Flow::TerminalCall;
        } catch (const InspectionError &) {
            active.resolutions.emplace(step.rva, std::current_exception());
            return Flow::Fallthrough;
        }

        bool GroupDiscovery::advance(uint32_t rva, FunctionDiscovery &active) try {
            const auto classify = [&](const Step &step, std::optional<int64_t> target) {
                if (step.isMemoryCall() && !operands.ripRva(step, 0)) {
                    return tableFlow(rva, active, step);
                }
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

        void GroupDiscovery::publishImport(RecoveredFunction &caller, const GuestBlock &block,
                                           const Step &step, const ExternalCallTarget &service,
                                           InitializerRecovery &initializers) try {
            auto imported = service;
            const auto callback = imported.binding.callback;
            if (!pointerInitialization && (callback == win64::Callback::Initializer ||
                                           callback == win64::Callback::Registration)) {
                pointerInitialization = entry.analysis.image().imageInitialization();
            }

            if (callback == win64::Callback::Initializer) {
                imported.initializers = recoverInitializerTable(
                    caller, block, step, imported.binding, entry.analysis.image(),
                    *pointerInitialization, instructions, regs, initializers);
            }

            if (callback == win64::Callback::Registration) {
                auto &proof = imported.registration.emplace();
                if (const auto target =
                        terminationTarget(caller, block, step, entry.analysis.image(),
                                          *pointerInitialization, instructions, regs)) {
                    proof.targets.emplace(0, *target);
                } else {
                    proof.forwarded = true;
                    caller.receivesRegistrationOrigin = true;
                }
            }

            const auto leader = block.steps.front().rva;
            auto &site = caller.calls
                             .emplace(step.rva, ResolvedCallSite{caller.entry, leader, step.rva,
                                                                 step.next, std::move(imported)})
                             .first->second;
            if (const auto &proof = site.external()->registration) {
                if (proof->forwarded) {
                    forwardedRegistrations.push_back(&site);
                } else if (const auto target = proof->targets.at(0)) {
                    admitCallback(site, step, target);
                }
            }

            if (site.external()->initializers) {
                for (const auto rva : site.external()->initializers->targets) {
                    admitCallback(site, step, rva);
                }
            }
        } catch (InspectionError &error) {
            if (error.context.instructionRva == step.rva) {
                error.context.branchTarget = step.directCallTarget();
            }
            error.context.importSlot = service.slot;
            error.context.importDll = service.descriptor.name;
            error.context.importSymbol = std::string(service.binding.name);
            throw;
        }

        void GroupDiscovery::admitCallback(const ResolvedCallSite &site, const Step &step,
                                           uint32_t rva) try {
            const auto *section = entry.analysis.image().sectionAtRva(rva);
            if (!section || section->permissions[2] != 'x' || !section->immutable()) {
                step.reject(FailureCode::InvalidCallTarget,
                            site.external()->registration
                                ? "termination callback requires immutable executable bytes"
                                : "initializer target requires immutable executable bytes");
            }

            if (!callbackSources.try_emplace(rva, &site).second || functions.contains(rva)) {
                return;
            }

            if (!staging.contains(rva) && !leafCandidates.contains(rva)) {
                if (const auto code = calleeCode(rva, step)) {
                    stage(rva, code->code);
                } else {
                    leafCandidates.insert(rva);
                }
            }

            if (leafCandidates.contains(rva)) {
                deferred.insert_or_assign(rva, &site);
            } else {
                pending.insert(rva);
            }
        } catch (InspectionError &error) {
            site.annotateCallbackFailure(error.context, rva);
            throw;
        }

        void GroupDiscovery::validateCallEvidence(uint32_t caller, const MappedRange &code,
                                                  const Step &call, int64_t target) {
            const auto &image = entry.analysis.image();
            if (image.advertisesDynamicRelocations() || !code.section.immutable()) {
                const auto transfer = call.flow == Flow::TailJump ? "tail jump" : "indirect call";
                call.reject(FailureCode::UnsupportedControlFlow,
                            Twine("cannot prove a stable ") + transfer +
                                " in mutable or dynamically relocated code",
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
                            Twine(call.flow == Flow::TailJump ? "tail jump" : "indirect call") +
                                " proof depends on loader-written code at " + hex(*write),
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
                                       const CallResolutions &resolutions,
                                       InitializerRecovery &initializers) try {
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

                    if (const auto *table = std::get_if<BoundedTableCall>(&resolution)) {
                        validateTableLoop(caller, step, *table, operands);
                        tableData.push_back(table->extent());
                        const auto &site =
                            caller.calls
                                .emplace(step.rva, ResolvedCallSite{caller.entry, leader, step.rva,
                                                                    step.next, *table})
                                .first->second;
                        for (const auto target : table->targets) {
                            tableSources.try_emplace(target, &site);
                            if (!schedule(target, step, resolutions)) {
                                deferred.try_emplace(target, &site);
                            }
                        }
                        continue;
                    }

                    const auto &service = std::get<ExternalCallTarget>(resolution);
                    if (mode == RecoveryMode::FunctionLift &&
                        service.binding.callback != win64::Callback::None) {
                        // A direct CALL encodes the thunk RVA. Only the memory CALL
                        // has an IAT slot as its own operand in a function diagnostic.
                        const auto slot =
                            step.isMemoryCall() ? std::optional{service.slot} : std::nullopt;
                        step.reject(FailureCode::UnsupportedControlFlow,
                                    service.descriptor.name + "!" +
                                        std::string(service.binding.name) +
                                        " requires a managed process artifact or --executable",
                                    {}, slot);
                    }

                    publishImport(caller, block, step, service, initializers);
                    continue;
                }

                if (step.flow == Flow::TailJump) {
                    if (found != resolutions.end()) {
                        std::rethrow_exception(std::get<std::exception_ptr>(found->second));
                    }

                    const auto target = static_cast<uint32_t>(step.relativeTarget());
                    schedule(target, step, resolutions);
                    caller.calls.emplace(
                        step.rva,
                        ResolvedCallSite{caller.entry, leader, step.rva, std::nullopt,
                                         GuestCallTarget{target, CallKind::TailJump, step.rva}});
                    continue;
                }

                CallKind kind;
                int64_t target;
                uint32_t evidence;
                if (const auto direct = step.directCallTarget()) {
                    kind = CallKind::Direct;
                    target = *direct;
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

        void GroupDiscovery::resolveRegistrationOrigin(ResolvedCallSite &site,
                                                       const ResolvedCallSite &incoming) try {
            auto &proof = *std::get<ExternalCallTarget>(site.target).registration;
            if (proof.targets.contains(incoming.instruction)) {
                return;
            }

            const auto &caller = functions.at(incoming.caller);
            const auto &step = *caller.instructionContaining(incoming.instruction);
            if (incoming.table() || incoming.guest().kind == CallKind::RipRelativeRegister ||
                proof.targets.size() >= 4096) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "unsupported CRT registration wrapper origin");
            }

            const auto target = terminationTarget(caller, caller.graph.at(incoming.block), step,
                                                  entry.analysis.image(), *pointerInitialization,
                                                  instructions, regs);
            if (!target) {
                step.reject(FailureCode::UnsupportedControlFlow,
                            "unproven callback at caller of CRT registration wrapper");
            }

            proof.targets.emplace(incoming.instruction, *target);
            if (*target) {
                admitCallback(site, step, *target);
            }
        } catch (InspectionError &error) {
            auto &context = error.context;
            context.functionRva = incoming.caller;
            context.blockRva = incoming.block;
            context.branchTarget = site.caller;
            if (!context.sourceCall) {
                site.annotateCallbackFailure(context, {});
            }
            throw;
        }

        void GroupDiscovery::resolveForwardedRegistrations() {
            if (forwardedRegistrations.empty()) {
                return;
            }

            std::map<uint32_t, std::vector<const ResolvedCallSite *>> callers;
            for (const auto &[rva, function] : functions) {
                for (const auto &[address, call] : function.calls) {
                    for (const auto target : call.guestTargets()) {
                        callers[target].push_back(&call);
                    }
                }
            }

            for (auto *site : forwardedRegistrations) {
                for (const auto *incoming : callers[site->caller]) {
                    resolveRegistrationOrigin(*site, *incoming);
                }
            }
        }

        // The two SCC traversals borrow the same transfer records in opposite directions.
        std::vector<uint32_t>
        incomingFinishOrder(const std::map<uint32_t, RecoveredFunction> &functions) {
            std::set<uint32_t> seen;
            std::vector<uint32_t> order;
            for (const auto &[entry, function] : functions) {
                if (!seen.insert(entry).second) {
                    continue;
                }

                std::vector<std::pair<uint32_t, size_t>> stack{{entry, 0}};
                while (!stack.empty()) {
                    auto &[rva, index] = stack.back();
                    const auto &incoming = functions.at(rva).incoming;
                    if (index == incoming.size()) {
                        order.push_back(rva);
                        stack.pop_back();
                        continue;
                    }

                    const auto source = incoming[index++]->caller;
                    if (seen.insert(source).second) {
                        stack.emplace_back(source, 0);
                    }
                }
            }

            return order;
        }

        std::map<uint32_t, uint32_t>
        transferComponents(const std::map<uint32_t, RecoveredFunction> &functions) {
            const auto order = incomingFinishOrder(functions);
            std::map<uint32_t, uint32_t> components;
            for (auto start : llvm::reverse(order)) {
                if (!components.emplace(start, start).second) {
                    continue;
                }

                std::vector<uint32_t> pending{start};
                while (!pending.empty()) {
                    const auto rva = pending.back();
                    pending.pop_back();
                    for (const auto &[site, transfer] : functions.at(rva).calls) {
                        for (const auto target : transfer.guestTargets()) {
                            if (functions.contains(target) &&
                                components.emplace(target, start).second) {
                                pending.push_back(target);
                            }
                        }
                    }
                }
            }

            return components;
        }

        // Also classify the published portion of a group when a later dependency fails.
        const ResolvedCallSite *indexTransfers(std::map<uint32_t, RecoveredFunction> &functions) {
            bool hasTailJump = false;
            for (const auto &[caller, function] : functions) {
                for (const auto &[instruction, call] : function.calls) {
                    for (const auto rva : call.guestTargets()) {
                        const auto target = functions.find(rva);
                        if (target != functions.end()) {
                            target->second.incoming.push_back(&call);
                            hasTailJump |= call.isTailJump();
                        }
                    }
                }
            }

            if (!hasTailJump) {
                return nullptr;
            }

            const auto components = transferComponents(functions);
            const ResolvedCallSite *first = nullptr;

            for (auto &[rva, function] : functions) {
                for (auto &[site, transfer] : function.calls) {
                    if (!transfer.isTailJump()) {
                        continue;
                    }

                    auto &target = std::get<GuestCallTarget>(transfer.target);
                    const auto component = components.find(target.rva);
                    if (component == components.end() || component->second != components.at(rva)) {
                        continue;
                    }

                    target.recursiveTail = true;

                    if (!first) {
                        first = &transfer;
                    }
                }
            }

            return first;
        }

        void GroupDiscovery::run() {
            stage(entry.rva, entry.code);
            pending.insert(entry.rva);
            while (!pending.empty()) {
                discoverReturns();
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

                    function.mayReturn = state.mayReturn;
                    function.graph = state.cfg.finish();
                    InitializerRecovery initializers;
                    for (const auto &[leader, block] : function.graph) {
                        scanCalls(function, block, state.resolutions, initializers);
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

                    const auto indirect = tableSources.find(rva);
                    if (!error.context.sourceCall && indirect != tableSources.end()) {
                        indirect->second->annotateTableFailure(error.context, rva);
                    }
                    const auto source = callbackSources.find(rva);
                    if (!error.context.sourceCall && source != callbackSources.end()) {
                        source->second->annotateCallbackFailure(error.context, rva);
                    }
                    throw;
                }
                if (pending.empty()) {
                    resolveForwardedRegistrations();
                }
            }

            for (const auto *site : forwardedRegistrations) {
                if (site->caller == entry.rva || callbackSources.contains(site->caller) ||
                    site->external()->registration->targets.empty()) {
                    functions.at(site->caller)
                        .instructionContaining(site->instruction)
                        ->reject(FailureCode::UnsupportedControlFlow,
                                 "CRT registration wrapper requires a proven direct guest caller");
                }
            }

            if (!deferred.empty()) {
                std::vector<RvaRange> thunks;
                for (const auto start : thunkStarts) {
                    thunks.push_back({start, uint64_t(start) + amd64ImportThunkSize});
                }
                tableData = mergeRanges(std::move(tableData));
                recoverLeaves(entry, functions, deferred, functionRanges(), thunks,
                              loaderWrittenRanges(), tableData, dis, instructions, regs);
            }

            for (const auto &[rva, site] : callbackSources) {
                functions.at(rva).callbackSource = site;
            }
        }
    } // namespace

    void ResolvedCallSite::annotateCallbackFailure(FailureContext &context,
                                                   std::optional<uint32_t> targetRva) const {
        if (external()->registration) {
            context.terminationTargetRva = targetRva;
        } else {
            context.initializerTargetRva = targetRva;
        }

        context.sourceCall = CallLocation{caller, instruction};

        if (!context.importSlot) {
            const auto &service = *external();
            context.importSlot = service.slot;
            context.importDll = service.descriptor.name;
            context.importSymbol = std::string(service.binding.name);
        }
    }

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

            return ValidatedEntry{analysis, rva, code->code, std::move(relocations)};
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
        RecoveryMode mode)
        : source(entry.analysis.image()), entryRva(entry.rva) {
        const auto location = entryLocation(source, entryRva, entry.code);
        withLocation(source, location, FailureCode::LiftingInternal, [&] {
            decoder = std::make_unique<Decoder>(entryRva);
            GroupDiscovery discovery(entry, services, recovered, *decoder->dis,
                                     *decoder->instructions, *decoder->regs, mode);
            try {
                discovery.run();
            } catch (const InspectionError &failure) {
                if (onFailure) {
                    indexTransfers(recovered);
                    onFailure(*this, failure);
                }

                throw;
            }

            if (const auto *cycle = indexTransfers(recovered)) {
                const auto &function = recovered.at(cycle->caller);
                try {
                    function.instructionContaining(cycle->instruction)
                        ->reject(FailureCode::UnsupportedControlFlow,
                                 "recursive cross-function tail transfer", cycle->guest().rva);
                } catch (InspectionError &failure) {
                    failure.context.functionRva = cycle->caller;
                    failure.context.blockRva = cycle->block;

                    if (onFailure) {
                        onFailure(*this, failure);
                    }

                    throw;
                }
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

            for (const auto *incoming : owner.incoming) {
                if (incoming->table() && !failure.context.sourceCall) {
                    incoming->annotateTableFailure(failure.context, rva);
                    break;
                }
            }
            if (failure.context.sourceCall) {
                return;
            }
            if (const auto *sourceSite = owner.callbackSource) {
                sourceSite->annotateCallbackFailure(failure.context, rva);
            } else if (owner.origin == RecoveryOrigin::InferredLeaf && !owner.incoming.empty()) {
                const auto &site = *owner.incoming.front();
                failure.context.sourceCall = CallLocation{site.caller, site.instruction};
            }

            return;
        }
    }
} // namespace forge::x86
