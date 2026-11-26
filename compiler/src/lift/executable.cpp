#include "lift/executable.h"

#include "analysis/analysis.h"
#include "forge/process.h"

#include <tuple>

namespace forge::x86 {
    namespace {
        std::string importName(const Symbol &symbol) {
            return symbol.ordinal ? "#" + std::to_string(*symbol.ordinal) : symbol.name;
        }

        void recordImport(ExecutableReadiness &readiness, const std::string &dll,
                          const std::string &name) {
            const auto key = std::tie(dll, name);
            auto pos =
                llvm::lower_bound(readiness.imports, key, [](const auto &item, const auto &value) {
                    return std::tie(item.dll, item.name) < value;
                });

            if (pos == readiness.imports.end() || std::tie(pos->dll, pos->name) != key) {
                readiness.imports.insert(pos, {dll, name});
            }
        }

        std::optional<ExecutableUnresolvedCall> failedCall(const RecoveredFunctionGroup &group,
                                                           const FailureContext &context) {
            if (context.sourceCall) {
                const auto &source = *context.sourceCall;
                const auto &call = group.function(source.caller).calls.at(source.instruction);
                if (!call.external() && !call.table()) {
                    return ExecutableUnresolvedCall{source.caller, source.instruction,
                                                    call.guest().rva};
                }

                // A failed CALL inside an admitted target has its own unresolved edge.
                if (context.instructionRva == source.instruction ||
                    !llvm::StringRef(context.opcode).starts_with("CALL")) {
                    if (call.table()) {
                        return ExecutableUnresolvedCall{source.caller, source.instruction,
                                                        context.tableTargetRva};
                    }
                    return ExecutableUnresolvedCall{source.caller, source.instruction,
                                                    context.terminationTargetRva
                                                        ? context.terminationTargetRva
                                                        : context.initializerTargetRva};
                }
            }

            if (context.instructionRva && llvm::StringRef(context.opcode).starts_with("CALL")) {
                return ExecutableUnresolvedCall{context.functionRva.value_or(group.root()),
                                                *context.instructionRva, context.branchTarget};
            }

            return {};
        }

        void recordCallTargets(ExecutableReadiness &readiness, const RecoveredFunctionGroup &group,
                               const RecoveredFunction &function,
                               const std::optional<ExecutableUnresolvedCall> &failed) {
            for (const auto &[instruction, call] : function.calls) {
                if (const auto *external = call.external()) {
                    if (const auto &table = external->initializers) {
                        readiness.initializerTables.push_back({function.entry, instruction,
                                                               table->first, table->last,
                                                               table->targets});
                    }
                    continue;
                }

                if (const auto *table = call.table()) {
                    readiness.boundedCalls.push_back(
                        {function.entry, instruction, table->first, table->last, table->targets,
                         table->forward() ? std::optional{table->forward()->pointerLoad}
                                          : std::nullopt});
                }

                const bool failedSite = failed && failed->callerRva == function.entry &&
                                        failed->instructionRva == instruction;
                if (call.isTailJump()) {
                    if (!failedSite && !call.guest().recursiveTail) {
                        readiness.tailTransfers.push_back(
                            {function.entry, instruction, call.guest().rva});
                    }
                    continue;
                }

                for (const auto target : call.guestTargets()) {
                    if (failedSite && (!call.table() || failed->targetRva == target)) {
                        continue;
                    }
                    const auto callee = group.functions().find(target);
                    if (callee == group.functions().end() || callee->second.graph.empty()) {
                        readiness.unresolvedCalls.push_back({function.entry, instruction, target});
                    } else {
                        readiness.calls.push_back({function.entry, instruction, target});
                    }
                }
            }
        }

        void recordEntryHandler(const AnalyzedImage &analysis, ExecutableReadiness &readiness) {
            for (const auto &function : analysis.functions()) {
                if (function.record.begin != analysis.module().entryPoint || !function.eligible() ||
                    !function.hasUnwindHandler) {
                    continue;
                }

                readiness.entryHandlerUnwindRva = function.record.unwind;
                readiness.entryHandlerRva = function.handlerRva;
                try {
                    readiness.entryCHandler = analysis.cSpecificHandler(function);
                } catch (const InspectionError &error) {
                    readiness.entryHandlerError = error.what();
                }
                return;
            }
        }
    } // namespace

    std::optional<uint32_t> crtDataExport(const Import &descriptor, const Symbol &symbol) {
        if (descriptor.normalizedName != "msvcrt.dll" || symbol.ordinal || descriptor.delayed ||
            descriptor.bound) {
            return {};
        }
        static constexpr std::pair<std::string_view, uint32_t> cells[] = {
            {"_acmdln", FORGE_RT_CRT_ACMDLN},
            {"__initenv", FORGE_RT_CRT_INITENV},
            {"_fmode", FORGE_RT_CRT_FMODE},
            {"_commode", FORGE_RT_CRT_COMMODE}};
        for (const auto &[name, kind] : cells) {
            if (name == symbol.name) {
                return kind;
            }
        }
        return {};
    }

    void recordExecutableRequirements(const AnalyzedImage &analysis,
                                      ExecutableReadiness &readiness) {
        readiness.tls = analysis.module().tls;
        recordEntryHandler(analysis, readiness);

        // Preserve the original failure ordering and call-site provenance if the parsed
        // image has competing failures. Executable admission still checks every import.
        try {
            for (const auto &descriptor : analysis.image().importBindings().entries()) {
                ExecutableImportDirectory directory{descriptor.name,
                                                    descriptor.descriptorRva,
                                                    descriptor.delayed,
                                                    descriptor.bound,
                                                    {}};
                for (size_t i = 0; i < descriptor.symbols.size(); ++i) {
                    const auto &symbol = descriptor.symbols[i];
                    const auto slot =
                        descriptor.addressTableRva + static_cast<uint32_t>(i * importSlotWidth);
                    directory.slots.push_back(
                        {importName(symbol), slot,
                         findService(win64::services, descriptor, symbol) != nullptr,
                         crtDataExport(descriptor, symbol).has_value()});
                }
                readiness.loadImports.push_back(std::move(directory));
            }
        } catch (const InspectionError &error) {
            readiness.importInventoryError = error.what();
        }
    }

    void recordExecutableRecovery(ExecutableReadiness &readiness,
                                  const RecoveredFunctionGroup &group,
                                  const InspectionError *failure) {
        readiness.recoveryComplete = !failure;
        const auto failed = failure ? failedCall(group, failure->context) : std::nullopt;

        if (failed) {
            readiness.unresolvedCalls.push_back(*failed);
        }

        for (const auto &[rva, function] : group.functions()) {
            recordCallTargets(readiness, group, function, failed);
        }

        for (const auto &[dll, name] : group.requiredImports()) {
            readiness.imports.push_back({std::string(dll), std::string(name)});
        }

        if (!failure) {
            return;
        }

        const auto &context = failure->context;

        if (!context.importDll.empty() && !context.importSymbol.empty()) {
            recordImport(readiness, llvm::StringRef(context.importDll).lower(),
                         context.importSymbol);
        }
    }

    namespace {
        void validateEagerImport(const Import &descriptor, size_t index,
                                 const RelocationIndex &relocations,
                                 llvm::ArrayRef<RvaRange> writes, ExecutableReadiness &readiness) {
            const auto &symbol = descriptor.symbols[index];
            const auto name = importName(symbol);
            recordImport(readiness, descriptor.normalizedName, name);

            // Both table extents were checked while building the descriptor.
            const auto offset = static_cast<uint32_t>(index * importSlotWidth);
            const auto slot = descriptor.addressTableRva + offset;
            const auto lookup =
                descriptor.lookupRva ? descriptor.lookupRva : descriptor.addressTableRva;
            const ImportSlot imported{descriptor, symbol, lookup + offset};
            llvm::StringRef reason = "unsupported eager import ";

            if (findService(win64::services, descriptor, symbol) ||
                crtDataExport(descriptor, symbol)) {
                if (!imported.unstableIdentityRva(relocations, writes)) {
                    return;
                }

                reason = "unstable eager import identity for ";
            }

            InspectionError error(
                (reason + descriptor.name + "!" + name + " at IAT slot " + hex(slot)).str(),
                FailureCode::ExecutableStartup);
            error.context.importDll = descriptor.name;
            error.context.importSymbol = name;
            error.context.importSlot = slot;
            throw error;
        }

        // The Windows loader must resolve eager imports even if the recovered group never
        // calls them. Only the production catalogue can satisfy them in a standalone image.
        void validateEagerImports(const ValidatedEntry &entry, llvm::ArrayRef<RvaRange> writes,
                                  ExecutableReadiness &readiness) {
            const auto &bindings = entry.analysis.image().importBindings();

            for (const auto &descriptor : bindings.entries()) {
                if (descriptor.delayed || descriptor.bound || descriptor.symbols.empty()) {
                    InspectionError error(
                        "unsupported delayed, bound or empty import descriptor for " +
                            descriptor.name,
                        FailureCode::ExecutableStartup);
                    error.context.importDll = descriptor.name;
                    throw error;
                }

                for (size_t i = 0; i < descriptor.symbols.size(); ++i) {
                    validateEagerImport(descriptor, i, entry.relocations, writes, readiness);
                }
            }
        }

        void validateReachableHandlers(const AnalyzedImage &analysis,
                                       const RecoveredFunctionGroup &group,
                                       const ExecutableReadiness &readiness) {
            for (const auto &function : analysis.functions()) {
                if (!function.eligible() || !function.hasUnwindHandler ||
                    !group.functions().contains(function.record.begin)) {
                    continue;
                }

                const auto handler = function.record.begin == analysis.module().entryPoint
                                         ? readiness.entryCHandler
                                         : analysis.cSpecificHandler(function);
                auto reason = "reachable function at RVA " + hex(function.record.begin);
                if (handler) {
                    reason += " declares " + handler->dll +
                              "!__C_specific_handler with scope table at " +
                              hex(handler->tableRva) + ": " + handler->limitation;
                } else {
                    reason += " declares an unsupported exception or termination handler";
                }

                InspectionError error(reason,
                                      handler ? handler->failure : FailureCode::ExecutableStartup);
                error.context.functionRva = function.record.begin;
                throw error;
            }
        }
    } // namespace

    void validateExecutableStartup(const ValidatedEntry &entry, const RecoveredFunctionGroup &group,
                                   uint64_t guestBase, ExecutableReadiness &readiness) {
        const auto &image = entry.analysis.image();
        image.validateExecutableLayout(guestBase);

        // A standalone artifact publishes the original header bytes even at a relocated base.
        const RvaRange headers{0, image.headerBytes().size()};

        if (const auto *relocation = entry.relocations.firstOverlap(headers)) {
            throw InspectionError("unsupported relocation in PE headers at RVA " +
                                      hex(relocation->rva),
                                  FailureCode::ExecutableStartup);
        }

        const auto writes = image.loaderWrittenRanges();
        const auto headerWrites = rangesIn(writes, headers);

        if (!headerWrites.empty()) {
            throw InspectionError("unsupported loader write in PE headers at RVA " +
                                      hex(headerWrites.front().begin),
                                  FailureCode::ExecutableStartup);
        }

        validateReachableHandlers(entry.analysis, group, readiness);
        validateEagerImports(entry, writes, readiness);
    }
} // namespace forge::x86
