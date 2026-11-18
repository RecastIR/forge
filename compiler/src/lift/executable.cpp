#include "lift/executable.h"

#include "analysis/analysis.h"

#include <tuple>

namespace forge::x86 {
    namespace {
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
                return ExecutableUnresolvedCall{source.caller, source.instruction,
                                                call.guest().rva};
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
                if (call.external() || (failed && failed->callerRva == function.entry &&
                                        failed->instructionRva == instruction)) {
                    continue;
                }

                const auto target = call.guest().rva;
                const auto callee = group.functions().find(target);

                if (callee == group.functions().end() || callee->second.graph.empty()) {
                    readiness.unresolvedCalls.push_back({function.entry, instruction, target});
                } else {
                    readiness.calls.push_back({function.entry, instruction, target});
                }
            }
        }
    } // namespace

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
            const auto name = symbol.ordinal ? "#" + std::to_string(*symbol.ordinal) : symbol.name;
            recordImport(readiness, descriptor.normalizedName, name);

            // Both table extents were checked while building the descriptor.
            const auto offset = static_cast<uint32_t>(index * importSlotWidth);
            const auto slot = descriptor.addressTableRva + offset;
            const auto lookup =
                descriptor.lookupRva ? descriptor.lookupRva : descriptor.addressTableRva;
            const ImportSlot imported{descriptor, symbol, lookup + offset};
            llvm::StringRef reason = "unsupported eager import ";

            if (findService(win64::services, descriptor, symbol)) {
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

        for (const auto &function : entry.analysis.functions()) {
            if (function.eligible() && function.hasUnwindHandler &&
                group.functions().contains(function.record.begin)) {
                InspectionError error(
                    "reachable function at RVA " + hex(function.record.begin) +
                        " declares an unsupported exception or termination handler",
                    FailureCode::ExecutableStartup);
                error.context.functionRva = function.record.begin;
                throw error;
            }
        }

        validateEagerImports(entry, writes, readiness);
    }
} // namespace forge::x86
