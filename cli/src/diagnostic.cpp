#include "diagnostic.h"
#include "lift/lift.h"
#include "pe/image.h"
#include "report.h"
#include "tls_report.h"

#include "llvm/Support/JSON.h"

#include <utility>

namespace forge {
    void printFailure(const InspectionError &error, const fs::path &input, llvm::raw_ostream &err) {
        const auto prefix = failureKind(error.kind).legacy;

        if (prefix != "forge") {
            err << input.string() << ": ";
        }

        err << prefix << ": " << error.what();

        const auto callee = error.context.functionRva;
        const auto site = error.context.sourceCall;
        if (site && error.context.initializerTargetRva) {
            err << " (initializer " << hex(*error.context.initializerTargetRva) << " from call at "
                << hex(site->instruction) << " in " << hex(site->caller) << ")";
        } else if (site && error.context.terminationTargetRva) {
            err << " (termination callback " << hex(*error.context.terminationTargetRva)
                << " from registration at " << hex(site->instruction) << " in " << hex(site->caller)
                << ")";
        } else if (site && callee && error.context.branchTarget == site->caller &&
                   error.context.importSlot) {
            err << " (function " << hex(*callee) << " calls " << hex(site->caller) << ", import "
                << error.context.importDll << "!" << error.context.importSymbol << " at "
                << hex(site->instruction) << ")";
        } else if (site && callee) {
            err << " (function " << hex(*callee) << " reached from call at "
                << hex(site->instruction) << " in " << hex(site->caller) << ")";
        }

        err << '\n';
    }

    namespace {
        llvm::json::Object failureFields(const FailureContext &context, const fs::path &input) {
            const auto &source = context.input.empty() ? input : context.input;
            llvm::json::Object fields{{"input", llvm::json::fixUTF8(source.native())}};

            if (context.blockRva) {
                fields["block_rva"] = hex(*context.blockRva);
            }

            if (context.functionRva) {
                fields["function_rva"] = hex(*context.functionRva);
            }

            if (const auto site = context.sourceCall) {
                fields["caller_rva"] = hex(site->caller);
                fields["call_site_rva"] = hex(site->instruction);
            }

            if (context.initializerTargetRva) {
                fields["initializer_target_rva"] = hex(*context.initializerTargetRva);
            }

            if (context.terminationTargetRva) {
                fields["termination_target_rva"] = hex(*context.terminationTargetRva);
            }

            if (context.branchTarget) {
                fields["branch_target"] = *context.branchTarget;
            }

            if (context.importSlot) {
                fields["iat_slot_rva"] = hex(*context.importSlot);
            }

            if (context.importOwnership) {
                fields["import_descriptor_rva"] = hex(context.importOwnership->descriptorRva);
                fields["import_ownership_reason"] = context.importOwnership->reason;
            }

            if (!context.importDll.empty()) {
                fields["import_dll"] = context.importDll;
            }

            if (!context.importSymbol.empty()) {
                fields["import_symbol"] = context.importSymbol;
            }

            if (!context.output.empty()) {
                fields["output"] = llvm::json::fixUTF8(context.output.native());
            }

            if (context.endRva) {
                fields["end_rva"] = hex(*context.endRva);
            }

            if (context.instructionRva) {
                fields["instruction_rva"] = hex(*context.instructionRva);
            }

            if (context.fileOffset) {
                fields["file_offset"] = *context.fileOffset;
            }

            if (!context.architecture.empty()) {
                fields["architecture"] = llvm::json::fixUTF8(context.architecture);
            }

            if (!context.opcode.empty()) {
                fields["opcode"] = context.opcode;
            }

            if (!context.bytes.empty()) {
                fields["bytes"] = context.bytes;
            }

            return fields;
        }

        void writeFailure(const InspectionError &error, llvm::json::Object fields,
                          llvm::raw_ostream &out) {
            const auto &kind = failureKind(error.kind);
            out << llvm::json::Value(
                       llvm::json::Object{{"schema_version", 1},
                                          {"stage", kind.stage},
                                          {"category", kind.category},
                                          {"code", kind.code},
                                          {"message", llvm::json::fixUTF8(error.what())},
                                          {"context", std::move(fields)}})
                << '\n';
        }

        llvm::json::Object cSpecificHandlerJson(const CSpecificHandler &handler) {
            llvm::json::Object fields{{"dll", llvm::json::fixUTF8(handler.dll)},
                                      {"symbol", "__C_specific_handler"},
                                      {"iat_slot_rva", hex(handler.iatSlotRva)},
                                      {"scope_table_rva", hex(handler.tableRva)},
                                      {"limitation", handler.limitation}};
            if (handler.count) {
                fields["scope_count"] = *handler.count;
            }

            if (handler.scope) {
                const auto &scope = *handler.scope;
                fields["scope"] = llvm::json::Object{{"begin_rva", hex(scope.beginRva)},
                                                     {"end_rva", hex(scope.endRva)},
                                                     {"filter_rva", hex(scope.filterRva)},
                                                     {"continuation_rva", hex(scope.jumpRva)}};
            }

            return fields;
        }

        void addLoaderFields(llvm::json::Object &fields, const ExecutableReadiness &readiness) {
            if (readiness.tls) {
                auto tls = tlsJson(*readiness.tls);
                tls["limitation"] = "PE TLS initialization and loader callbacks are unsupported";
                fields["tls"] = std::move(tls);
            }

            if (readiness.entryHandlerUnwindRva) {
                llvm::json::Object handler{{"unwind_rva", hex(*readiness.entryHandlerUnwindRva)}};
                if (readiness.entryHandlerRva) {
                    handler["handler_rva"] = hex(*readiness.entryHandlerRva);
                }
                if (readiness.entryCHandler) {
                    handler["c_specific_handler"] = cSpecificHandlerJson(*readiness.entryCHandler);
                } else if (!readiness.entryHandlerError.empty()) {
                    handler["analysis_error"] = llvm::json::fixUTF8(readiness.entryHandlerError);
                }
                fields["entry_unwind_handler"] = std::move(handler);
            }

            if (!readiness.importInventoryError.empty()) {
                fields["load_imports_error"] = llvm::json::fixUTF8(readiness.importInventoryError);
                return;
            }

            llvm::json::Array directories;
            for (const auto &directory : readiness.loadImports) {
                llvm::json::Array slots;
                for (const auto &slot : directory.slots) {
                    slots.emplace_back(
                        llvm::json::Object{{"name", llvm::json::fixUTF8(slot.name)},
                                           {"iat_slot_rva", hex(slot.iatRva)},
                                           {"catalogued_service", slot.hasService},
                                           {"catalogued_data_export", slot.hasDataExport}});
                }
                directories.emplace_back(
                    llvm::json::Object{{"dll", llvm::json::fixUTF8(directory.dll)},
                                       {"descriptor_rva", hex(directory.descriptorRva)},
                                       {"delayed", directory.delayed},
                                       {"bound", directory.bound},
                                       {"symbols", std::move(slots)}});
            }
            fields["load_imports"] = std::move(directories);
        }

        void addReadinessFields(llvm::json::Object &fields, const ExecutableReadiness &readiness) {
            if (!readiness.architecture.empty()) {
                fields["architecture"] = readiness.architecture;
            }

            if (readiness.entryRva) {
                fields["entry_rva"] = hex(*readiness.entryRva);
                addLoaderFields(fields, readiness);
            }

            fields["entry_recovered"] = readiness.entryRecovered;
            fields["recovery_complete"] = readiness.recoveryComplete;
            llvm::json::Array calls, imports, unresolved;

            for (const auto &call : readiness.calls) {
                calls.emplace_back(llvm::json::Object{{"caller_rva", hex(call.callerRva)},
                                                      {"instruction_rva", hex(call.instructionRva)},
                                                      {"target_rva", hex(call.targetRva)}});
            }

            for (const auto &service : readiness.imports) {
                imports.emplace_back(
                    llvm::json::Object{{"dll", service.dll}, {"name", service.name}});
            }

            for (const auto &site : readiness.unresolvedCalls) {
                llvm::json::Object call{{"caller_rva", hex(site.callerRva)},
                                        {"instruction_rva", hex(site.instructionRva)}};

                if (site.targetRva && std::in_range<uint32_t>(*site.targetRva)) {
                    call["target_rva"] = hex(static_cast<uint32_t>(*site.targetRva));
                } else if (site.targetRva) {
                    call["branch_target"] = *site.targetRva;
                }

                unresolved.emplace_back(std::move(call));
            }

            fields["calls"] = std::move(calls);
            fields["imports"] = std::move(imports);
            fields["unresolved_calls"] = std::move(unresolved);

            if (!readiness.initializerTables.empty()) {
                llvm::json::Array tables;
                for (const auto &table : readiness.initializerTables) {
                    llvm::json::Array targets;
                    for (const auto rva : table.initialTargetRvas) {
                        targets.emplace_back(hex(rva));
                    }
                    tables.emplace_back(
                        llvm::json::Object{{"caller_rva", hex(table.callerRva)},
                                           {"instruction_rva", hex(table.instructionRva)},
                                           {"first_rva", hex(table.firstRva)},
                                           {"last_rva", hex(table.lastRva)},
                                           {"initial_target_rvas", std::move(targets)}});
                }
                fields["initializer_tables"] = std::move(tables);
            }
        }

        void printEntryHandler(const ExecutableReadiness &readiness, llvm::raw_ostream &out) {
            if (!readiness.entryHandlerUnwindRva) {
                return;
            }

            out << "  entry declares exception or termination handler, unwind RVA "
                << hex(*readiness.entryHandlerUnwindRva);
            if (readiness.entryHandlerRva) {
                out << ", handler RVA " << hex(*readiness.entryHandlerRva);
            }
            out << '\n';

            if (!readiness.entryHandlerError.empty()) {
                out << "    " << readiness.entryHandlerError << '\n';
            }

            if (readiness.entryCHandler) {
                const auto &handler = *readiness.entryCHandler;
                out << "    " << handler.dll << "!__C_specific_handler, IAT slot "
                    << hex(handler.iatSlotRva) << ", scope table " << hex(handler.tableRva) << '\n';
                if (handler.scope) {
                    const auto &scope = *handler.scope;
                    out << "    protected [" << hex(scope.beginRva) << ", " << hex(scope.endRva)
                        << "), filter " << hex(scope.filterRva) << ", continuation "
                        << hex(scope.jumpRva) << '\n';
                }
                out << "    " << handler.limitation << '\n';
            }
        }

        void printLoaderRequirements(const ExecutableReadiness &readiness, llvm::raw_ostream &out) {
            if (readiness.tls) {
                const auto &tls = *readiness.tls;
                out << "  TLS directory " << hex(tls.rva) << ", index VA " << hex(tls.index)
                    << ", template " << (tls.end - tls.start) << " bytes + " << tls.zeroFill
                    << " zero-filled bytes (PE TLS initialization and loader callbacks are "
                       "unsupported)\n";
                for (const auto va : tls.callbackVas) {
                    out << "    callback VA " << hex(va) << '\n';
                }
            }

            printEntryHandler(readiness, out);

            if (!readiness.importInventoryError.empty()) {
                out << "  import inventory unavailable: " << readiness.importInventoryError << '\n';
            }
            for (const auto &directory : readiness.loadImports) {
                out << "  " << (directory.delayed ? "delay" : "eager") << " imports from "
                    << directory.dll << (directory.bound ? " (bound)" : "") << '\n';
                for (const auto &slot : directory.slots) {
                    llvm::StringRef provider = "unavailable";
                    if (slot.hasService) {
                        provider = "catalogued service";
                    } else if (slot.hasDataExport) {
                        provider = "process-owned data";
                    }
                    out << "    " << hex(slot.iatRva) << " " << slot.name << " (" << provider
                        << ")\n";
                }
            }
        }
    } // namespace

    void printLiftDiagnostic(const InspectionError &error, const fs::path &input,
                             LiftRequest request, llvm::raw_ostream &out) {
        auto fields = failureFields(error.context, input);
        fields["entry_rva"] = hex(error.context.entryRva.value_or(request.startRva));
        fields["signature"] =
            request.mode == EntryMode::RegisterState ? "register-state" : "i64(i64,i64)";
        writeFailure(error, std::move(fields), out);
    }

    void printExecutableDiagnostic(const ExecutableReadiness &readiness, const fs::path &input,
                                   const fs::path &output, const InspectionError *failure,
                                   bool json, llvm::raw_ostream &out) {
        if (json) {
            auto fields = failure
                              ? failureFields(failure->context, input)
                              : llvm::json::Object{{"input", llvm::json::fixUTF8(input.native())}};
            fields["output"] = llvm::json::fixUTF8(output.native());
            addReadinessFields(fields, readiness);

            if (failure) {
                writeFailure(*failure, std::move(fields), out);
            } else {
                out << llvm::json::Value(llvm::json::Object{
                           {"schema_version", 1},
                           {"stage", "publication"},
                           {"category", "success"},
                           {"code", "EXECUTABLE_READY"},
                           {"message", "Published native ARM64 Mach-O executable"},
                           {"context", std::move(fields)}})
                    << '\n';
            }

            return;
        }

        if (failure) {
            printFailure(*failure, input, out);
            printLoaderRequirements(readiness, out);
        }

        if (readiness.entryRva) {
            out << input.string() << ": " << readiness.architecture << " PE entry "
                << hex(*readiness.entryRva)
                << (readiness.entryRecovered ? " recovered" : " unrecovered") << ", "
                << (readiness.recoveryComplete ? "complete" : "partial") << " call recovery"
                << ", " << readiness.calls.size() << " guest calls, " << readiness.imports.size()
                << " imported services\n";
        }

        for (const auto &call : readiness.calls) {
            out << "  " << hex(call.callerRva) << " calls " << hex(call.targetRva) << " at "
                << hex(call.instructionRva) << '\n';
        }

        for (const auto &table : readiness.initializerTables) {
            out << "  initializer table [" << hex(table.firstRva) << ", " << hex(table.lastRva)
                << ") at call " << hex(table.instructionRva) << " in " << hex(table.callerRva)
                << " with " << table.initialTargetRvas.size() << " distinct initial targets\n";
        }

        for (const auto &service : readiness.imports) {
            out << "  requires " << service.dll << '!' << service.name << '\n';
        }

        for (const auto &call : readiness.unresolvedCalls) {
            out << "  unresolved call at " << hex(call.instructionRva) << " in "
                << hex(call.callerRva);

            if (call.targetRva && std::in_range<uint32_t>(*call.targetRva)) {
                out << " to " << hex(static_cast<uint32_t>(*call.targetRva));
            } else if (call.targetRva) {
                out << " to out-of-range target " << *call.targetRva;
            }

            out << '\n';
        }
    }
} // namespace forge
