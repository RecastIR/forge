#include "diagnostic.h"
#include "lift/lift.h"
#include "pe/image.h"
#include "report.h"

#include "llvm/Support/JSON.h"

namespace forge {
    void printFailure(const InspectionError &error, const fs::path &input, llvm::raw_ostream &err) {
        const auto prefix = failureKind(error.kind).legacy;

        if (prefix != "forge") {
            err << input.string() << ": ";
        }

        err << prefix << ": " << error.what();

        const auto callee = error.context.functionRva;
        if (const auto site = error.context.sourceCall; site && callee) {
            err << " (leaf " << hex(*callee) << " called at " << hex(site->instruction) << " in "
                << hex(site->caller) << ")";
        }

        err << '\n';
    }

    void printLiftDiagnostic(const InspectionError &error, const fs::path &input,
                             LiftRequest request, llvm::raw_ostream &out) {
        const auto &kind = failureKind(error.kind);
        const auto &context = error.context;
        // Loading and publication can fail before the core operation sees the requested RVA.
        const auto &source = context.input.empty() ? input : context.input;
        llvm::json::Object fields{{"input", llvm::json::fixUTF8(source.native())},
                                  {"entry_rva", hex(context.entryRva.value_or(request.startRva))}};

        fields["signature"] =
            request.mode == EntryMode::RegisterState ? "register-state" : "i64(i64,i64)";
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

        if (context.branchTarget) {
            fields["branch_target"] = *context.branchTarget;
        }

        if (context.importSlot) {
            fields["iat_slot_rva"] = hex(*context.importSlot);
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

        out << llvm::json::Value(llvm::json::Object{{"schema_version", 1},
                                                    {"stage", kind.stage},
                                                    {"category", kind.category},
                                                    {"code", kind.code},
                                                    {"message", llvm::json::fixUTF8(error.what())},
                                                    {"context", std::move(fields)}})
            << '\n';
    }
} // namespace forge
