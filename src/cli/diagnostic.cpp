#include "diagnostic.h"
#include "cli/report.h"
#include "pe/image.h"

#include "llvm/Support/JSON.h"

namespace forge {
    void printLiftDiagnostic(const InspectionError &error, const fs::path &input, uint32_t entryRva,
                             llvm::raw_ostream &out) {
        const auto &kind = failureKind(error.kind);
        const auto &context = error.context;
        // Loading and publication can fail before the core operation sees the requested RVA.
        const auto &source = context.input.empty() ? input : context.input;
        llvm::json::Object fields{{"input", llvm::json::fixUTF8(source.native())},
                                  {"entry_rva", hex(context.entryRva.value_or(entryRva))}};

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
