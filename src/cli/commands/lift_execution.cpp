#include "cli/analysis_input.h"
#include "cli/commands/lift.h"
#include "cli/report.h"
#include "output/publication.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

namespace forge::cli {
    int executeLift(const LiftOptions &options, llvm::raw_ostream &err) {
        FailureCode stage = FailureCode::InputInternal;

        try {
            const auto analysis = analyzeInput(options.input, DebugInfo::Omit, stage);
            stage = FailureCode::PublicationInternal;
            (void)checkedOutputDestination(analysis.image(), options.output);

            stage = FailureCode::LiftingInternal;
            llvm::LLVMContext context;
            const auto module = generateIR(analysis, options.request, context);

            stage = FailureCode::PublicationInternal;
            publishIR(*module, analysis.image(), options.output);
            return 0;
        } catch (const InspectionError &error) {
            if (error.kind == FailureCode::OutputAlias) {
                throw std::invalid_argument(error.what());
            }

            if (options.jsonDiagnostics) {
                printLiftDiagnostic(error, options.input, options.request.startRva, err);
            } else {
                printFailure(error, options.input, err);
            }

            return 1;
        } catch (const std::exception &error) {
            if (!options.jsonDiagnostics) {
                throw;
            }

            InspectionError failure(error.what(), stage);

            if (stage == FailureCode::PublicationInternal) {
                failure.context.output = options.output;
            }

            printLiftDiagnostic(failure, options.input, options.request.startRva, err);
            return 1;
        }
    }
} // namespace forge::cli
