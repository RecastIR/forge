#pragma once

#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <filesystem>

namespace forge {
    class AnalyzedImage;
    struct InspectionError;
    struct Report;
    struct LiftRequest;

    struct ReportOptions {
        bool json = false, strict = false;
    };

    void printReport(const Report &report, bool json, bool verbose, llvm::raw_ostream &out);
    void printDiagnostics(const Report &report, llvm::raw_ostream &err);
    void printAnalysis(const AnalyzedImage &analysis, bool json, llvm::raw_ostream &out);
    void printFindings(const AnalyzedImage &analysis, const std::filesystem::path &input,
                       llvm::raw_ostream &err);
    void printFailure(const InspectionError &error, const std::filesystem::path &input,
                      llvm::raw_ostream &err);
    void printLiftDiagnostic(const InspectionError &error, const std::filesystem::path &input,
                             LiftRequest request, llvm::raw_ostream &out);
} // namespace forge
