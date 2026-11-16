#include "report.h"

#include "analysis/analysis.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"

namespace forge {
    using namespace llvm;

    namespace {
        StringRef status(const FunctionRange &f) {
            if (f.defect) {
                return "invalid";
            }

            if (f.overlapGroup) {
                return "conflicting";
            }

            if (f.unsupportedUnwindVersion) {
                return "unsupported";
            }

            return "valid";
        }
    } // namespace

    void printAnalysis(const AnalyzedImage &a, bool jsonFormat, raw_ostream &out) {
        if (!jsonFormat) {
            out << "Functions (" << a.functions().size() << "), source: PE exception directory\n";

            for (const auto &f : a.functions()) {
                const auto &r = f.record;

                out << "  " << hex(r.begin) << ".." << hex(r.end);

                if (r.end >= r.begin) {
                    out << " (" << r.end - r.begin << " bytes)";
                }

                out << " unwind " << hex(r.unwind) << " " << status(f) << " records";

                for (auto index : f.indices) {
                    out << " " << index;
                }

                if (f.entry) {
                    out << " entry";
                }

                if (f.callback) {
                    out << " TLS callback";
                }

                if (f.chainedFragment) {
                    out << " chained fragment";
                }

                if (f.unsupportedUnwindVersion) {
                    out << " unwind version " << *f.unsupportedUnwindVersion;
                }

                if (!f.name.empty()) {
                    out << " " << f.name;
                }

                if (f.line) {
                    out << " " << f.file << ":" << f.line;
                }

                out << "\n";
            }

            for (auto [begin, end] : a.unknownRanges()) {
                out << "  Unknown executable range " << hex(begin) << ".." << hex(end) << "\n";
            }

            return;
        }

        json::Array functions, unknown, diagnostics;

        for (const auto &f : a.functions()) {
            const auto &r = f.record;

            json::Object o{{"start_rva", hex(r.begin)},
                           {"end_rva", hex(r.end)},
                           {"unwind_rva", hex(r.unwind)},
                           {"source", "exception_directory"},
                           {"record_indices", json::Array(f.indices)},
                           {"status", status(f)},
                           {"liftable", f.eligible()},
                           {"contains_entry_point", f.entry},
                           {"contains_tls_callback", f.callback},
                           {"size", nullptr}};

            if (r.end >= r.begin) {
                o["size"] = r.end - r.begin;
            }

            if (f.overlapGroup) {
                o["overlap_diagnostic"] = *f.overlapGroup;
            }

            if (f.chainedFragment) {
                o["chained_fragment"] = true;
            }

            if (f.unsupportedUnwindVersion) {
                o["unwind_version"] = *f.unsupportedUnwindVersion;
            }

            if (!f.name.empty()) {
                o["name"] = f.name;
            }

            if (f.line) {
                o["location"] = json::Object{{"file", f.file}, {"line", f.line}};
            }

            functions.push_back(std::move(o));
        }

        for (auto [begin, end] : a.unknownRanges()) {
            unknown.push_back(json::Object{{"start_rva", hex(begin)}, {"end_rva", hex(end)}});
        }

        for (const auto &d : a.findings()) {
            diagnostics.push_back(json::Object{{"code", d.code},
                                               {"severity", "warning"},
                                               {"message", d.message},
                                               {"record_indices", json::Array(d.records)}});
        }

        out << formatv("{0:2}\n",
                       json::Value(json::Object{{"schema_version", 1},
                                                {"functions", std::move(functions)},
                                                {"unknown_executable_ranges", std::move(unknown)},
                                                {"diagnostics", std::move(diagnostics)}}));
    }

    void printFindings(const AnalyzedImage &analysis, const fs::path &input, raw_ostream &err) {
        for (const auto &finding : analysis.findings()) {
            err << input.string() << ": " << finding.code << ": " << finding.message << " (records";

            for (auto index : finding.records) {
                err << " " << index;
            }

            err << ")\n";
        }
    }
} // namespace forge
