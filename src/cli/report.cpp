#include "cli/report.h"
#include "pe/dependencies.h"

#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Unicode.h"

#include <algorithm>
#include <map>

namespace forge {
    namespace {
        using namespace llvm;
        using json::Array;
        using json::Object;
        using json::Value;

        std::string pathText(const fs::path &p) { return json::fixUTF8(p.native()); }

        const char *loadType(const Import &i) { return i.delayed ? "delay" : "direct"; }

        template <typename T, typename F> Array array(const std::vector<T> &values, F convert) {
            Array result;
            result.reserve(values.size());

            for (const auto &v : values) {
                result.push_back(convert(v));
            }

            return result;
        }

        Object importJson(const Import &i) {
            return Object{{"name", i.name},
                          {"normalized_name", i.normalizedName},
                          {"load_type", loadType(i)},
                          {"symbols", array(i.symbols, [](const Symbol &s) {
                               return s.ordinal ? Object{{"ordinal", *s.ordinal}}
                                                : Object{{"name", s.name}};
                           })}};
        }

        std::string machineText(const Module &module) {
            return module.machine == COFF::IMAGE_FILE_MACHINE_AMD64 ? "AMD64" : hex(module.machine);
        }

        Object moduleJson(const Module &m) {
            Object o{{"path", pathText(m.path)},
                     {"machine", machineText(m)},
                     {"pe_type", "PE32+"},
                     {"image_kind", m.dll ? "dll" : "exe"},
                     {"image_base_va", hex(m.imageBase)},
                     {"entry_point_rva", hex(m.entryPoint)}};
            o["sections"] = array(m.sections, [](const Section &s) {
                return Object{{"name", s.name},
                              {"rva", hex(s.rva)},
                              {"virtual_size", s.virtualSize},
                              {"file_offset", s.fileOffset},
                              {"raw_size", s.rawSize},
                              {"permissions", s.permissions}};
            });
            o["imports"] = array(m.imports, importJson);
            o["exports"] = array(m.exports, [](const Export &e) {
                Object entry{
                    {"ordinal", e.ordinal}, {"rva", hex(e.rva)}, {"names", Array(e.names)}};

                if (e.forwarder) {
                    entry["forwarder"] = *e.forwarder;
                }

                return entry;
            });
            o["relocations"] = array(m.relocations, [](const RelocationBlock &b) {
                return Object{{"page_rva", hex(b.pageRva)},
                              {"size", b.size},
                              {"entries", array(b.entries, [](const Relocation &e) {
                                   Object entry{{"type", e.type}, {"rva", hex(e.rva)}};
                                   if (e.adjustment) {
                                       entry["adjustment"] = *e.adjustment;
                                   }
                                   return entry;
                               })}};
            });
            o["tls"] = nullptr;

            if (m.tls) {
                const auto &t = *m.tls;

                o["tls"] = Object{{"directory_rva", hex(t.rva)},
                                  {"raw_data_start_va", hex(t.start)},
                                  {"raw_data_end_va", hex(t.end)},
                                  {"index_va", hex(t.index)},
                                  {"callbacks_va", hex(t.callbacks)},
                                  {"zero_fill_size", t.zeroFill},
                                  {"characteristics", t.characteristics},
                                  {"callback_vas", array(t.callbackVas, hex)}};
            }
            o["exceptions"] = nullptr;

            if (m.exceptions) {
                const auto &e = *m.exceptions;

                o["exceptions"] =
                    Object{{"directory_rva", hex(e.rva)},
                           {"size", e.size},
                           {"functions", array(e.functions, [](const RuntimeFunction &f) {
                                return Object{{"begin_rva", hex(f.begin)},
                                              {"end_rva", hex(f.end)},
                                              {"unwind_info_rva", hex(f.unwind)}};
                            })}};
            }

            return o;
        }

        Value reportJson(const Report &r) {
            Array edges, diagnostics;
            std::map<std::string, size_t> counts;

            for (const auto &d : r.dependencies) {
                const auto &source = r.locations[d.importerLocation];
                const Import &i = r.modules[source.module].imports[d.importIndex];
                Object edge{{"importer", source.module},
                            {"importer_directory", pathText(source.path.parent_path())},
                            {"import_index", d.importIndex},
                            {"name", i.name},
                            {"normalized_name", i.normalizedName},
                            {"load_type", loadType(i)},
                            {"kind", d.kind},
                            {"required", d.required},
                            {"status", d.status}};

                if (d.targetLocation) {
                    const auto &target = r.locations[*d.targetLocation];
                    edge["target_module"] = target.module;
                    edge["target_directory"] = pathText(target.path.parent_path());
                }

                if (!d.path.empty()) {
                    edge["path"] = pathText(d.path);
                }

                if (!d.searchDirectory.empty()) {
                    edge["search_directory"] = pathText(d.searchDirectory);
                }

                if (!d.searched.empty()) {
                    edge["searched_paths"] = array(d.searched, pathText);
                }

                if (!d.candidates.empty()) {
                    edge["candidates"] = array(d.candidates, pathText);
                }

                if (!d.architecture.empty()) {
                    edge["detected_architecture"] = d.architecture;
                }

                if (!d.code.empty()) {
                    diagnostics.push_back(Object{{"dependency", edges.size()},
                                                 {"code", d.code},
                                                 {"message", json::fixUTF8(d.message)}});
                }

                edges.push_back(std::move(edge));
                ++counts[d.status];
            }

            Object summary;
            for (const auto &[key, count] : counts) {
                summary[key] = count;
            }

            return Object{{"schema_version", 1},
                          {"inspection", Object{{"status", "completed"}, {"root_module", 0}}},
                          {"modules", array(r.modules, moduleJson)},
                          {"dependencies", std::move(edges)},
                          {"diagnostics", std::move(diagnostics)},
                          {"summary", std::move(summary)}};
        }

        void textModule(const Module &m, bool verbose, raw_ostream &out) {
            out << m.path.string() << "  (PE32+ " << machineText(m) << " "
                << (m.dll ? "DLL" : "EXE") << ")\n"
                << "  Image base VA " << hex(m.imageBase) << "  Entry point RVA "
                << hex(m.entryPoint) << "\n";

            auto columns = [](StringRef name) -> unsigned {
                int width = sys::unicode::columnWidthUTF8(name);
                // Section names have already passed the per-image 64 MiB name budget.
                return width < 0 ? static_cast<unsigned>(name.size())
                                 : static_cast<unsigned>(width);
            };

            constexpr StringLiteral heading = "Sections";
            constexpr unsigned headingWidth = heading.size();
            unsigned width = headingWidth;

            for (const auto &s : m.sections) {
                width = std::max(width, columns(s.name));
            }

            out << "    " << heading;
            out.indent(width - headingWidth + 2)
                << formatv("{0,-12}{1,-15}{2,-14}{3,-11}{4}\n", "RVA", "Virtual size",
                           "File offset", "Raw size", "Permissions");

            for (const auto &s : m.sections) {
                out << "    " << s.name;
                out.indent(width - columns(s.name) + 2)
                    << formatv("{0,-12}{1,-15}{2,-14}{3,-11}{4}\n", hex(s.rva), s.virtualSize,
                               s.fileOffset, s.rawSize, s.permissions);
            }

            size_t symbols = 0, relocations = 0;
            for (const auto &i : m.imports) {
                symbols += i.symbols.size();
            }

            for (const auto &b : m.relocations) {
                relocations += b.entries.size();
            }

            out << "  Imports: " << m.imports.size() << " descriptors, " << symbols
                << " symbols; exports: " << m.exports.size() << "\n  Relocations: " << relocations
                << " entries in " << m.relocations.size() << " blocks; exception records: "
                << (m.exceptions ? m.exceptions->functions.size() : 0) << "\n";

            if (m.tls) {
                out << "  TLS directory RVA " << hex(m.tls->rva) << ", "
                    << m.tls->callbackVas.size() << " callbacks\n";
            } else {
                out << "  TLS: absent\n";
            }

            if (!verbose) {
                return;
            }

            for (const auto &i : m.imports) {
                out << "  Import " << i.name << " (" << loadType(i) << ")\n";

                for (const auto &s : i.symbols) {
                    if (s.ordinal) {
                        out << "    ordinal " << *s.ordinal << "\n";
                    } else {
                        out << "    " << s.name << "\n";
                    }
                }
            }

            for (const auto &e : m.exports) {
                out << "  Export ordinal " << e.ordinal << " RVA " << hex(e.rva);

                for (const auto &n : e.names) {
                    out << " " << n;
                }

                if (e.forwarder) {
                    out << " -> " << *e.forwarder;
                }

                out << "\n";
            }

            for (const auto &b : m.relocations) {
                out << "  Relocations at page RVA " << hex(b.pageRva) << " (" << b.size
                    << " bytes)\n";

                for (const auto &e : b.entries) {
                    out << "    RVA " << hex(e.rva) << " type " << e.type;

                    if (e.adjustment) {
                        out << " adjustment " << *e.adjustment;
                    }

                    out << "\n";
                }
            }

            if (m.tls) {
                const auto &t = *m.tls;

                out << "  TLS directory RVA " << hex(t.rva) << ", template VA " << hex(t.start)
                    << ".." << hex(t.end) << ", index VA " << hex(t.index) << ", callbacks VA "
                    << hex(t.callbacks) << ", zero fill " << t.zeroFill << ", characteristics "
                    << hex(t.characteristics) << "\n";

                for (auto cb : t.callbackVas) {
                    out << "    Callback VA " << hex(cb) << "\n";
                }
            }

            if (m.exceptions) {
                const auto &e = *m.exceptions;
                out << "  Exception directory RVA " << hex(e.rva) << " (" << e.size << " bytes)\n";

                for (const auto &f : e.functions) {
                    out << "    Function RVA " << hex(f.begin) << ".." << hex(f.end)
                        << " unwind RVA " << hex(f.unwind) << "\n";
                }
            }
        }
    } // namespace

    void printReport(const Report &report, bool json, bool verbose, llvm::raw_ostream &out) {
        if (json) {
            out << llvm::formatv("{0:2}\n", reportJson(report));
            return;
        }

        for (const auto &m : report.modules) {
            textModule(m, verbose, out);
        }

        out << "Dependencies (" << report.dependencies.size() << ")";
        std::map<std::string, size_t> counts;

        for (const auto &d : report.dependencies) {
            ++counts[d.status];
        }

        for (const auto &[status, count] : counts) {
            out << "  " << status << " " << count;
        }

        out << "\n";
        if (!verbose) {
            return;
        }

        for (const auto &d : report.dependencies) {
            const auto &source = report.locations[d.importerLocation];
            const auto &i = report.modules[source.module].imports[d.importIndex];

            out << "  " << source.path.string() << " -> " << i.name << " (" << loadType(i) << ", "
                << (d.required ? "required" : "optional") << ", " << d.kind << ") " << d.status;

            if (!d.path.empty()) {
                out << " " << d.path.string();
            }

            out << "\n";
            for (const auto &p : d.candidates) {
                out << "    Candidate " << p.string() << "\n";
            }

            for (const auto &p : d.searched) {
                out << "    Searched " << p.string() << "\n";
            }
        }
    }

    void printDiagnostics(const Report &report, llvm::raw_ostream &err) {
        for (const auto &d : report.dependencies) {
            if (d.code.empty()) {
                continue;
            }

            const auto &source = report.locations[d.importerLocation];
            err << source.path.string() << ": " << d.code << ": "
                << report.modules[source.module].imports[d.importIndex].name;

            if (!d.path.empty()) {
                err << " (" << d.path.string() << ")";
            }

            err << ": " << d.message << "\n";
        }
    }
} // namespace forge
