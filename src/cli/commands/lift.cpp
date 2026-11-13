#include "cli/commands/lift.h"
#include "cli/parsing.h"

#include "llvm/Support/raw_ostream.h"

#include <charconv>
#include <string_view>

namespace forge::cli {
    namespace {
        uint32_t parseRva(std::string_view value) {
            int base = 10;

            if (value.starts_with("0x") || value.starts_with("0X")) {
                value.remove_prefix(2);
                base = 16;
            }

            uint32_t rva;
            const auto [end, ec] =
                std::from_chars(value.data(), value.data() + value.size(), rva, base);

            if (ec != std::errc{} || end != value.data() + value.size()) {
                throw std::invalid_argument("expected a 32-bit decimal or hexadecimal RVA");
            }

            return rva;
        }
    } // namespace

    void registerLift(CLI::App &app, LiftOptions &options, int &status) {
        auto *command = app.add_subcommand("lift", "Lift a discovered function to LLVM IR.");
        addInput(*command, "exe", options.input);
        command
            ->add_option_function<std::string>(
                "--rva",
                [&options](const std::string &value) {
                    options.request.startRva = parseRva(value);
                },
                "Function start as a decimal or hexadecimal RVA.")
            ->type_name("RVA")
            ->required()
            ->trigger_on_parse();
        command
            ->add_option<std::filesystem::path, std::string>("--output", options.output,
                                                             "Destination LLVM IR file.")
            ->type_name("FILE")
            ->required()
            ->trigger_on_parse();
        command
            ->add_option_function<std::string>(
                "--signature",
                [&options](const std::string &) {
                    options.request.mode = EntryMode::WindowsX64I64Pair;
                },
                "Wrap the function with this signature (default: register state).")
            ->check(CLI::IsMember({"i64(i64,i64)"}))
            ->trigger_on_parse();
        addFormat(*command, "--diagnostics-format", options.jsonDiagnostics,
                  "Execution diagnostic format (default: text).");
        command->final_callback(
            [&options, &status] { status = executeLift(options, llvm::errs()); });
    }
} // namespace forge::cli
