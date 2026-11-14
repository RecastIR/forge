#include "cli/parsing.h"

#include <algorithm>
#include <optional>
#include <string_view>

namespace forge::cli {
    namespace {
        std::string literalArgument(std::string arg) {
            // CLI11 decodes doubled brackets even in scalar arguments. Escape bracketed
            // argv strings with its matching encoder to keep file names byte-for-byte.
            CLI::detail::handle_secondary_array(arg);
            return arg;
        }
    } // namespace

    void addInput(CLI::App &command, const char *name, std::filesystem::path &input) {
        command.add_option<std::filesystem::path, std::string>(name, input, "Input PE image.")
            ->required();
    }

    void addFormat(CLI::App &command, const char *name, bool &json, const char *description) {
        command
            .add_option_function<std::string>(
                name, [&json](const std::string &format) { json = format == "json"; }, description)
            ->check(CLI::IsMember({"text", "json"}))
            ->trigger_on_parse();
    }

    void addReportOptions(CLI::App &command, ReportOptions &options) {
        addFormat(command, "--format", options.json, "Report format (default: text).");
        command.add_flag("--strict", options.strict, "Return exit 3 on strict findings.");
    }

    std::vector<std::string> cliArguments(const CLI::App &app, int argc, char **argv) {
        if (argc < 2) {
            return {};
        }

        const std::string name(argv[1]);

        if (app.get_help_ptr()->check_name(name)) {
            return {name};
        }

        const auto *command = app.get_subcommand_no_throw(name);

        if (!command) {
            throw CLI::ExtrasError({name});
        }

        // CLI11 splits attached values and treats ++ as a subcommand terminator.
        // Check the original option spelling and pass the input literally after --.
        std::vector<std::string> args{name};
        std::optional<std::string> input;
        bool literal = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg(argv[i]);

            if (!literal && arg == "--") {
                literal = true;
                continue;
            }

            const bool positional = literal || !arg.starts_with('-');

            if (positional && input) {
                throw CLI::ExtrasError({arg});
            }

            if (positional) {
                input = std::move(arg);
                continue;
            }

            const auto *option = command->get_option_no_throw(arg);

            if (!option) {
                throw CLI::ExtrasError({arg});
            }

            args.push_back(arg);

            if (option == command->get_help_ptr()) {
                break;
            }

            if (option->get_items_expected_max() == 0) {
                continue;
            }

            ++i;

            if (i == argc || !*argv[i] || std::string_view(argv[i]).starts_with("--")) {
                throw CLI::ValidationError(arg, "requires a value");
            }

            args.push_back(literalArgument(argv[i]));
        }

        if (input && !input->empty()) {
            args.emplace_back("--");
            args.push_back(literalArgument(std::move(*input)));
        }

        // CLI11 expects its vector of arguments in reverse order.
        std::reverse(args.begin(), args.end());
        return args;
    }
} // namespace forge::cli
