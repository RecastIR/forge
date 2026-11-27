#include "format.h"

#include <algorithm>
#include <charconv>
#include <string_view>

namespace forge::runtime {
    namespace {
        using namespace win64;
        constexpr auto unsupported = FORGE_RT_UNSUPPORTED_CRT_FORMAT;
        using Part = FormattedOutput::Part;
        using Slots = GuestBuffer<crtVfprintf.arguments[2]>;

        // Read only through the first NUL, even next to an unmapped page or a return slot.
        template <Argument argument>
        forge_rt_status copyString(const GuestBuffer<argument> &input, std::span<char> output,
                                   size_t &length) {
            for (size_t i = 0; i < argument.size; ++i) {
                uint8_t byte;
                const auto status = input.readScalar(i, byte);

                if (status != FORGE_RT_OK) {
                    return status;
                }

                if (!byte) {
                    length = i;
                    return FORGE_RT_OK;
                }

                if (i == output.size()) {
                    return unsupported;
                }

                output[i] = static_cast<char>(byte);
            }

            return unsupported;
        }

        struct Conversion {
            size_t begin, end;
            char type;
            std::string_view flags;
            bool integer64 = false;
            unsigned width = 0;
            std::optional<unsigned> precision;

            bool flag(char value) const { return flags.find(value) != flags.npos; }
        };

        bool decimal(std::string_view &text, unsigned &value) {
            constexpr unsigned limit = 4096;

            while (!text.empty() && text.front() >= '0' && text.front() <= '9') {
                const unsigned digit = static_cast<unsigned>(text.front() - '0');

                if (value > (limit - digit) / 10) {
                    return false;
                }

                value = value * 10 + digit;
                text.remove_prefix(1);
            }

            return true;
        }

        bool parseConversion(std::string_view &text, Conversion &spec) {
            const size_t initial = text.size();
            spec.flags = text.substr(0, text.find_first_not_of("-+ #0"));
            text.remove_prefix(spec.flags.size());

            if (!decimal(text, spec.width)) {
                return false;
            }

            if (text.starts_with('.')) {
                text.remove_prefix(1);

                if (!decimal(text, spec.precision.emplace(0))) {
                    return false;
                }
            }

            if (text.starts_with("I64")) {
                spec.integer64 = true;
                text.remove_prefix(3);
            } else if (text.starts_with('l')) {
                text.remove_prefix(1);
            }

            if (text.empty()) {
                return false;
            }

            const bool plain = text.size() == initial;
            spec.type = text.front();
            text.remove_prefix(1);

            switch (spec.type) {
            case '%':
            case 'p':
            case 's':
                return plain;
            case 'd':
            case 'i':
                return !spec.flag('#');
            case 'u':
                return !spec.flag('#') && !spec.flag(' ') && !spec.flag('+');
            case 'x':
            case 'X':
                return !spec.flag(' ') && !spec.flag('+');
            default:
                return false;
            }
        }

        bool append(FormattedOutput &out, std::string_view bytes) {
            if (bytes.size() > out.bytes.size() - out.length) {
                return false;
            }

            std::ranges::copy(bytes, out.bytes.begin() + out.length);
            out.length += bytes.size();
            return true;
        }

        void pad(FormattedOutput &out, char byte, size_t count) {
            std::fill_n(out.bytes.begin() + out.length, count, byte);
            out.length += count;
        }

        std::string_view integerPrefix(const Conversion &spec, uint64_t &magnitude) {
            if (spec.type == 'd' || spec.type == 'i') {
                const bool negative = (magnitude >> (spec.integer64 ? 63U : 31U)) != 0;

                if (negative) {
                    // Unsigned arithmetic also represents the magnitude of INT64_MIN.
                    magnitude = spec.integer64 ? 0 - magnitude : uint32_t(0 - magnitude);
                    return "-";
                }

                if (spec.flag('+')) {
                    return "+";
                }

                if (spec.flag(' ')) {
                    return " ";
                }
            }

            if (spec.flag('#') && magnitude) {
                return spec.type == 'X' ? "0X" : "0x";
            }

            return {};
        }

        forge_rt_status integer(FormattedOutput &out, const Conversion &spec, uint64_t raw) {
            const bool pointer = spec.type == 'p';
            const bool hex = pointer || spec.type == 'x' || spec.type == 'X';
            const auto prefix = integerPrefix(spec, raw);
            std::array<char, 20> digits;
            auto end =
                std::to_chars(digits.data(), digits.data() + digits.size(), raw, hex ? 16 : 10).ptr;

            if (!raw && spec.precision == 0) {
                end = digits.data();
            }

            const bool uppercase = pointer || spec.type == 'X';

            for (auto *it = digits.data(); it != end; ++it) {
                if (uppercase && *it >= 'a' && *it <= 'f') {
                    *it -= 'a' - 'A';
                }
            }

            const std::string_view number(digits.data(), end);
            // The legacy integer conversion buffer admits at most 512 digits.
            const auto minDigits = pointer ? 16u : std::min(512u, spec.precision.value_or(0));
            const size_t zeros = std::max<size_t>(number.size(), minDigits) - number.size();
            const size_t used = prefix.size() + zeros + number.size();
            const size_t field = std::max<size_t>(used, spec.width);

            if (field > out.bytes.size() - out.length) {
                return unsupported;
            }

            const size_t padding = field - used;
            const bool left = spec.flag('-');
            const bool zeroPad = !left && spec.flag('0') && !spec.precision;

            if (!left && !zeroPad && padding) {
                pad(out, ' ', padding);
                out.finishPart(Part::Padding);
            }

            if (!prefix.empty()) {
                append(out, prefix);
                out.finishPart(Part::Text);
            }

            if (zeroPad && padding) {
                pad(out, '0', padding);
                out.finishPart(Part::Padding);
            }

            // Precision zeroes and digits are one string for the legacy writer.
            pad(out, '0', zeros);
            append(out, number);
            out.finishPart(Part::Text);

            if (left && padding) {
                pad(out, ' ', padding);
                out.finishPart(Part::Boundary);
            }

            return FORGE_RT_OK;
        }

        forge_rt_status render(FormattedOutput &out, const Conversion &spec, const Slots &arguments,
                               size_t &cursor) {
            if (spec.type == '%') {
                if (!append(out, "%")) {
                    return unsupported;
                }
                out.finishPart(Part::Boundary);
                return FORGE_RT_OK;
            }

            uint64_t raw;
            const bool fullSlot = spec.type == 'p' || spec.type == 's' || spec.integer64;

            if (fullSlot) {
                const auto status = arguments.readScalar(cursor, raw);

                if (status != FORGE_RT_OK) {
                    return status;
                }
            } else {
                uint32_t value;
                const auto status = arguments.readScalar(cursor, value);

                if (status != FORGE_RT_OK) {
                    return status;
                }

                raw = value;
            }

            out.slotBytes = cursor + (fullSlot ? 8 : 4);
            cursor += 8;

            if (spec.type != 's') {
                return integer(out, spec, raw);
            }

            if (!raw) {
                if (!append(out, "(null)")) {
                    return unsupported;
                }
                out.finishPart(Part::Text);
                return FORGE_RT_OK;
            }

            size_t length;
            const auto status = copyString(arguments.stringOperand(GuestAddress{raw}),
                                           std::span(out.bytes).subspan(out.length), length);

            if (status == FORGE_RT_OK) {
                out.strings[out.stringCount++] = {raw, length + 1};
                out.length += length;
                out.finishPart(Part::Text);
            }

            return status;
        }
    } // namespace

    forge_rt_status formatOutput(const win64::GuestBuffer<win64::crtVfprintf.arguments[1]> &format,
                                 const Slots &arguments, FormattedOutput &out) {
        std::array<char, crtFormatLimit> bytes;
        size_t length;
        const auto copied = copyString(format, bytes, length);

        if (copied != FORGE_RT_OK) {
            return copied;
        }

        out.formatBytes = length + 1;
        const std::string_view input(bytes.data(), length);
        std::array<Conversion, crtFormatConversions> conversions{};
        size_t count = 0;
        size_t pos = 0;

        while ((pos = input.find('%', pos)) != input.npos) {
            if (count == conversions.size()) {
                return unsupported;
            }

            auto &spec = conversions[count++];
            spec.begin = pos;
            auto remaining = input.substr(pos + 1);

            if (!parseConversion(remaining, spec)) {
                return unsupported;
            }

            spec.end = length - remaining.size();
            pos = spec.end;
        }

        pos = 0;
        size_t cursor = 0;

        for (const auto &spec : std::span(conversions).first(count)) {
            if (!append(out, input.substr(pos, spec.begin - pos))) {
                return unsupported;
            }

            // Even an empty literal separates adjacent conversions after a write failure.
            out.finishPart(Part::Boundary);
            const auto status = render(out, spec, arguments, cursor);

            if (status != FORGE_RT_OK) {
                return status;
            }

            pos = spec.end;
        }

        if (!append(out, input.substr(pos))) {
            return unsupported;
        }
        out.finishPart(Part::Boundary);
        return FORGE_RT_OK;
    }
} // namespace forge::runtime
