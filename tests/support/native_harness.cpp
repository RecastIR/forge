#include <bit>
#include <cstdint>
#include <cstdio>
#include <iostream>

extern "C" std::int64_t forge_lifted(std::int64_t, std::int64_t);

int main() {
    std::cin >> std::hex;

    while (std::cin >> std::ws && !std::cin.eof()) {
        std::uint64_t a, b;

        if (!(std::cin >> a >> b)) {
            return 1;
        }

        const auto result =
            forge_lifted(std::bit_cast<std::int64_t>(a), std::bit_cast<std::int64_t>(b));
        std::cout << std::hex << std::bit_cast<std::uint64_t>(result) << '\n';
    }

    // A stdio read error can also set eofbit on the synchronized C++ stream.
    const bool cleanEof = std::cin.eof() && !std::cin.bad() && std::ferror(stdin) == 0;
    return cleanEof && std::cout.flush() ? 0 : 1;
}
