#include <bit>
#include <cstdint>
#include <iostream>

extern "C" std::int64_t forge_lifted(std::int64_t, std::int64_t);

int main() {
    std::cin >> std::hex;

    while (std::cin >> std::ws && !std::cin.eof()) {
        std::uint64_t a, b;

        if (!(std::cin >> a >> b)) {
            return 1;
        }

        const auto Result =
            forge_lifted(std::bit_cast<std::int64_t>(a), std::bit_cast<std::int64_t>(b));
        std::cout << std::hex << std::bit_cast<std::uint64_t>(Result) << '\n';
    }

    return std::cin.eof() && !std::cin.bad() && std::cout.flush() ? 0 : 1;
}
