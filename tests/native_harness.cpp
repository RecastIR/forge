#include <bit>
#include <cstdint>
#include <iostream>

extern "C" std::int64_t forge_lifted(std::int64_t, std::int64_t);

int main() {
    std::uint64_t a, b;
    while (std::cin >> std::hex >> a >> b) {
        const auto result =
            forge_lifted(std::bit_cast<std::int64_t>(a), std::bit_cast<std::int64_t>(b));
        std::cout << std::hex << std::bit_cast<std::uint64_t>(result) << '\n';
    }
    return std::cin.eof() && std::cout ? 0 : 1;
}
