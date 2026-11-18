#pragma once

#include "forge/process.h"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace forge::runtime {
    struct CrtParameters {
        forge_rt_status initialize(std::string_view command,
                                   const forge_rt_process_startup &startup);
        void relocate(uint64_t base);
        uint64_t dataAddress(uint32_t kind) const;
        forge_rt_status copyArguments(forge_rt_instance &owner, uint64_t &address) const;

        int32_t count() const { return static_cast<int32_t>(arguments.size()); }

        std::vector<uint8_t> bytes;
        uint64_t claim = 0;

      private:
        std::vector<std::string> arguments;
        uint64_t base = 0;
        std::vector<size_t> fixups;
        void bind(size_t offset, size_t target);
        size_t appendString(std::string_view text);
        size_t appendVector(std::span<const std::string_view> strings);
    };
} // namespace forge::runtime
