#pragma once

#include "forge/process.h"
#include "instance.h"
#include "page_protection.h"

#include <array>

namespace forge::runtime {
    template <typename T> std::span<const T> tableRows(const T *table, uint64_t count) {
        return {table, static_cast<size_t>(count)};
    }

    struct WritableBacking {
        std::vector<uint8_t> bytes;
        uint64_t claim = 0;
    };

    struct ExecutionContext {
        ExecutionContext();
        ExecutionContext(const ExecutionContext &) = delete;
        ExecutionContext &operator=(const ExecutionContext &) = delete;

        std::array<uint8_t, FORGE_RT_STACK_SIZE> bytes{}, marks{};
        forge_rt_stack stack{FORGE_RT_STACK_BASE, FORGE_RT_STACK_SIZE, bytes.data(), marks.data(),
                             FORGE_RT_ENTRY_RSP};
        forge_rt_thread_token thread = 0;
        forge_rt_execution view{};
    };

    // The managed occurrence constructs this image in place. Published descriptors and
    // the execution view borrow its backing, primary stack and instance at stable addresses.
    struct ProcessImage {
        explicit ProcessImage(const forge_rt_artifact &artifact) : artifact(artifact) {}

        forge_rt_status prepare();
        forge_rt_status reserveImportAddresses(uint64_t size, uint64_t alignment);
        void reservePrimaryStackSlot();
        forge_rt_process_result run() noexcept;
        void retire() noexcept;

        const forge_rt_artifact &artifact;
        std::vector<WritableBacking> backings;
        forge_rt_image functionAddresses{};
        ExecutionContext execution;
        forge_rt_instance instance;

      private:
        std::vector<forge_rt_image_region> regions;
        forge_rt_image image{};
        PageProtections protections;
        forge_rt_status bindRegions();
    };

    forge_rt_status checkArtifact(const forge_rt_artifact &artifact);
} // namespace forge::runtime
