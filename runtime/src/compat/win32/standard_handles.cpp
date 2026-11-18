#include "../../core/instance.h"

namespace forge::runtime {
    StandardHandles::~StandardHandles() {
        // Retire stdin, stdout and stderr in capture order, including on registration rollback.
        for (auto &stream : streams) {
            stream.descriptor.reset();
        }
    }

    forge_rt_status StandardHandles::capture() noexcept {
        using Status = darwin::CaptureResult::Status;

        for (size_t index = 0; index < streams.size(); ++index) {
            auto &stream = streams[index];
            const auto captured =
                darwin::Descriptor::capture(static_cast<int>(index), stream.descriptor);

            switch (captured.status) {
            case Status::Captured:
                break;
            case Status::Unavailable:
                continue;
            case Status::ResourceExhausted:
                return FORGE_RT_RESOURCE_EXHAUSTED;
            case Status::NativeFailure:
                return FORGE_RT_HOST_CONFIGURATION;
            }

            // Guest handles occupy a separate namespace from small POSIX descriptors.
            // Exhaust before wrapping or issuing the Windows INVALID_HANDLE_VALUE sentinel.
            constexpr uint64_t handleTag = uint64_t{1} << 63U;
            const auto generation = issueToken();

            if (!generation || generation >= handleTag - 1) {
                return FORGE_RT_RESOURCE_EXHAUSTED;
            }

            stream.handle = handleTag | generation;
        }

        return FORGE_RT_OK;
    }
} // namespace forge::runtime
