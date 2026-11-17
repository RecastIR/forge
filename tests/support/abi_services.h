#pragma once

#include "forge/service_signature.h"

namespace forge::test {
    using namespace win64;

    extern "C" {
    forge_rt_status abiPair(forge_rt_instance *, forge_rt_thread_token, int32_t, uint32_t,
                            int64_t *) noexcept;
    forge_rt_status abiTriple(forge_rt_instance *, forge_rt_thread_token, uint64_t, int64_t,
                              uint64_t, uint64_t *) noexcept;
    forge_rt_status abiFour(forge_rt_instance *, forge_rt_thread_token, int32_t, uint32_t, int64_t,
                            uint64_t, int32_t *) noexcept;
    forge_rt_status abiSix(forge_rt_instance *, forge_rt_thread_token, uint64_t, uint64_t, uint64_t,
                           uint64_t, int32_t, uint64_t, uint64_t *) noexcept;
    forge_rt_status abiWrite(forge_rt_instance *, forge_rt_thread_token, uint64_t, uint64_t,
                             uint32_t, uint64_t, uint64_t, int32_t *,
                             forge_rt_memory_fault *) noexcept;
    forge_rt_status abiEcho(forge_rt_instance *, forge_rt_thread_token, uint64_t,
                            uint64_t *) noexcept;
    forge_rt_status abiTailByte(forge_rt_instance *, forge_rt_thread_token, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint32_t, uint32_t *,
                                forge_rt_memory_fault *) noexcept;
    }

    inline constexpr Argument u32{Value::U32}, i32{Value::I32}, u64{Value::U64}, i64{Value::I64},
        word{Value::Word}, handle{Value::Handle}, address{Value::Address};
    inline constexpr Argument input{Value::Address, Access::Input, Extent::CountArgument, 2};
    inline constexpr Argument countOut{Value::Address, Access::Output, Extent::Fixed, 4, true};
    inline constexpr Argument overlapped{Value::Address, Access::InOut, Extent::Fixed, 32, true};
    inline constexpr auto writeProbe = bind<Value::I32, handle, input, u32, countOut, overlapped>(
        "forgeabi.dll", "WriteProbe", LastError::Preserve, FORGE_SERVICE_ADAPTER(abiWrite));
    inline constexpr Argument stackCounted{Value::Address, Access::Input, Extent::CountArgument, 4};
    inline constexpr auto tailByte = bind<Value::U32, stackCounted, word, word, word, u32>(
        "forgeabi.dll", "TailByte", LastError::Preserve, FORGE_SERVICE_ADAPTER(abiTailByte));

    constexpr bool rejected(Argument arg, Convention convention = Convention::WindowsX64) {
        const ServiceBinding binding{"test.dll",          "Test",    "test", {&arg, 1}, Value::Void,
                                     LastError::Preserve, convention};
        return !binding.error().empty();
    }

    static_assert(rejected({Value::Float}) && rejected({Value::Vector}) &&
                  rejected({Value::Aggregate}) && rejected({Value::Callback}));
    static_assert(rejected(u32, Convention::Variadic) && rejected(u32, Convention::Alternate) &&
                  rejected(u32, Convention::Unwinding));
    static_assert(rejected({Value::Void}) &&
                  rejected({Value::I32, Access::Output, Extent::Fixed, 4}) &&
                  rejected({Value::Address, Access::Input, Extent::CountArgument, 1}) &&
                  rejected({Value::Address, Access::Input, Extent::CountArgument, 0}));

    inline constexpr ServiceBinding abiServices[] = {
        setLastError,
        getLastError,
        stringLength,
        bind<Value::I64, i32, u32>("forgeabi.dll", "Pair", LastError::Preserve,
                                   FORGE_SERVICE_ADAPTER(abiPair)),
        bind<Value::Word, word, i64, u64>("forgeabi.dll", "Triple", LastError::Preserve,
                                          FORGE_SERVICE_ADAPTER(abiTriple)),
        bind<Value::I32, i32, u32, i64, handle>("forgeabi.dll", "Four", LastError::Preserve,
                                                FORGE_SERVICE_ADAPTER(abiFour)),
        bind<Value::U64, u64, u64, u64, u64, i32, u64>("forgeabi.dll", "Six", LastError::Preserve,
                                                       FORGE_SERVICE_ADAPTER(abiSix)),
        bind<Value::Address, address>("forgeabi.dll", "Address", LastError::Preserve,
                                      FORGE_SERVICE_ADAPTER(abiEcho)),
        bind<Value::Handle, handle>("forgeabi.dll", "Handle", LastError::Preserve,
                                    FORGE_SERVICE_ADAPTER(abiEcho)),
        writeProbe,
        tailByte,
        {"forgeabi.dll", "Bad", "abiBad", {}, Value::Vector, LastError::Preserve}};
} // namespace forge::test
