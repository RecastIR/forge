#pragma once

#include "forge/msvcrt_process.h"
#include "forge/runtime.h"

#include <array>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>

namespace forge::win64 {
    enum class Value : uint8_t {
        Void,
        U32,
        I32,
        U64,
        I64,
        Word,
        Address,
        Handle,
        Float,
        Vector,
        Aggregate,
        Callback
    };
    enum class Access : uint8_t { None, Input, Output, InOut };
    enum class Extent : uint8_t {
        None,
        Fixed,
        CountArgument,
        CString,
        InitializerEnd,
        ElementProduct,
        FormatArguments
    };
    enum class Callback : uint8_t { None, Initializer, Registration, Cleanup };

    // Match the compiler's per-table indirect dispatch budget.
    inline constexpr uint64_t maxInitializerEntries = 1024;

    constexpr std::optional<uint64_t> initializerRangeBytes(uint64_t first, uint64_t last) {
        constexpr auto stride = sizeof(uint64_t);
        if (first % stride || last % stride || first > last ||
            last - first > maxInitializerEntries * stride) {
            return std::nullopt;
        }

        return last - first;
    }

    constexpr std::optional<uint64_t> elementBytes(uint64_t size, uint64_t count) {
        if (size && count > UINT64_MAX / size) {
            return std::nullopt;
        }
        return size * count;
    }

    constexpr std::string_view unsupportedType(Value type) {
        switch (type) {
        case Value::Float:
            return "floating-point values require XMM lowering";
        case Value::Vector:
            return "vector values require vector ABI lowering";
        case Value::Aggregate:
            return "aggregate parameters and structure returns are unsupported";
        case Value::Callback:
            return "guest callback re-entry is unsupported";
        default:
            return {};
        }
    }

    enum class Convention : uint8_t { WindowsX64, Variadic, Alternate, Unwinding };
    enum class Requirement : uint8_t { Instance, Process };
    enum class Control : uint8_t { Returns, Terminates };
    enum class LastError : uint8_t { Read, Write, Preserve, OnFailure, CallbackDefined };

    constexpr unsigned width(Value type) {
        switch (type) {
        case Value::U32:
        case Value::I32:
            return 32;
        case Value::U64:
        case Value::I64:
        case Value::Word:
        case Value::Address:
        case Value::Handle:
            return 64;
        default:
            return 0;
        }
    }

    struct Argument {
        Value type;
        Access access = Access::None;
        Extent extent = Extent::None;
        // Fixed size, CString limit including NUL, FormatArguments ceiling in bytes, or size
        // argument index.
        unsigned size = 0;
        bool optional = false;

        constexpr bool writes() const {
            return access == Access::Output || access == Access::InOut;
        }
    };

    struct ServiceBinding {
        std::string_view dll, name, nativeSymbol;
        std::span<const Argument> arguments;
        Value result;
        LastError lastError;
        Convention convention = Convention::WindowsX64;
        Requirement requirement = Requirement::Instance;
        Control control = Control::Returns;
        bool returnsProcessStorage = false;
        Callback callback = Callback::None;

        constexpr bool checkedMemory() const {
            for (auto arg : arguments) {
                if (arg.access != Access::None) {
                    return true;
                }
            }

            return false;
        }

        constexpr bool validArgument(Argument arg) const {
            if (!width(arg.type)) {
                return false;
            }

            if (arg.access == Access::None) {
                return arg.extent == Extent::None && !arg.size && !arg.optional;
            }

            if (arg.type != Value::Address) {
                return false;
            }

            switch (arg.extent) {
            case Extent::CString:
                return arg.access == Access::Input;
            case Extent::FormatArguments:
                return arg.access == Access::Input && !arg.optional && arg.size && !(arg.size % 8);
            case Extent::Fixed:
                return arg.size != 0;
            case Extent::InitializerEnd:
                return arg.access == Access::Input && !arg.optional &&
                       arg.size < arguments.size() && arguments[arg.size].type == Value::Address &&
                       arguments[arg.size].access == Access::None;
            case Extent::ElementProduct:
                // size names the first of two consecutive Windows size_t arguments.
                return arg.access == Access::Input && arg.size < arguments.size() &&
                       arguments.size() - arg.size >= 2 &&
                       arguments[arg.size].type == Value::Word &&
                       arguments[arg.size + 1].type == Value::Word;
            case Extent::CountArgument:
                if (arg.size < arguments.size()) {
                    const auto count = arguments[arg.size].type;
                    return count == Value::U32 || count == Value::U64 || count == Value::Word;
                }
                return false;
            default:
                return false;
            }
        }

        constexpr std::string_view error() const {
            if (callback == Callback::Initializer &&
                (result != Value::Void || requirement != Requirement::Process ||
                 control != Control::Returns || lastError != LastError::CallbackDefined ||
                 arguments.size() != 2 || arguments[0].extent != Extent::InitializerEnd ||
                 arguments[0].size != 1)) {
                return "initializer dispatch requires a managed void service with a pointer range";
            }

            if (callback != Callback::None && requirement != Requirement::Process) {
                return "guest callbacks require a managed process";
            }
            if (callback == Callback::Registration &&
                (result != Value::Address || arguments.size() != 1 ||
                 arguments.front().type != Value::Address || checkedMemory())) {
                return "CRT registration requires one unchecked guest address and an address "
                       "result";
            }

            if (callback == Callback::Cleanup && (lastError != LastError::CallbackDefined ||
                                                  result != Value::Void || checkedMemory())) {
                return "CRT cleanup requires an unchecked void service with callback-defined last "
                       "error";
            }

            if (returnsProcessStorage &&
                (result != Value::Address || requirement != Requirement::Process)) {
                return "process storage requires a managed service returning a guest address";
            }
            if (control == Control::Terminates &&
                (result != Value::Void || requirement != Requirement::Process)) {
                return "a terminal service requires a managed process and void result";
            }

            switch (convention) {
            case Convention::Variadic:
                return "variadic calls are unsupported";
            case Convention::Alternate:
                return "alternate calling conventions are unsupported";
            case Convention::Unwinding:
                return "exception unwinding across the bridge is unsupported";
            case Convention::WindowsX64:
                break;
            }

            if (const auto reason = unsupportedType(result); !reason.empty()) {
                return reason;
            }

            if (result != Value::Void && !width(result)) {
                return "unsupported service result type";
            }

            for (auto arg : arguments) {
                if (arg.extent == Extent::InitializerEnd && callback != Callback::Initializer) {
                    return "an initializer table requires a generated dispatcher";
                }

                if (const auto reason = unsupportedType(arg.type); !reason.empty()) {
                    return reason;
                }

                if (!validArgument(arg)) {
                    return "invalid argument type, guest-memory direction or buffer-length "
                           "relationship";
                }
            }

            return {};
        }
    };

    // Exact fixed-width types at the native C boundary. Guest addresses and handles
    // cross as integer bits. Only result and fault slots are native output pointers.
    template <Value type> struct NativeScalar {
        using Type = uint64_t;
    };

    template <> struct NativeScalar<Value::I64> {
        using Type = int64_t;
    };

    template <> struct NativeScalar<Value::I32> {
        using Type = int32_t;
    };

    template <> struct NativeScalar<Value::U32> {
        using Type = uint32_t;
    };

    template <> struct NativeScalar<Value::Void> {
        using Type = void;
    };

    template <Argument... args>
    inline constexpr std::array<Argument, sizeof...(args)> parameters{args...};

    template <class... Args>
    using NativeFunction = forge_rt_status (*)(forge_rt_instance *, forge_rt_thread_token,
                                               Args...) noexcept;

    template <Value result, Argument... args, class Function>
    consteval ServiceBinding bind(std::string_view dll, std::string_view name, LastError effect,
                                  std::string_view nativeSymbol, Function,
                                  Requirement requirement = Requirement::Instance,
                                  Control control = Control::Returns) {
        constexpr ServiceBinding shape{
            {}, {}, {}, parameters<args...>, result, LastError::Preserve};
        using Out = typename NativeScalar<result>::Type *;
        using Fault = forge_rt_memory_fault *;
        constexpr bool initializer =
            std::is_same_v<Function, NativeFunction<typename NativeScalar<args.type>::Type...,
                                                    Fault, forge_rt_initializer_dispatch>>;
        constexpr bool registration =
            std::is_same_v<Function, NativeFunction<uint64_t, uint64_t *, uint64_t>>;
        constexpr bool cleanup =
            std::is_same_v<Function, NativeFunction<typename NativeScalar<args.type>::Type...,
                                                    forge_rt_termination_dispatch>>;
        if constexpr (registration) {
            static_assert(result == Value::Address && sizeof...(args) == 1 &&
                          ((args.type == Value::Address) && ...));
        } else if constexpr (cleanup) {
            static_assert(result == Value::Void && !shape.checkedMemory());
        } else if constexpr (initializer) {
            static_assert(result == Value::Void && shape.checkedMemory());
        } else if constexpr (result == Value::Void && !shape.checkedMemory()) {
            static_assert(
                std::is_same_v<Function,
                               NativeFunction<typename NativeScalar<args.type>::Type...>>);
        } else if constexpr (result == Value::Void) {
            static_assert(
                std::is_same_v<Function,
                               NativeFunction<typename NativeScalar<args.type>::Type..., Fault>>);
        } else if constexpr (shape.checkedMemory()) {
            static_assert(
                std::is_same_v<Function, NativeFunction<typename NativeScalar<args.type>::Type...,
                                                        Out, Fault>>);
        } else {
            static_assert(
                std::is_same_v<Function,
                               NativeFunction<typename NativeScalar<args.type>::Type..., Out>>);
        }

        ServiceBinding binding{dll,    name,   nativeSymbol,           parameters<args...>,
                               result, effect, Convention::WindowsX64, requirement,
                               control};
        if constexpr (initializer) {
            binding.callback = Callback::Initializer;
        } else if constexpr (registration) {
            binding.callback = Callback::Registration;
        } else if constexpr (cleanup) {
            binding.callback = Callback::Cleanup;
        }

        if (!binding.error().empty()) {
            throw "invalid Windows x64 service declaration";
        }

        return binding;
    }

    consteval ServiceBinding processPointer(ServiceBinding binding) {
        binding.returnsProcessStorage = true;
        if (!binding.error().empty()) {
            throw "invalid process pointer result";
        }
        return binding;
    }

    // Keep the linker spelling and the declaration used for the prototype check together.
#define FORGE_SERVICE_ADAPTER(symbol) #symbol, symbol

    inline constexpr auto getStdHandle = bind<Value::Handle, Argument{Value::U32}>(
        "kernel32.dll", "GetStdHandle", LastError::OnFailure,
        FORGE_SERVICE_ADAPTER(forge_rt_get_std_handle), Requirement::Process);
    inline constexpr auto writeFile =
        bind<Value::I32, Argument{Value::Handle},
             Argument{Value::Address, Access::Input, Extent::CountArgument, 2},
             Argument{Value::U32}, Argument{Value::Address, Access::Output, Extent::Fixed, 4},
             Argument{Value::Address}>("kernel32.dll", "WriteFile", LastError::OnFailure,
                                       FORGE_SERVICE_ADAPTER(forge_rt_write_file),
                                       Requirement::Process);

    inline constexpr Argument nullableString{Value::Address, Access::Input, Extent::CString, 0,
                                             true};
    inline constexpr auto stringLength = bind<Value::I32, nullableString>(
        "kernel32.dll", "lstrlenA", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_lstrlen_a));

    inline constexpr Argument byteString{Value::Address, Access::Input, Extent::CString};
    inline constexpr Argument inputBytes{Value::Address, Access::Input, Extent::CountArgument, 2};
    inline constexpr Argument outputBytes{Value::Address, Access::Output, Extent::CountArgument, 2};
    inline constexpr auto crtStrlen = bind<Value::U64, byteString>(
        "msvcrt.dll", "strlen", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_strlen));
    inline constexpr auto crtStrcmp = bind<Value::I32, byteString, byteString>(
        "msvcrt.dll", "strcmp", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_strcmp));
    inline constexpr auto crtStrncmp =
        bind<Value::I32, inputBytes, inputBytes, Argument{Value::U64}>(
            "msvcrt.dll", "strncmp", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_strncmp));
    inline constexpr auto crtMemcpy =
        bind<Value::Address, outputBytes, inputBytes, Argument{Value::U64}>(
            "msvcrt.dll", "memcpy", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_memcpy));

    inline constexpr auto setLastError =
        bind<Value::Void, Argument{Value::U32}>("kernel32.dll", "SetLastError", LastError::Write,
                                                FORGE_SERVICE_ADAPTER(forge_rt_set_last_error));
    inline constexpr auto getLastError =
        bind<Value::U32>("kernel32.dll", "GetLastError", LastError::Read,
                         FORGE_SERVICE_ADAPTER(forge_rt_get_last_error));
    inline constexpr auto sleep = bind<Value::Void, Argument{Value::U32}>(
        "kernel32.dll", "Sleep", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_sleep));

    inline constexpr auto exitProcess = bind<Value::Void, Argument{Value::U32}>(
        "kernel32.dll", "ExitProcess", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_exit_process), Requirement::Process, Control::Terminates);

    inline constexpr auto setUnhandledExceptionFilter =
        bind<Value::Address, Argument{Value::Address}>(
            "kernel32.dll", "SetUnhandledExceptionFilter", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_set_unhandled_exception_filter), Requirement::Process);

    inline constexpr auto virtualProtect =
        bind<Value::I32, Argument{Value::Address}, Argument{Value::U64}, Argument{Value::U32},
             Argument{Value::Address, Access::Output, Extent::Fixed, 4}>(
            "kernel32.dll", "VirtualProtect", LastError::OnFailure,
            FORGE_SERVICE_ADAPTER(forge_rt_virtual_protect), Requirement::Process);

    inline constexpr Argument startupInfoOutput{Value::Address, Access::Output, Extent::Fixed, 104};
    inline constexpr auto getStartupInfoA = bind<Value::Void, startupInfoOutput>(
        "kernel32.dll", "GetStartupInfoA", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_get_startup_info_a), Requirement::Process);
    inline constexpr auto getStartupInfoW = bind<Value::Void, startupInfoOutput>(
        "kernel32.dll", "GetStartupInfoW", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_get_startup_info_w), Requirement::Process);

    inline constexpr auto getCommandLineA = processPointer(bind<Value::Address>(
        "kernel32.dll", "GetCommandLineA", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_get_command_line_a), Requirement::Process));
    inline constexpr auto getCommandLineW = processPointer(bind<Value::Address>(
        "kernel32.dll", "GetCommandLineW", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_get_command_line_w), Requirement::Process));

    inline constexpr auto crtMalloc = processPointer(bind<Value::Address, Argument{Value::U64}>(
        "msvcrt.dll", "malloc", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_malloc),
        Requirement::Process));
    inline constexpr auto crtCalloc =
        processPointer(bind<Value::Address, Argument{Value::U64}, Argument{Value::U64}>(
            "msvcrt.dll", "calloc", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_calloc), Requirement::Process));
    inline constexpr auto crtFree = bind<Value::Void, Argument{Value::Address}>(
        "msvcrt.dll", "free", LastError::Preserve, FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_free),
        Requirement::Process);
    inline constexpr auto crtErrno = processPointer(
        bind<Value::Address>("msvcrt.dll", "_errno", LastError::Preserve,
                             FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_errno), Requirement::Process));

    inline constexpr auto crtIob = processPointer(bind<Value::Address>(
        "msvcrt.dll", "__iob_func", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_iob_func), Requirement::Process));
    // Includes the NUL. The compiler and runtime use the same readable extent.
    inline constexpr uint64_t crtPutsScanLimit = 1024 * 1024;
    inline constexpr auto crtPuts = bind<Value::I32, Argument{Value::Address, Access::Input,
                                                              Extent::CString, crtPutsScanLimit}>(
        "msvcrt.dll", "puts", LastError::OnFailure, FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_puts),
        Requirement::Process);
    inline constexpr unsigned crtFormatLimit = 4096, crtFormatConversions = 64;
    inline constexpr Argument crtFormatStringOperand{Value::Address, Access::Input, Extent::CString,
                                                     8192};
    inline constexpr auto crtVfprintf =
        bind<Value::I32, Argument{Value::Address},
             Argument{Value::Address, Access::Input, Extent::CString, crtFormatLimit},
             Argument{Value::Address, Access::Input, Extent::FormatArguments,
                      crtFormatConversions * 8}>("msvcrt.dll", "vfprintf", LastError::OnFailure,
                                                 FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_vfprintf),
                                                 Requirement::Process);

    inline constexpr auto crtFwrite =
        bind<Value::Word, Argument{Value::Address, Access::Input, Extent::ElementProduct, 1},
             Argument{Value::Word}, Argument{Value::Word}, Argument{Value::Address}>(
            "msvcrt.dll", "fwrite", LastError::OnFailure,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_fwrite), Requirement::Process);

    inline constexpr auto crtGetMainArgs =
        bind<Value::I32, Argument{Value::Address, Access::Output, Extent::Fixed, 4},
             Argument{Value::Address, Access::Output, Extent::Fixed, 8},
             Argument{Value::Address, Access::Output, Extent::Fixed, 8}, Argument{Value::I32},
             Argument{Value::Address, Access::Input, Extent::Fixed, 4, true}>(
            "msvcrt.dll", "__getmainargs", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_getmainargs), Requirement::Process);

    inline constexpr auto crtSetAppType = bind<Value::Void, Argument{Value::I32}>(
        "msvcrt.dll", "__set_app_type", LastError::Preserve,
        FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_set_app_type), Requirement::Process);

    inline constexpr auto crtAmsgExit =
        bind<Value::Void, Argument{Value::I32}>("msvcrt.dll", "_amsg_exit", LastError::Preserve,
                                                FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_amsg_exit),
                                                Requirement::Process, Control::Terminates);

    inline constexpr auto crtInitterm =
        bind<Value::Void, Argument{Value::Address, Access::Input, Extent::InitializerEnd, 1},
             Argument{Value::Address}>("msvcrt.dll", "_initterm", LastError::CallbackDefined,
                                       FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_initterm),
                                       Requirement::Process);

    inline constexpr auto crtOnexit = bind<Value::Address, Argument{Value::Address}>(
        "msvcrt.dll", "_onexit", LastError::OnFailure,
        FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_onexit), Requirement::Process);
    inline constexpr auto crtCexit =
        bind<Value::Void>("msvcrt.dll", "_cexit", LastError::CallbackDefined,
                          FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_cexit), Requirement::Process);
    inline constexpr auto crtExit = bind<Value::Void, Argument{Value::I32}>(
        "msvcrt.dll", "exit", LastError::CallbackDefined,
        FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_exit), Requirement::Process, Control::Terminates);

    inline constexpr auto crtAbort = bind<Value::Void>("msvcrt.dll", "abort", LastError::Preserve,
                                                       FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_abort),
                                                       Requirement::Process, Control::Terminates);

    inline constexpr ServiceBinding services[] = {
        crtGetMainArgs,
        crtStrlen,
        crtStrcmp,
        crtStrncmp,
        crtMemcpy,
        crtMalloc,
        crtCalloc,
        crtFree,
        crtErrno,
        setLastError,
        getLastError,
        stringLength,
        getStdHandle,
        writeFile,
        exitProcess,
        getCommandLineA,
        getCommandLineW,
        sleep,
        setUnhandledExceptionFilter,
        crtAmsgExit,
        crtInitterm,
        getStartupInfoA,
        getStartupInfoW,
        crtOnexit,
        crtCexit,
        crtExit,
        crtSetAppType,
        virtualProtect,
        crtIob,
        crtFwrite,
        crtPuts,
        crtVfprintf,
        crtAbort,
    };
} // namespace forge::win64
