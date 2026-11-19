#pragma once

#include "forge/msvcrt_process.h"
#include "forge/runtime.h"

#include <array>
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
    enum class Extent : uint8_t { None, Fixed, CountArgument, CString };

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
    enum class LastError : uint8_t { Read, Write, Preserve, OnFailure };

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
        // Fixed byte count or zero-based index of the unsigned byte-count argument.
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
                return arg.access == Access::Input && !arg.size;
            case Extent::Fixed:
                return arg.size != 0;
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
        static_assert(shape.error().empty(),
                      "unsupported Windows x64 service type or memory contract");
        using Out = typename NativeScalar<result>::Type *;
        using Fault = forge_rt_memory_fault *;
        if constexpr (result == Value::Void && !shape.checkedMemory()) {
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

        const ServiceBinding binding{dll,    name,   nativeSymbol,           parameters<args...>,
                                     result, effect, Convention::WindowsX64, requirement,
                                     control};

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

    inline constexpr auto crtGetMainArgs =
        bind<Value::I32, Argument{Value::Address, Access::Output, Extent::Fixed, 4},
             Argument{Value::Address, Access::Output, Extent::Fixed, 8},
             Argument{Value::Address, Access::Output, Extent::Fixed, 8}, Argument{Value::I32},
             Argument{Value::Address, Access::Input, Extent::Fixed, 4, true}>(
            "msvcrt.dll", "__getmainargs", LastError::Preserve,
            FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_getmainargs), Requirement::Process);

    inline constexpr auto crtAmsgExit =
        bind<Value::Void, Argument{Value::I32}>("msvcrt.dll", "_amsg_exit", LastError::Preserve,
                                                FORGE_SERVICE_ADAPTER(forge_rt_msvcrt_amsg_exit),
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
    };
} // namespace forge::win64
