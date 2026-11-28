#pragma once

#include "pe/image.h"
#include "llvm/Support/JSON.h"

namespace forge {
    inline llvm::json::Object tlsJson(const TLS &tls) {
        llvm::json::Array callbacks;
        for (const auto va : tls.callbackVas) {
            callbacks.push_back(hex(va));
        }

        return llvm::json::Object{
            {"directory_rva", hex(tls.rva)},          {"raw_data_start_va", hex(tls.start)},
            {"raw_data_end_va", hex(tls.end)},        {"index_va", hex(tls.index)},
            {"callbacks_va", hex(tls.callbacks)},     {"zero_fill_size", tls.zeroFill},
            {"characteristics", tls.characteristics}, {"callback_vas", std::move(callbacks)}};
    }
} // namespace forge
