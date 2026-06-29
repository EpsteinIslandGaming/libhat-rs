#pragma once

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../c/libhat.h"
#include "defines.hpp"
#include "export.hpp"
#include "result.hpp"

LIBHAT_EXPORT namespace hat {

    struct signature_element {
        std::byte value_{};
        std::byte mask_{};

        constexpr signature_element() noexcept = default;
        constexpr signature_element(std::nullopt_t) noexcept {}
        constexpr signature_element(std::byte value) noexcept : value_(value), mask_(std::byte{0xFF}) {}
        constexpr signature_element(std::byte value, std::byte mask) noexcept : value_(value & mask), mask_(mask) {}

        constexpr signature_element& operator=(std::nullopt_t) noexcept { return *this = signature_element{}; }
        constexpr signature_element& operator=(std::byte valueIn) noexcept { return *this = signature_element{valueIn}; }
        constexpr void reset() noexcept { *this = std::nullopt; }

        [[nodiscard]] constexpr std::byte value() const noexcept { return value_; }
        [[nodiscard]] constexpr std::byte mask() const noexcept { return mask_; }
        [[nodiscard]] constexpr std::byte operator*() const noexcept { return value(); }
        [[nodiscard]] constexpr bool all() const noexcept { return mask_ == std::byte{0xFF}; }
        [[nodiscard]] constexpr bool any() const noexcept { return mask_ != std::byte{0x00}; }
        [[nodiscard]] constexpr bool none() const noexcept { return mask_ == std::byte{0x00}; }
        [[nodiscard]] constexpr bool operator==(std::byte byte) const noexcept { return (byte & mask_) == value_; }
    };

    using signature = std::vector<signature_element>;
    using signature_view = std::span<const signature_element>;

    enum class signature_error {
        missing_masked_byte,
        element_parse_error,
        empty_signature,
        expected_wildcard,
        invalid_token_length,
    };

    namespace detail {
        inline signature_error status_to_error(libhat_status_t status) {
            switch (status) {
                case libhat_err_sig_no_byte: return signature_error::missing_masked_byte;
                case libhat_err_sig_empty:   return signature_error::empty_signature;
                default:                     return signature_error::element_parse_error;
            }
        }
    }

    inline result<signature, signature_error> parse_signature(std::string_view str) {
        signature_t* sig = nullptr;
        auto status = libhat_parse_signature(str.data(), &sig);
        if (status == libhat_success) {
            auto data = static_cast<signature_element*>(sig->data);
            signature result;
            result.reserve(sig->count);
            for (size_t i = 0; i < sig->count; ++i) {
                auto& elem = data[i];
                result.emplace_back(elem.value_, elem.mask_);
            }
            libhat_free(sig);
            return result;
        }
        return result_error{detail::status_to_error(status)};
    }

    inline result<signature, signature_error> create_signature(
        std::span<const std::byte> bytes,
        std::span<const std::byte> mask)
    {
        if (bytes.size() != mask.size()) {
            return result_error{signature_error::element_parse_error};
        }
        if (bytes.empty()) {
            return result_error{signature_error::empty_signature};
        }

        signature sig;
        sig.reserve(bytes.size());
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (std::to_integer<uint8_t>(mask[i]) != 0) {
                sig.emplace_back(bytes[i]);
            } else {
                sig.emplace_back(std::nullopt);
            }
        }
        return sig;
    }

    template<typename Char>
    inline result<signature, signature_error> string_to_signature(std::basic_string_view<Char> str) {
        if (str.empty()) {
            return result_error{signature_error::empty_signature};
        }
        signature result;
        result.resize(str.size() * sizeof(Char));
        auto it = result.begin();
        for (Char ch : str) {
            const auto bytes = std::bit_cast<std::array<std::byte, sizeof(Char)>>(ch);
            for (auto b : bytes) {
                *it++ = b;
            }
        }
        return result;
    }

    template<typename Char>
    inline result<signature, signature_error> string_to_signature(const std::basic_string<Char>& str) {
        return string_to_signature(std::basic_string_view<Char>{str});
    }
}
