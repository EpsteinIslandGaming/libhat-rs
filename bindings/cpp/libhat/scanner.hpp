#pragma once

#include <cstddef>
#include <cstring>
#include <memory>

#include "../../c/libhat.h"
#include "defines.hpp"
#include "export.hpp"
#include "signature.hpp"

LIBHAT_EXPORT namespace hat {

    class const_scan_result {
    public:
        using underlying_type = const std::byte*;

        constexpr const_scan_result() noexcept : result_(nullptr) {}
        explicit(false) constexpr const_scan_result(std::nullptr_t) noexcept : result_(nullptr) {}
        explicit(false) constexpr const_scan_result(underlying_type result) noexcept : result_(result) {}

        template<std::integral Int>
        [[nodiscard]] Int read(size_t offset) const noexcept {
            Int value;
            std::memcpy(&value, result_ + offset, sizeof(Int));
            return value;
        }

        template<std::integral Int, typename ArrayType>
        [[nodiscard]] size_t index(size_t offset) const noexcept {
            return static_cast<size_t>(read<Int>(offset)) / sizeof(ArrayType);
        }

        [[nodiscard]] underlying_type rel(size_t offset, size_t remaining = 0) const noexcept {
            if (!has_result()) LIBHAT_UNLIKELY return nullptr;
            using rel32_t = int32_t;
            return result_ + read<rel32_t>(offset) + offset + sizeof(rel32_t) + remaining;
        }

        [[nodiscard]] bool has_result() const noexcept { return result_ != nullptr; }
        [[nodiscard]] explicit operator bool() const noexcept { return has_result(); }
        [[nodiscard]] underlying_type operator*() const noexcept { return result_; }
        [[nodiscard]] underlying_type get() const noexcept { return result_; }
        [[nodiscard]] auto operator<=>(const const_scan_result&) const noexcept = default;

    private:
        underlying_type result_;
    };

    using scan_result = const_scan_result;

    enum class scan_alignment : uint8_t {
        X1 = 0,
        X16 = 1,
    };

    enum class scan_hint : uint64_t {
        none   = 0,
        x86_64 = 1 << 0,
        pair0  = 1 << 1,
    };

    constexpr scan_hint operator|(scan_hint lhs, scan_hint rhs) {
        using U = std::underlying_type_t<scan_hint>;
        return static_cast<scan_hint>(static_cast<U>(lhs) | static_cast<U>(rhs));
    }

    constexpr scan_hint operator&(scan_hint lhs, scan_hint rhs) {
        using U = std::underlying_type_t<scan_hint>;
        return static_cast<scan_hint>(static_cast<U>(lhs) & static_cast<U>(rhs));
    }

    namespace detail {
        inline scan_alignment_t to_c_align(scan_alignment align) {
            return static_cast<scan_alignment_t>(align);
        }
    }

    inline const_scan_result find_pattern(
        const std::byte*        begin,
        const std::byte*        end,
        signature_view          sig,
        scan_alignment          alignment = scan_alignment::X1,
        scan_hint               /*hints*/ = scan_hint::none)
    {
        if (sig.empty()) return nullptr;

        std::vector<signature_element> tmp(sig.begin(), sig.end());
        signature_t c_sig;
        c_sig.data = tmp.data();
        c_sig.count = tmp.size();

        auto result = libhat_find_pattern(
            &c_sig,
            begin,
            static_cast<size_t>(end - begin),
            detail::to_c_align(alignment));

        return const_scan_result{static_cast<const std::byte*>(result)};
    }

    inline const_scan_result find_pattern(
        std::span<const std::byte> range,
        signature_view              sig,
        scan_alignment              alignment = scan_alignment::X1,
        scan_hint                   hints = scan_hint::none)
    {
        return find_pattern(range.data(), range.data() + range.size(), sig, alignment, hints);
    }
}
