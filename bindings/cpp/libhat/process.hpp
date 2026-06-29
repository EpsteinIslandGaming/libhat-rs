#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../../c/libhat.h"
#include "defines.hpp"
#include "export.hpp"
#include "memory.hpp"
#include "scanner.hpp"

LIBHAT_EXPORT namespace hat::process {

    class module {
    public:
        module() noexcept : baseAddress_(nullptr) {}

        [[nodiscard]] const std::byte* address() const noexcept {
            return baseAddress_;
        }

        [[nodiscard]] std::span<const std::byte> get_module_data() const;

        [[nodiscard]] std::span<const std::byte> get_section_data(std::string_view name) const;

        [[nodiscard]] auto operator<=>(const module&) const noexcept = default;

    private:
        friend module get_process_module();
        friend std::optional<module> get_module(std::string_view);
        friend std::optional<module> module_at(const void* address);

        explicit module(const void* base) noexcept : baseAddress_(static_cast<const std::byte*>(base)) {}

        const std::byte* baseAddress_;
    };

    inline module get_process_module() {
        auto* addr = libhat_get_module(nullptr);
        return module{addr};
    }

    inline std::optional<module> get_module(std::string_view name) {
        std::string tmp(name);
        auto* addr = libhat_get_module(tmp.c_str());
        if (!addr) return std::nullopt;
        return module{addr};
    }

    inline std::optional<module> module_at(const void* address) {
        auto* addr = libhat_module_at(address);
        if (!addr) return std::nullopt;
        return module{addr};
    }
}
