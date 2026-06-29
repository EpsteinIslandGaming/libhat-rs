#pragma once

#include <variant>

#include "export.hpp"

LIBHAT_EXPORT namespace hat {

    template<class E>
    class result_error {
        template<typename T, typename R>
        friend class result;
    public:
        constexpr explicit result_error(const E& t) noexcept(std::is_nothrow_copy_constructible_v<E>)
            : error(t) {}
        constexpr explicit result_error(E&& t) noexcept(std::is_nothrow_move_constructible_v<E>)
            : error(std::move(t)) {}
    private:
        E error;
    };

    template<class T, class E>
    class result {
        std::variant<T, E> impl;
    public:
        result(const T& t) noexcept(std::is_nothrow_constructible_v<std::variant<T, E>, const T&>)
            : impl(std::in_place_index<0>, t) {}
        result(T&& t) noexcept(std::is_nothrow_constructible_v<std::variant<T, E>, T&&>)
            : impl(std::in_place_index<0>, std::move(t)) {}
        result(const result_error<E>& e) noexcept(std::is_nothrow_constructible_v<std::variant<T, E>, const result_error<E>&>)
            : impl(std::in_place_index<1>, e.error) {}
        result(result_error<E>&& e) noexcept(std::is_nothrow_constructible_v<std::variant<T, E>, result_error<E>&&>)
            : impl(std::in_place_index<1>, std::move(e.error)) {}
        result(const result&) = default;
        result(result&&) = default;

        [[nodiscard]] bool has_value() const noexcept { return impl.index() == 0; }
        [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

        T& value() { return std::get<0>(impl); }
        const T& value() const { return std::get<0>(impl); }

        E& error() { return std::get<1>(impl); }
        const E& error() const { return std::get<1>(impl); }
    };
}
