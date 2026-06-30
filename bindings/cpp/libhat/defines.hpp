#pragma once

#if __cpp_if_consteval >= 202106L
    #define LIBHAT_IF_CONSTEVAL consteval
#else
    #include <type_traits>
    #define LIBHAT_IF_CONSTEVAL (std::is_constant_evaluated())
#endif

#if __has_cpp_attribute(likely)
    #define LIBHAT_LIKELY [[likely]]
#else
    #define LIBHAT_LIKELY
#endif

#if __has_cpp_attribute(unlikely)
    #define LIBHAT_UNLIKELY [[unlikely]]
#else
    #define LIBHAT_UNLIKELY
#endif

#if __cpp_lib_unreachable >= 202202L
    #define LIBHAT_UNREACHABLE() std::unreachable()
#elif defined(__GNUC__) || defined(__clang__)
    #define LIBHAT_UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
    #define LIBHAT_UNREACHABLE() __assume(false)
#else
    #include <cstdlib>
    namespace hat::detail {
        [[noreturn]] inline void unreachable_impl() noexcept { std::abort(); }
    }
    #define LIBHAT_UNREACHABLE() hat::detail::unreachable_impl()
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define LIBHAT_FORCEINLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
    #define LIBHAT_FORCEINLINE __forceinline
#else
    #define LIBHAT_FORCEINLINE inline
#endif

#if defined(__GNUC__) || defined(__clang__)
    #include <xmmintrin.h>
    #define LIBHAT_PREFETCH(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
#elif defined(_MSC_VER)
    #include <intrin.h>
    #define LIBHAT_PREFETCH(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
#else
    #define LIBHAT_PREFETCH(addr) ((void)0)
#endif
