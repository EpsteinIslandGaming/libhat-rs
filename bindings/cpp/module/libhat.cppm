module;

#include <version>

#ifndef LIBHAT_USE_STD_MODULE
    #include <algorithm>
    #include <cstddef>
    #include <cstdint>
    #include <cstring>
    #include <memory>
    #include <optional>
    #include <span>
    #include <string>
    #include <string_view>
    #include <type_traits>
    #include <utility>
    #include <variant>
    #include <vector>
#endif

export module libhat;

#ifdef LIBHAT_USE_STD_MODULE
    import std.compat;
#endif

extern "C++" {
#define LIBHAT_MODULE
#include "../libhat.hpp"
}
