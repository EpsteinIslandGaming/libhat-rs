#include <cstdio>
#include <cstring>
#include <bit>
#include <span>
#include <string_view>

#include <libhat.hpp>

int main() {
    {
        constexpr auto str = "abcdefghijklmnopqrstuvwxyz0123456789"sv;
        auto sig = hat::string_to_signature("xyz"sv);
        auto buf = std::as_bytes(std::span{str});

        auto result = hat::find_pattern(buf, sig.value());
        if (result) {
            auto offset = reinterpret_cast<const char*>(result.get()) - str.data();
            printf("Buffer: Found at %zu\n", offset);
        } else {
            printf("Buffer: Not found\n");
        }
    }

    {
        unsigned char data[] = { 0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01 };
        auto sig = hat::parse_signature("48 8D 05 ? ? ? ?");
        if (sig) {
            auto result = hat::find_pattern(
                reinterpret_cast<const std::byte*>(data),
                reinterpret_cast<const std::byte*>(data) + sizeof(data),
                *sig
            );
            if (result) {
                auto addr = result.rel(3);
                printf("Parsed sig: Found, RIP-relative address at %p\n",
                       static_cast<const void*>(addr));
            }
        }
    }

    return 0;
}
