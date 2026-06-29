#include <stdio.h>
#include <string.h>
#include <libhat.h>

int main() {
    unsigned char buffer[] = {
        0x00, 0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01, 0xE8, 0x00
    };
    signature_t* sig = NULL;

    libhat_status_t status = libhat_parse_signature("48 8D 05 ? ? ? ? E8", &sig);
    if (status != libhat_success) {
        printf("Failed to parse signature\n");
        return 1;
    }

    const void* result = libhat_find_pattern(sig, buffer, sizeof(buffer), scan_alignment_x1);
    if (result) {
        size_t offset = (const unsigned char*)result - buffer;
        printf("Found at offset %zu\n", offset);
    } else {
        printf("Not found\n");
    }

    libhat_free(sig);
    return 0;
}
