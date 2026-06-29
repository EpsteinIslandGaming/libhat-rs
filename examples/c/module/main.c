#include <stdio.h>
#include <libhat.h>

int main() {
    const void* mod = libhat_get_module(NULL);
    if (!mod) {
        printf("Could not get process module\n");
        return 1;
    }
    printf("Process module at %p\n", mod);

    const void* mod_at = libhat_module_at(mod);
    if (mod_at) {
        printf("module_at confirms module at %p\n", mod_at);
    }

    signature_t* sig = NULL;
    libhat_status_t status = libhat_parse_signature("48 89 5C 24 ? 48 89 6C 24 ?", &sig);
    if (status != libhat_success) {
        printf("Failed to parse signature\n");
        return 1;
    }

    const void* result = libhat_find_pattern_mod(sig, mod, ".text", scan_alignment_x1);
    if (result) {
        printf("Found pattern in .text at %p\n", result);
    } else {
        printf("Pattern not found in .text\n");
    }

    libhat_free(sig);
    return 0;
}
