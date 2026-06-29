#pragma once

#include <stddef.h>

#ifdef _WIN32
    #if defined(LIBHAT_BUILD_SHARED)
        #define LIBHAT_API __declspec(dllexport)
    #elif defined(LIBHAT_USE_SHARED)
        #define LIBHAT_API __declspec(dllimport)
    #else
        #define LIBHAT_API
    #endif
#else
    #if defined(LIBHAT_BUILD_SHARED)
        #define LIBHAT_API __attribute__((visibility("default")))
    #else
        #define LIBHAT_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum libhat_status_t {
    libhat_success = 0,
    libhat_err_unknown = 1,
    libhat_err_sig_invalid = 2,
    libhat_err_sig_empty = 3,
    libhat_err_sig_no_byte = 4,
} libhat_status_t;

typedef enum scan_alignment {
    scan_alignment_x1 = 0,
    scan_alignment_x16 = 1,
} scan_alignment_t;

typedef struct signature {
    void* data;
    size_t count;
} signature_t;

LIBHAT_API libhat_status_t libhat_parse_signature(
    const char*   signatureStr,
    signature_t** signatureOut
);

LIBHAT_API libhat_status_t libhat_create_signature(
    const char*   bytes,
    const char*   mask,
    size_t        size,
    signature_t** signatureOut
);

LIBHAT_API const void* libhat_find_pattern(
    const signature_t*  signature,
    const void*         buffer,
    size_t              size,
    scan_alignment_t    align
);

LIBHAT_API const void* libhat_find_pattern_mod(
    const signature_t*  signature,
    const void*         module,
    const char*         section,
    scan_alignment_t    align
);

LIBHAT_API const void* libhat_module_at(const void* address);

LIBHAT_API const void* libhat_get_module(const char* name);

LIBHAT_API void libhat_free(void* mem);

#ifdef __cplusplus
}
#endif
