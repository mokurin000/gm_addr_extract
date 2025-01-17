#pragma once

/* Generated with cbindgen:0.28.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Extract RVA of a pointer to GlobalMetadata,
 *
 * using `libil2cpp.so` from current process.
 *
 * (use with zygisk hook, e.g.)
 */
uint64_t rva_from_current_process(void);

/**
 * Extract RVA of a pointer to GlobalMetadata,
 *
 * using `libil2cpp.so` from `file_path` (encoded as UTF-8).
 *
 * You can deallocate `file_path` after this call.
 *
 * `len` means bytes of the string (without the possible trailing null).
 *
 * SAFETY: you must pass a valid UTF-8 encoded string.
 */
uint64_t rva_from_path(const uint8_t *file_path, uintptr_t len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
