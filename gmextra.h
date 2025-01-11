#pragma once

/* Generated with cbindgen:0.27.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

uint64_t rva_from_current_process(void);

uint64_t rva_from_path(const uint8_t *file_path, uintptr_t len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
