#ifndef PE_H
#define PE_H
#include <stdint.h>
#include <stddef.h>
int pe_load(const uint8_t *blob, size_t len, uintptr_t base);
#endif
