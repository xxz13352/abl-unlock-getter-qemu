/*
 * pe.c - minimal PE32+ image loader.
 *
 * Copies headers and sections to the requested base, applies IMAGE_REL_BASED_
 * DIR64 (10) and HIGHLOW (3) relocations, and leaves the image callable.
 * Enough for LinuxLoader.efi; not a general-purpose PE loader.
 */
#include "pe.h"
#include "console.h"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static void copy_bytes(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

static void zero_bytes(void *dst, uint64_t n)
{
    uint8_t *d = dst;
    for (uint64_t i = 0; i < n; i++)
        d[i] = 0;
}

int pe_load(const uint8_t *blob, size_t len, uintptr_t base)
{
    if (len < 0x40 || blob[0] != 'M' || blob[1] != 'Z') {
        kprintf("PE_ERR no_mz\n");
        return -1;
    }
    uint32_t e_lfanew = rd32(blob + 0x3c);
    if (e_lfanew + 0x18 > len || rd32(blob + e_lfanew) != 0x00004550u) {
        kprintf("PE_ERR no_pe\n");
        return -2;
    }
    uint32_t coff = e_lfanew + 4;
    uint16_t machine = rd16(blob + coff);
    uint16_t nsections = rd16(blob + coff + 2);
    uint16_t opt_size = rd16(blob + coff + 16);
    uint32_t opt = coff + 20;
    if (opt + opt_size > len || rd16(blob + opt) != 0x20b) {
        kprintf("PE_ERR bad_opt machine=0x%x\n", machine);
        return -3;
    }
    uint64_t image_base = rd64(blob + opt + 24);
    uint32_t size_of_image = rd32(blob + opt + 56);
    uint32_t size_of_headers = rd32(blob + opt + 60);
    if (size_of_headers > len || size_of_headers > size_of_image) {
        kprintf("PE_ERR headers\n");
        return -4;
    }
    copy_bytes((void *)base, blob, size_of_headers);
    zero_bytes((void *)(base + size_of_headers), size_of_image - size_of_headers);

    uint32_t sec = opt + opt_size;
    for (uint16_t i = 0; i < nsections; i++) {
        uint32_t sh = sec + (uint32_t)i * 40;
        if (sh + 40 > len) {
            kprintf("PE_ERR section_table\n");
            return -5;
        }
        uint32_t vsize = rd32(blob + sh + 8);
        uint32_t va = rd32(blob + sh + 12);
        uint32_t rawsize = rd32(blob + sh + 16);
        uint32_t rawptr = rd32(blob + sh + 20);
        if (va + vsize > size_of_image) {
            kprintf("PE_ERR section_range\n");
            return -6;
        }
        if (rawsize) {
            if ((uint64_t)rawptr + rawsize > len)
                return -7;
            copy_bytes((void *)(base + va), blob + rawptr, rawsize);
        }
        if (vsize > rawsize)
            zero_bytes((void *)(base + va + rawsize), vsize - rawsize);
    }

    uint32_t nrva = rd32(blob + opt + 108);
    uint32_t reloc_rva = 0, reloc_size = 0;
    if (nrva > 5) {
        reloc_rva = rd32(blob + opt + 112 + 5 * 8);
        reloc_size = rd32(blob + opt + 112 + 5 * 8 + 4);
    }
    uintptr_t delta = base - (uintptr_t)image_base;
    uint32_t applied = 0, unknown = 0;
    if (reloc_rva && reloc_size && reloc_rva + reloc_size <= size_of_image) {
        uint32_t p = reloc_rva;
        uint32_t end = reloc_rva + reloc_size;
        while (p + 8 <= end) {
            uint32_t page = rd32((const uint8_t *)(base + p));
            uint32_t block = rd32((const uint8_t *)(base + p + 4));
            if (block < 8 || p + block > end)
                break;
            uint32_t n = (block - 8) / 2;
            for (uint32_t j = 0; j < n; j++) {
                uint16_t ent = rd16((const uint8_t *)(base + p + 8 + j * 2));
                uint32_t type = ent >> 12;
                uint32_t off = ent & 0xfff;
                uintptr_t addr = base + page + off;
                if (type == 10) {
                    *(volatile uint64_t *)addr += delta;
                    applied++;
                } else if (type == 3) {
                    *(volatile uint32_t *)addr += (uint32_t)delta;
                    applied++;
                } else if (type != 0) {
                    unknown++;
                }
            }
            p += block;
        }
    }
    flush_icache_all();
    kprintf("PE_LOAD base=0x%x image_base=0x%x image_size=0x%x sections=%u relocs_applied=%u relocs_unknown=%u\n",
            (uint64_t)base, image_base, (uint64_t)size_of_image, (uint64_t)nsections,
            (uint64_t)applied, (uint64_t)unknown);
    return unknown ? -8 : 0;
}
