#!/usr/bin/env python3
"""Dump PE headers, sections, relocations and getter fingerprints.

    python3 tools/inspect_pe.py /path/to/LinuxLoader.efi

The last block prints the four instructions the harness depends on using the
image-relative addresses of the 16.1.15.3 build. On a different build the
values will differ: treat them as fingerprints, not as a validity check.
"""
import struct
import sys
import pathlib


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: inspect_pe.py <LinuxLoader.efi>", file=sys.stderr)
        return 2
    path = pathlib.Path(argv[1])
    blob = path.read_bytes()
    if blob[:2] != b"MZ":
        print("not a PE image (missing MZ)", file=sys.stderr)
        return 1
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        print("not a PE image (missing PE signature)", file=sys.stderr)
        return 1
    coff = e_lfanew + 4
    machine, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", blob, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
    size_of_image = struct.unpack_from("<I", blob, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", blob, opt + 60)[0]
    nrva = struct.unpack_from("<I", blob, opt + 108)[0]
    reloc_rva, reloc_size = struct.unpack_from("<II", blob, opt + 112 + 5 * 8)
    print(f"file={path} bytes={len(blob)}")
    print(f"e_lfanew=0x{e_lfanew:x} machine=0x{machine:04x} nsections={nsections} "
          f"opt_size=0x{opt_size:x} magic=0x{magic:x}")
    print(f"image_base=0x{image_base:x} size_of_image=0x{size_of_image:x} "
          f"size_of_headers=0x{size_of_headers:x} nrva={nrva}")
    print(f"reloc_rva=0x{reloc_rva:x} reloc_size=0x{reloc_size:x}")

    sec = opt + opt_size
    total_reloc_entries = 0
    for i in range(nsections):
        off = sec + i * 40
        name = blob[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", blob, off + 8)
        chars = struct.unpack_from("<I", blob, off + 36)[0]
        print(f"  [{i}] {name:8s} VA=0x{va:08x} VSize=0x{vsize:08x} "
              f"RawPtr=0x{rawptr:08x} RawSize=0x{rawsize:08x} Chars=0x{chars:08x}")

    if reloc_size:
        end = reloc_rva + reloc_size
        p = reloc_rva
        counts = {}
        while p + 8 <= end:
            page, block = struct.unpack_from("<II", blob, p)
            if block < 8:
                break
            n = (block - 8) // 2
            for j in range(n):
                ent = struct.unpack_from("<H", blob, p + 8 + j * 2)[0]
                t = ent >> 12
                counts[t] = counts.get(t, 0) + 1
            total_reloc_entries += n
            p += block
        print(f"relocations: entries={total_reloc_entries} types={counts}")

    print("getter fingerprints (16.1.15.3 RVAs, bytes in file order):")
    for rva, want, label in (
        (0x1E424, "ff8300d1", "unlock wrapper    sub sp, sp, #0x20"),
        (0x1E44C, "ff8300d1", "critical wrapper  sub sp, sp, #0x20"),
        (0x1F740, "08210091", "getter body       add x8, x8, #8"),
        (0x1F764, "e0079f1a", "cset              cset w0, ne"),
    ):
        got = blob[rva:rva + 4].hex()
        mark = "match" if got == want else "differs"
        print(f"  file[0x{rva:x}]={got} expected={want} ({mark})  {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
