#!/usr/bin/env python3
"""Disassemble a range of an image-relative PE section.

    python3 tools/disasm_pe.py image.pe --start 0x120c0 --end 0x12130
    python3 tools/disasm_pe.py image.pe --symbol 0x11edc --count 40

Requires capstone (pip install capstone). Section mapping is by RVA, which is
correct for the PE images used here (section raw pointer == RVA); a file whose
layout differs will map wrongly, and the script says so when it cannot find a
containing section.
"""
import argparse
import pathlib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def sections_of(blob):
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    coff = e_lfanew + 4
    _, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", blob, coff)
    opt = coff + 20
    sec = opt + opt_size
    out = []
    for i in range(nsections):
        off = sec + i * 40
        name = blob[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", blob, off + 8)
        out.append((name, va, vsize, rawptr, rawsize))
    return out


def file_offset(sections, rva):
    for name, va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va)
    return None


def main(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="PE image to read")
    parser.add_argument("--start", help="start RVA, e.g. 0x120c0")
    parser.add_argument("--end", help="end RVA (exclusive)")
    parser.add_argument("--symbol", help="alias for --start")
    parser.add_argument("--count", type=int, default=0,
                        help="number of instructions (with --symbol)")
    args = parser.parse_args(argv[1:])

    blob = pathlib.Path(args.image).read_bytes()
    if blob[:2] != b"MZ":
        print("not a PE image", file=sys.stderr)
        return 1
    sections = sections_of(blob)

    start = args.start or args.symbol
    if not start:
        parser.error("need --start/--end or --symbol/--count")
    lo = int(start, 0)
    if args.end:
        hi = int(args.end, 0)
    elif args.count:
        hi = lo + args.count * 4
    else:
        hi = lo + 256

    off = file_offset(sections, lo)
    if off is None:
        print(f"no section contains RVA 0x{lo:x}", file=sys.stderr)
        return 1

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    code = blob[off:off + (hi - lo)]
    for insn in md.disasm(code, lo):
        note = ""
        if insn.mnemonic == "bl" and insn.operands and insn.operands[0].type == 2:
            target = insn.operands[0].imm
            inside = file_offset(sections, target) is not None
            note = f"  -> 0x{target:x} {'inside' if inside else 'OUTSIDE'}"
        if insn.mnemonic in ("blr", "br"):
            note = "  INDIRECT"
        print(f"0x{insn.address:06x}: {insn.bytes.hex():8s} "
              f"{insn.mnemonic:6s} {insn.op_str}{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
