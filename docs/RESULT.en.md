# QEMU attack simulation: ABL unlock-state getters

This experiment loads a real ABL `LinuxLoader.efi` as a bare-metal AArch64
guest under QEMU and executes the original unlock / critical-unlock predicates
directly, in order to test at the machine-code level whether "patch ABL memory
to fake an unlocked bootloader" is even a coherent primitive.

**Result: yes at the getter level, with a single 4-byte code patch.** With both
backing state bytes `0/0` the original functions return 0; setting either the
transient byte or the devinfo byte to 1 makes them return 1. Replacing the
shared `cset w0, ne` (RVA `0x1f764`) with `mov w0, #1` makes both predicates
return 1 for any input, including `0/0`.

This proves getter semantics and patch semantics only. It does **not** prove
that the patch can be injected, that a modified `abl` partition survives
Qualcomm PIL/PAS authentication, or that Android userspace would accept the
resulting state.

## Input and loading

| Item | Value |
| --- | --- |
| Image | `LinuxLoader.efi` (iQOO 13 / PD2408 / SM8750, ABL 16.1.15.3) |
| SHA-256 | `52f5c6795ece1a4eccc30d2d41e0edb6a1ec3bf8f5f51a9130d8167c271c29b0` |
| File size | 839,680 bytes |
| ImageBase / SizeOfImage | `0x0` / `0xcd000` |
| Sections | `.text` VA `0x1000`, `.data` VA `0x99000`, `.reloc` VA `0xcc000` |
| Relocations | 1,139 DIR64 entries, all applied, 0 unknown types |
| Load base | `0x50000000` (QEMU virt RAM starts at `0x40000000`) |
| QEMU | `qemu-system-aarch64` 6.2.0 |
| Machine | `-machine virt,gic-version=3 -cpu max -m 1024 -accel tcg,thread=multi` |

`tools/run_harness.py` generates a `blob.S` that `.incbin`s the PE into the
bare-metal ELF. The harness parses the DOS/PE headers, copies the sections,
applies `IMAGE_REL_BASED_DIR64` relocations, and then calls
`PE_BASE+0x1e424` and `PE_BASE+0x1e44c` directly in EL1. Output goes to the
PL011 at `0x09000000`; the run ends with a semihosting `SYS_EXIT`.

## Method

1. `tools/inspect_pe.py` checks the PE layout and the four fingerprint
   instructions before anything runs.
2. After loading, the harness re-checks them and prints `VERIFY ... ok` for
   each; on any mismatch it prints `QEMU_ABL_HARNESS image_mismatch` and stops
   rather than reporting meaningless numbers.
3. For each of the four `temp/devinfo` combinations, call both wrappers.
4. Patch `0x1f764` from `cset w0, ne` (`0x1a9f07e0`) to `mov w0, #1`
   (`0x52800020`) in guest memory, flush the I-cache, and re-run `0/0`.

## Results

The original getters (`0x1e424` / `0x1e44c` → shared body `0x1f740`) OR
`[base+0xbc374]` (temp) with `[base+0xbc385]` (devinfo); the critical variants
read `0xbc375` / `0xbc386`:

| temp | devinfo | unlock | critical |
| --- | --- | --- | --- |
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 |

After the patch (`0x1f764: 0x1a9f07e0 → 0x52800020`), `temp=0/devinfo=0`
returns 1 for both.

Raw console output: `evidence/console.log`. Structured summary:
`evidence/result.json`.

## Relation to the fastboot write gates

Two fastboot write checks in the same image consume these getters:

- **Normal write path**, `0x6e7c8`: `bl 0x1e424` → `tst w0, #0xff` →
  `b.eq 0x6e814`; `0x6e814` loads the string at `0x77024`,
  `"Flashing is not allowed in Lock State"`. Only a 0 result takes the reject
  branch.
- **Critical-partition path**, `0x6f554`: `bl 0x1e44c` → `tst w0, #0xff` →
  `b.eq 0x6f590`. A non-zero result goes straight to `0x6f560` → `0x739e4`,
  the write helper. A zero result scans a 24-entry name table at `0xa3fc8`
  (stride 8, total `0xc0` bytes); a name match loads
  `"Flashing is not allowed for Critical Partitions"` from `0x86dcc` and
  rejects, while no match also falls through to `0x6f560`.

So if `0x1e424` / `0x1e44c` could be forced to return 1, both gates would take
their allow branches. What this experiment executes is the getter itself, not
full fastboot command handling; the branch semantics come from disassembly of
the same image.

## Boundaries

1. **Only the predicate is shown patchable.** The real boot chain has
   QcomBds → PILDxe → SCM/PAS authentication before ABL. Whether a persistently
   modified `abl` partition is accepted on the next boot is a separate question
   this experiment does not answer.
2. **Injectability is not shown.** Modifying ABL memory on every boot requires
   a code primitive that runs before the predicate. This repository contains
   no such primitive.
3. **Userspace acceptance is not shown.** Android init / libfs_mgr gates
   (vbmeta tuple, `veritymode`, `ro.boot.flash.locked`) are outside the
   experiment; faking unlock does not by itself disable init_boot verification.
4. **QEMU virt is not a Qualcomm board.** There is no UFS, TZ/SCM, PIL, RPMB or
   QSEE; only ABL's pure computation path is executed and no secure-world
   response is simulated.
5. **The patch is not persistent.** It exists in guest RAM and disappears when
   QEMU exits; it is not a substitute for an on-disk persistence scheme.

## Reproducing

```sh
python3 tools/inspect_pe.py /path/to/LinuxLoader.efi
python3 tools/run_harness.py --abl /path/to/LinuxLoader.efi
```

`tools/run_harness.py` writes `build/blob.S`, links the sources in `harness/`
with `aarch64-linux-gnu-gcc`, and runs the result with
`qemu-system-aarch64 -kernel`. On Windows it hands the run to WSL.

No device was accessed and no original image was modified.
