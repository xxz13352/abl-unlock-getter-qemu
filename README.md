# ABL unlock-getter QEMU harness

A bare-metal AArch64 harness that loads a Qualcomm ABL `LinuxLoader.efi` into
QEMU's `virt` machine and executes its unlock-state getters against controlled
input bytes.

The point is methodological: **"the check has a defect" and "the defect is
exploitable on a device" are different claims.** This harness isolates and
executes only the first one.

## Experiment

1. Load a real `LinuxLoader.efi` (PE32+) at `0x50000000` and apply its DIR64
   relocations.
2. Call the unlock wrapper at RVA `0x1e424` and the critical-unlock wrapper at
   RVA `0x1e44c` with the two backing state bytes set to every 0/1
   combination.
3. Patch the shared instruction `cset w0, ne` at RVA `0x1f764` to
   `mov w0, #1` and run the `0/0` case again.

The harness fingerprints the four instructions it depends on and prints
`VERIFY ... ok` for each; on a different build it stops with
`QEMU_ABL_HARNESS image_mismatch` instead of producing meaningless numbers.

## Result

| temp | devinfo | unlock | critical |
| ---- | ------- | ------ | -------- |
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 |

After the 4-byte patch, `temp=0 / devinfo=0` returns 1 for both getters.

Captured output: [`evidence/console.log`](evidence/console.log),
[`evidence/result.json`](evidence/result.json).

## What this proves, and what it does not

Proves:

- the getter ORs the two state bytes in one shared body at `0x1f740`;
- a single instruction change (`cset` → `mov`) forces both the unlock and the
  critical-unlock answer to 1 for any input.

Does not prove:

- **injectability** — something must run before the getter and write ABL
  memory. This repository contains no such primitive;
- **persistence** — a modified `abl` partition must still pass Qualcomm
  PIL/PAS authentication, which this harness does not model;
- **userspace acceptance** — Android init/libfs_mgr gates are outside the
  experiment;
- **any effect on a device** — the patch lives in guest RAM and disappears
  with QEMU.

## Requirements

- `aarch64-linux-gnu-gcc`
- `qemu-system-aarch64` >= 6.2
- Python 3.8+
- `capstone` (only for `tools/disasm_pe.py`)

## Usage

```sh
python3 tools/run_harness.py --abl /path/to/LinuxLoader.efi
```

On Windows the script re-executes itself under WSL (`WSL_DISTRO`, default
`Ubuntu-22.04`) because that is where the cross compiler and QEMU normally
live.

Outputs go to `build/`: `harness.elf`, `console.log`, `result.json`. Success
is `QEMU_SIM_DONE` on the console; the QEMU process status after semihosting
`SYS_EXIT` is not a reliable success signal.

Inspect the image before running:

```sh
python3 tools/inspect_pe.py /path/to/LinuxLoader.efi
python3 tools/disasm_pe.py /path/to/LinuxLoader.efi --symbol 0x1f740 --count 20
```

## Firmware is not included

`LinuxLoader.efi` is proprietary Qualcomm/vivo firmware. This repository
contains **no firmware image and no device dump**. Supply your own copy.

The run this repository records was made against the ABL of an iQOO 13
(PD2408, SM8750) build `16.1.15.3`, SHA-256
`52f5c6795ece1a4eccc30d2d41e0edb6a1ec3bf8f5f51a9130d8167c271c29b0`.
All RVAs above are specific to that image family.

## Layout

```
harness/   bare-metal guest: start.S, linker.ld, console.[ch], pe.[ch], main.c
tools/     run_harness.py (build + QEMU), inspect_pe.py, disasm_pe.py
docs/      RESULT.en.md, RESULT.zh-CN.md - full write-up and boundaries
evidence/  console.log, result.json from the recorded run
```

## Literature

The RVAs and the fastboot gates that consume the same getters are described in
[`docs/RESULT.en.md`](docs/RESULT.en.md). In short: the normal flash path at
RVA `0x6e7c8` and the critical-partition path at `0x6f554` both branch on the
values this harness returns.

## Responsible use

Use only on devices you own or are authorised to test. The harness does not
attack, unlock or modify anything; it executes a firmware image you supply, in
an emulator, on your own machine.

## License

MIT for the harness and tools. Firmware images are not distributed and are not
covered by this license.
