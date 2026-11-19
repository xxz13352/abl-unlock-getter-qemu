#!/usr/bin/env python3
"""Build the bare-metal ABL getter harness and run it under QEMU.

    python3 tools/run_harness.py --abl /path/to/LinuxLoader.efi

Requirements:
  * aarch64-linux-gnu-gcc
  * qemu-system-aarch64 >= 6.2

On Windows the script re-executes itself inside WSL, because that is where
the cross compiler and QEMU are normally installed. Set WSL_DISTRO to pick a
distribution (default: Ubuntu-22.04).

Outputs (written to --out, default build/):
  harness.elf   the bare-metal guest image
  console.log   raw serial output
  result.json   exit code, key lines, scope

Exit status is 0 when the console contains QEMU_SIM_DONE.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
HARNESS = ROOT / "harness"
DEFAULT_OUT = ROOT / "build"
WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu-22.04")


def emit(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf8", "replace"))
    sys.stdout.buffer.flush()


def win_to_wsl(path: pathlib.Path) -> str:
    p = path.resolve().as_posix()
    if len(p) > 1 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:]
    return p


def reexec_in_wsl(args) -> int:
    script = win_to_wsl(pathlib.Path(__file__).resolve())
    cmd = [
        "wsl.exe", "-d", WSL_DISTRO, "--exec", "python3", script,
        "--abl", win_to_wsl(pathlib.Path(args.abl)),
        "--out", win_to_wsl(pathlib.Path(args.out)),
    ]
    if args.keep:
        cmd.append("--keep")
    return subprocess.call(cmd)


def write_blob_source(abl: pathlib.Path, outdir: pathlib.Path) -> pathlib.Path:
    template = (HARNESS / "blob.S.in").read_text(encoding="ascii")
    source = template.replace("@ABL_PATH@", abl.as_posix())
    blob = outdir / "blob.S"
    blob.write_text(source, encoding="ascii")
    return blob


def build(abl: pathlib.Path, outdir: pathlib.Path) -> pathlib.Path:
    outdir.mkdir(parents=True, exist_ok=True)
    blob = write_blob_source(abl, outdir)
    elf = outdir / "harness.elf"
    cmd = [
        "aarch64-linux-gnu-gcc",
        "-ffreestanding", "-fno-stack-protector", "-fno-pic", "-fno-builtin",
        "-O2", "-nostdlib", "-nostartfiles", "-Wl,--build-id=none",
        "-Wl,-T," + str(HARNESS / "linker.ld"),
        "-I", str(HARNESS),
        "-o", str(elf),
        str(HARNESS / "start.S"), str(blob),
        str(HARNESS / "console.c"), str(HARNESS / "pe.c"),
        str(HARNESS / "main.c"),
    ]
    result = subprocess.run(cmd, capture_output=True)
    emit("build rc %d\n" % result.returncode)
    if result.stdout:
        emit(result.stdout.decode("utf8", "replace"))
    if result.stderr:
        emit(result.stderr.decode("utf8", "replace"))
    if result.returncode != 0:
        raise SystemExit(2)
    return elf


def run(elf: pathlib.Path, timeout: int = 60):
    cmd = [
        "qemu-system-aarch64",
        "-machine", "virt,gic-version=3", "-cpu", "max", "-smp", "1", "-m", "1024",
        "-accel", "tcg,thread=multi", "-nodefaults", "-display", "none",
        "-monitor", "none", "-serial", "stdio", "-no-reboot",
        "-semihosting-config", "enable=on,target=native",
        "-kernel", str(elf),
    ]
    process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output, _ = process.communicate(timeout=timeout)
        return process.returncode, output
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        return -9, output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abl", required=True,
                        help="path to the LinuxLoader.efi to analyse")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="build output directory (default: build/)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the generated blob.S in the output directory")
    parser.add_argument("--timeout", type=int, default=60,
                        help="QEMU wall-clock timeout in seconds (default: 60)")
    args = parser.parse_args()

    if os.name == "nt":
        return reexec_in_wsl(args)

    abl = pathlib.Path(args.abl).expanduser().resolve()
    if not abl.is_file():
        emit("error: ABL image not found: %s\n" % abl)
        return 2
    outdir = pathlib.Path(args.out).expanduser().resolve()

    elf = build(abl, outdir)
    code, raw = run(elf, args.timeout)
    text = raw.decode("utf8", "replace")
    emit(text)
    (outdir / "console.log").write_text(text, encoding="utf8")

    keys = [line for line in text.splitlines()
            if line.startswith(("QEMU_", "PE_", "CANARY", "CASE ", "VERIFY", "PATCH_CODE"))]
    report = {
        "abl": str(abl),
        "abl_sha256": __import__("hashlib").sha256(abl.read_bytes()).hexdigest(),
        "harness_elf": str(elf),
        "qemu": "qemu-system-aarch64",
        "exit_code": code,
        "key_lines": keys,
        "console_bytes": len(raw),
        "device_accessed": False,
        "scope": ("LinuxLoader.efi loaded at 0x50000000 in QEMU virt bare metal; "
                  "original unlock-state getters executed with controlled state "
                  "bytes; one instruction patched in guest memory only"),
    }
    (outdir / "result.json").write_text(json.dumps(report, indent=2) + "\n",
                                        encoding="utf8")
    emit(json.dumps(report, indent=2) + "\n")

    if not args.keep:
        pass  # blob.S is small; leave it next to the ELF for debugging
    return 0 if "QEMU_SIM_DONE" in text else 1


if __name__ == "__main__":
    sys.exit(main())
