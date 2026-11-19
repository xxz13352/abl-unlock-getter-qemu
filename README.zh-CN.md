# ABL 解锁状态 getter 的 QEMU 裸机实验台

把真实的 Qualcomm ABL `LinuxLoader.efi` 装进 QEMU `virt` 机器，用受控的状态字节直接调用它的解锁判定函数。

出发点是一个方法论问题：**“代码有缺口”和“实机可利用”是两件事。** 这个实验台只负责把第一件事执行出来、量出来。

## 实验内容

1. 在 `0x50000000` 装载真实 `LinuxLoader.efi`（PE32+），应用 DIR64 重定位；
2. 用 4 种 0/1 组合设置两个状态字节，分别调用 RVA `0x1e424` 的 unlock 包装函数和 RVA `0x1e44c` 的 critical 包装函数；
3. 把共享函数体里 RVA `0x1f764` 的 `cset w0, ne` 改成 `mov w0, #1`，再跑 `0/0` 组合。

harness 会先校验它依赖的 4 条指令，逐条打印 `VERIFY ... ok`；换一个 ABL 版本会直接以 `QEMU_ABL_HARNESS image_mismatch` 终止，而不是给出没有意义的数字。

## 结果

| temp | devinfo | unlock | critical |
| ---- | ------- | ------ | -------- |
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 |

4 字节补丁之后，`temp=0 / devinfo=0` 两个函数都返回 1。

原始输出：[`evidence/console.log`](evidence/console.log)、[`evidence/result.json`](evidence/result.json)。

## 证明了什么、没证明什么

证明：

- getter 在 `0x1f740` 的同一个函数体里把两个状态字节做 OR；
- 一条指令（`cset` → `mov`）就能让 unlock 与 critical 两个判定对任意输入恒返回 1。

没证明：

- **可注入性**：必须有一段在 getter 之前执行的代码去写 ABL 内存，本仓库不包含这样的原语；
- **持久性**：改写后的 `abl` 分区能否通过 Qualcomm PIL/PAS 认证，本实验不模拟；
- **用户态接受**：Android init / libfs_mgr 的门槛不在实验范围内；
- **对实机的任何效果**：补丁只存在于 QEMU 客户机内存，QEMU 退出即消失。

## 依赖

- `aarch64-linux-gnu-gcc`
- `qemu-system-aarch64` ≥ 6.2
- Python 3.8+
- `capstone`（仅 `tools/disasm_pe.py` 需要）

## 用法

```sh
python3 tools/run_harness.py --abl /path/to/LinuxLoader.efi
```

Windows 下脚本会自动在 WSL 里重新执行（`WSL_DISTRO`，默认 `Ubuntu-22.04`）。

产物写入 `build/`：`harness.elf`、`console.log`、`result.json`。成功标志是控制台出现 `QEMU_SIM_DONE`；semihosting `SYS_EXIT` 之后的 QEMU 进程退出码不能单独当成功信号。

先看镜像：

```sh
python3 tools/inspect_pe.py /path/to/LinuxLoader.efi
python3 tools/disasm_pe.py /path/to/LinuxLoader.efi --symbol 0x1f740 --count 20
```

## 不含固件

`LinuxLoader.efi` 是 Qualcomm/vivo 的专有固件。本仓库**不包含任何固件镜像，也不包含任何设备 dump**，请自备。

本仓库记录的这次运行针对 iQOO 13（PD2408，SM8750）的 ABL `16.1.15.3`，SHA-256 为 `52f5c6795ece1a4eccc30d2d41e0edb6a1ec3bf8f5f51a9130d8167c271c29b0`。上文所有 RVA 都只对该镜像族成立。

## 目录

```
harness/   裸机客户机：start.S、linker.ld、console.[ch]、pe.[ch]、main.c
tools/     run_harness.py（构建 + QEMU）、inspect_pe.py、disasm_pe.py
docs/      RESULT.zh-CN.md、RESULT.en.md——完整记录与边界
evidence/  本次运行的 console.log 与 result.json
```

## 说明

同一次判定结果在 fastboot 写入路径中的使用位置（RVA `0x6e7c8` 普通写入、`0x6f554` critical 写入）见 [`docs/RESULT.zh-CN.md`](docs/RESULT.zh-CN.md)。

## 使用范围

只在你拥有或获授权测试的设备上使用。harness 本身不攻击、不解锁、不修改任何东西：它只是在你自己机器的模拟器里执行你提供的固件镜像。

## 许可

harness 与工具采用 MIT 许可；固件镜像不随仓库分发，也不在许可范围内。
