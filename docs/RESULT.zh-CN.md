# QEMU 攻击模拟：ABL 解锁状态 getter

本实验用 QEMU 以裸机 AArch64 方式装载真实 ABL `LinuxLoader.efi`，直接执行原厂
unlock / critical-unlock 判定函数，验证“内存打补丁伪装解锁”在机器码层是否成立。

**结论：判定函数可被一条 4 字节代码补丁翻转。** 两字节状态为 `0/0` 时原函数返回 0；
把临时状态字节或 devinfo 状态字节任一置 1，返回 1。把共享函数体里的
`cset w0, ne`（RVA `0x1f764`）改成 `mov w0, #1` 后，即使两字节全为 0，
unlock 与 critical 都恒返回 1。

该结果只证明**判定函数与补丁语义**，不证明补丁能跨重启保留，也不证明
PIL/PAS、TZ/SCM 或用户态门槛会接受。

## 输入与装载

| 项目 | 值 |
| --- | --- |
| 镜像 | `LinuxLoader.efi`（iQOO 13 / PD2408 / SM8750，ABL 16.1.15.3） |
| SHA-256 | `52f5c6795ece1a4eccc30d2d41e0edb6a1ec3bf8f5f51a9130d8167c271c29b0` |
| 文件大小 | 839680 字节 |
| ImageBase / SizeOfImage | `0x0` / `0xcd000` |
| 节 | `.text` VA `0x1000`、`.data` VA `0x99000`、`.reloc` VA `0xcc000` |
| 重定位 | 1139 条 DIR64，全部应用成功，0 条未知类型 |
| 装载基址 | `0x50000000`（QEMU virt RAM 0x40000000 起） |
| QEMU | `qemu-system-aarch64` 6.2.0 |
| 机器 | `-machine virt,gic-version=3 -cpu max -m 1024 -accel tcg,thread=multi` |

harness 通过生成的 `blob.S` 把 ABL PE 嵌入裸机 ELF，在 QEMU 内解析 DOS/PE 头、
复制节、应用 `IMAGE_REL_BASED_DIR64` 重定位，然后在 EL1 直接调用
`PE_BASE+0x1e424` 与 `PE_BASE+0x1e44c`。PL011（`0x09000000`）输出，
semihosting `SYS_EXIT` 结束。

## 方法

1. `tools/inspect_pe.py` 先确认 PE 布局与 4 条指纹指令；
2. harness 装载后再次逐条校验（`VERIFY ... ok`），不匹配即输出
   `QEMU_ABL_HARNESS image_mismatch` 并退出；
3. 对 4 种 `temp/devinfo` 组合分别调用两个包装函数；
4. 在客户机内存中把 `0x1f764` 的 `cset w0, ne`（`0x1a9f07e0`）改成
   `mov w0, #1`（`0x52800020`），刷新 I-cache，再跑 `0/0` 组合。

## 结果

原始 getter（`0x1e424` / `0x1e44c` → `0x1f740`）读取 `[base+0xbc374]`（temp）
与 `[base+0xbc385]`（devinfo）做 OR；critical 版本读 `0xbc375`/`0xbc386`：

| temp | devinfo | unlock 返回 | critical 返回 |
| --- | --- | --- | --- |
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 |

补丁后（`0x1f764: 0x1a9f07e0 → 0x52800020`），`temp=0/devinfo=0`：

| temp | devinfo | unlock 返回 | critical 返回 |
| --- | --- | --- | --- |
| 0 | 0 | 1 | 1 |

完整控制台输出见 `evidence/console.log`，结构化摘要见 `evidence/result.json`。

## 与 fastboot 写入门的关系

同一镜像里，两个 fastboot 写入判定直接消费这两个 getter：

- **普通写入路径** `0x6e7c8`：`bl 0x1e424` → `tst w0, #0xff` → `b.eq 0x6e814`。
  `0x6e814` 取 `0x77024` 的字符串 `"Flashing is not allowed in Lock State"`。
  即 getter 返回 0 才进入拒绝分支。
- **critical 分区路径** `0x6f554`：`bl 0x1e44c` → `tst w0, #0xff` → `b.eq 0x6f590`。
  返回非 0 时直接走 `0x6f560` → `0x739e4` 的写辅助；返回 0 时 `0x6f590`
  起扫描 `0xa3fc8` 的 24 项名称表（步长 8，共 `0xc0` 字节），名称命中则取
  `0x86dcc` 的 `"Flashing is not allowed for Critical Partitions"` 并拒绝，
  24 项都不命中则同样落到 `0x6f560` 的写路径。

也就是说，若 `0x1e424`/`0x1e44c` 能被强制返回 1，这两条写入判定都会走允许分支。
本实验执行的是 getter 本体，不是完整的 fastboot 命令处理；分支语义由同镜像反汇编给出。

## 边界

1. **只证明判定函数可被补丁翻转。** 真实启动链在 ABL 之前还有
   QcomBds → PILDxe → SCM/PAS 的 ABL 认证；持久改写 `abl` 分区能否被下一次
   启动接受，是独立问题，本实验没有证明。
2. **不证明补丁可注入。** 要在每次启动时改到 ABL 内存，需要一个在 ABL 判定
   之前执行的代码原语；本仓库不包含该原语。
3. **不证明用户态会接受。** Android init / libfs_mgr 的 vbmeta tuple、
   `veritymode`、`ro.boot.flash.locked` 等门槛不在本实验中；
   fake unlock 不等于 init_boot 校验自动关闭。
4. **QEMU virt 不是 Qualcomm 板。** 没有 UFS、TZ/SCM、PIL、RPMB、QSEE；
   本实验只执行 ABL 的纯计算判定路径，不模拟任何安全世界回复。
5. **补丁不持久。** 代码补丁只存在于 QEMU 内存，退出即消失；它不能替代
   GPT 改名 NoAuth0 这类落盘持久化。

## 复现

```sh
python3 tools/inspect_pe.py /path/to/LinuxLoader.efi
python3 tools/run_harness.py --abl /path/to/LinuxLoader.efi
```

构建与运行由 `tools/run_harness.py` 完成：生成 `build/blob.S`，用
`aarch64-linux-gnu-gcc` 链接 `harness/` 下的源文件，再以
`qemu-system-aarch64 -kernel` 运行。Windows 下脚本会自动转交 WSL 执行。

本实验未访问实机，未修改任何原镜像。
