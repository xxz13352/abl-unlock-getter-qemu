/*
 * start.S - boot stub for the bare-metal ABL getter harness.
 *
 * QEMU's -kernel loader enters at _start in EL1 with an identity-mapped
 * RAM view of the virt machine. We only need a stack before calling kmain.
 */
.section .text.boot
.global _start
_start:
    ldr x0, =_stack_top
    mov sp, x0
    bl kmain
1:
    wfi
    b 1b
