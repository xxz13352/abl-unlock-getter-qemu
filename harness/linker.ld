/*
 * Link the harness at the start of QEMU virt RAM (0x40000000) and put the
 * stack at 0x40200000, well clear of the loaded image.
 */
OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS
{
    . = 0x40080000;
    .text : { *(.text.boot) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    . = ALIGN(16);
    _image_end = .;
    _stack_top = 0x40200000;
}
