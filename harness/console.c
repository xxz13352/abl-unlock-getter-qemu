/*
 * console.c - PL011 UART output and cache maintenance for the harness.
 *
 * QEMU virt maps the PL011 at 0x09000000. Formatting is deliberately tiny:
 * %s %x %u %d %c %% only.
 */
#include "console.h"
#include <stdarg.h>

#define UART0 ((volatile uint32_t *)0x09000000u)

void uart_init(void)
{
    UART0[12] = 0;        /* CR: disable */
    UART0[9] = 13;        /* IBRD */
    UART0[10] = 1;        /* FBRD */
    UART0[11] = 0x70;     /* LCR_H: 8n1, FIFO */
    UART0[17] = 0x7ff;    /* ICR: clear */
    UART0[12] = 0x301;    /* CR: UARTEN|TXE|RXE */
}

void uart_putc(char c)
{
    if (c == '\n')
        uart_putc('\r');
    while (UART0[6] & (1u << 5)) { }
    UART0[0] = (uint8_t)c;
}

void uart_puts(const char *s)
{
    while (*s)
        uart_putc(*s++);
}

static void put_dec(uint64_t v)
{
    char buf[24];
    int n = 0;
    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v && n < (int)sizeof(buf)) {
        buf[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n--)
        uart_putc(buf[n]);
}

static void put_hex(uint64_t v)
{
    static const char *hex = "0123456789abcdef";
    char buf[20];
    int n = 0;
    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v && n < (int)sizeof(buf)) {
        buf[n++] = hex[v & 0xf];
        v >>= 4;
    }
    while (n--)
        uart_putc(buf[n]);
}

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            uart_putc(*p);
            continue;
        }
        p++;
        if (*p == 's') {
            const char *s = va_arg(ap, const char *);
            uart_puts(s ? s : "(null)");
        } else if (*p == 'x') {
            put_hex(va_arg(ap, uint64_t));
        } else if (*p == 'u') {
            put_dec(va_arg(ap, uint64_t));
        } else if (*p == 'd') {
            int64_t v = va_arg(ap, int64_t);
            if (v < 0) {
                uart_putc('-');
                v = -v;
            }
            put_dec((uint64_t)v);
        } else if (*p == 'c') {
            uart_putc((char)va_arg(ap, int));
        } else if (*p == '%') {
            uart_putc('%');
        } else {
            uart_putc('%');
            if (*p)
                uart_putc(*p);
        }
    }
    va_end(ap);
}

void flush_icache_all(void)
{
    asm volatile("dsb sy\n\t"
                 "ic iallu\n\t"
                 "dsb sy\n\t"
                 "isb\n\t" ::: "memory");
}
