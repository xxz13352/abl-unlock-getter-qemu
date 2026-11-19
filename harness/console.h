#ifndef CONSOLE_H
#define CONSOLE_H
#include <stdint.h>
void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
void kprintf(const char *fmt, ...);
void flush_icache_all(void);
#endif
