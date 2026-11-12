#ifndef UART_LOG_H
#define UART_LOG_H

#include <stdint.h>

void uart_log_init(uint32_t baudrate);
void uart_log(const char *str);
void uart_log_uint(uint32_t val);
void uart_log_hex(uint32_t val);
void uart_log_float(float val);
void uart_putc(char c);

#endif
