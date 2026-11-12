/* uart_log.c — LINFlexD_2 UART, DEVKIT-MPC5748G
   OpenSDA USB-serial is wired to LINFlexD_2:
     PC8  MSCR[40]  = LIN2_TX  SSS=1 OBE SRC=3
     PC9  MSCR[41]  = LIN2_RX  IBE
     IMCR[202]      = LIN2_RX source PC9 SSS=2
   LINCLK = 80 MHz, 57600 baud
*/

#include "MPC5748G.h"
#include "uart_log.h"
#include <stdint.h>

static uint8_t g_first_tx = 1u;

void uart_log_init(uint32_t baudrate)
{
    uint32_t div = 80000000u / baudrate;
    uint32_t ibr = div / 16u;
    uint32_t fbr = div - (ibr * 16u);

    LINFlexD_2->LINCR1 |= LINFlexD_LINCR1_INIT_MASK;
    LINFlexD_2->LINCR1 &= ~LINFlexD_LINCR1_SLEEP_MASK;

    LINFlexD_2->UARTCR  = LINFlexD_UARTCR_UART_MASK;
    LINFlexD_2->UARTCR  = 0x0033u;

    LINFlexD_2->UARTSR  = LINFlexD_UARTSR_SZF_MASK |
                          LINFlexD_UARTSR_DRFRFE_MASK;

    LINFlexD_2->LINIBRR = ibr;
    LINFlexD_2->LINFBRR = fbr;

    LINFlexD_2->LINCR1 &= ~LINFlexD_LINCR1_INIT_MASK;

    SIUL2->MSCR[40] = SIUL2_MSCR_SRC(3u) |
                      SIUL2_MSCR_OBE_MASK |
                      SIUL2_MSCR_SSS(1u);

    SIUL2->MSCR[41] = SIUL2_MSCR_IBE_MASK;

    SIUL2->IMCR[202] = SIUL2_IMCR_SSS(2u);

    g_first_tx = 1u;
}

void uart_putc(char c)
{
    if (g_first_tx) {
        g_first_tx = 0u;
    } else {
        while ((LINFlexD_2->UARTSR & LINFlexD_UARTSR_DTFTFF_MASK) == 0u);
        LINFlexD_2->UARTSR = LINFlexD_UARTSR_DTFTFF_MASK;
    }
    LINFlexD_2->BDRL = LINFlexD_BDRL_DATA0((uint32_t)(uint8_t)c);
}

void uart_log(const char *str)
{
    if (!str) return;
    while (*str) { uart_putc(*str++); }
}

void uart_log_uint(uint32_t val)
{
    char    buf[12];
    uint8_t idx = 0u;
    if (val == 0u) { uart_putc('0'); return; }
    while (val > 0u) {
        buf[idx++] = (char)('0' + (val % 10u));
        val /= 10u;
    }
    while (idx > 0u) { idx--; uart_putc(buf[idx]); }
}

void uart_log_hex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    int8_t i;
    for (i = 28; i >= 0; i -= 4)
        uart_putc(hex[(val >> i) & 0xFu]);
}

void uart_log_float(float val)
{
    uint32_t int_part;
    uint32_t frac_int;

    if (val < 0.0f) { uart_putc('-'); val = -val; }
    int_part = (uint32_t)val;
    frac_int = (uint32_t)((val - (float)int_part) * 100.0f);

    uart_log_uint(int_part);
    uart_putc('.');
    if (frac_int < 10u) uart_putc('0');
    uart_log_uint(frac_int);
}
