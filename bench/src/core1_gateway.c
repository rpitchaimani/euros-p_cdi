/* core1_gateway.c -- Core 1 (Z4b): zonal gateway + observers.
 * Waits for core 0, brings up ENET/lwIP and FlexCAN_0, then polls forever.
 * No detector output ever feeds back into forwarding or CAN traffic: the
 * impact event comes only from the target ECU (core 2) reacting to a write.
 */
#include "MPC5748G.h"
#include "shared_mem.h"
#include "lwip_port.h"
#include "can_drv.h"
#include "doip_gw.h"
#include "uart_log.h"
#include "stm_timer.h"

extern uint32_t __SBSS_C1_START[], __SBSS_C1_END[], __BSS_C1_START[], __BSS_C1_END[];

static void zero(uint32_t *a, uint32_t *b) { while (a < b) *a++ = 0u; }

int main(void)
{
    SHM_C1_STEP = 0xC1000001u;                 /* reached main */
    zero(__SBSS_C1_START, __SBSS_C1_END);
    zero(__BSS_C1_START, __BSS_C1_END);
    SHM_C1_STEP = 0xC1000002u;                 /* bss zeroed */

    while (SHM_C0_READY != SHM_CORE0_MAGIC) { __asm__ volatile("nop"); }

    uart_log("[C1] gateway core up\r\n");
    SHM_C1_STEP = 0xC1000003u;                 /* uart ok */
    lwip_init_port();
    SHM_C1_STEP = 0xC1000004u;                 /* lwip up */
    can_init();
    SHM_C1_STEP = 0xC1000005u;                 /* can up */
    gw_init();
    SHM_C1_STEP = 0xC1000006u;                 /* gateway up */

    MSYNC();
    SHM_C1_READY = SHM_CORE1_MAGIC;
    MSYNC();
    uart_log("[C1] gateway poll loop\r\n");

    for (;;) {
        lwip_poll();
        gw_poll();
    }
    return 0;
}
