/* main.c -- ChainRecon bench, Core 0 (Z4a)
 *
 * Boot order:
 *   1. clocks, UART (boot messages only), STM0 at 40 MHz
 *   2. zero the shared SRAM contract (ECC init), write layout version
 *   3. SJA1105Q: upload the static configuration once (VLANs and mirroring
 *      are part of it, MIRR_PTACU = 0, so nothing changes during a run)
 *   4. release core 1 (gateway + observers), wait until it is ready
 *   5. release core 2 (target ECU), wait until it is ready
 *   6. run the IDS forever (ids_core0.c); no UART after this point
 *
 * Core start registers follow an earlier build that ran on this DEVKIT
 * (CCTL2/CADDR2 for Z4b, CCTL3/CADDR3 for Z2).  Under the S32DS multicore
 * debug launch the debugger also starts each core at its entry stub.
 */
#include "MPC5748G.h"
#include "shared_mem.h"
#include "sja1105_spi.h"
#include "sja1105_config.h"
#include "ids_core0.h"
#include "stm_timer.h"
#include "uart_log.h"
#include "clock_init.h"
#include <stdint.h>

#define CORE1_START_ADDR  0x011D0000u   /* MPC5748G_core1.ld m_text */
#define CORE2_START_ADDR  0x013A0000u   /* MPC5748G_core2.ld m_text */

/* Off by default: sja1105_spi_init() has never run in a working build (DSPI_0
   clock gate and SCK/SOUT/SIN pin mux are not set up), and a bus error here
   would stop the boot before cores 1 and 2 are released.  Bring the bench up
   first, then enable with -DSJA_BOOT_CONFIG=1 or load the config via the EVB. */
#ifndef SJA_BOOT_CONFIG
#define SJA_BOOT_CONFIG   0
#endif

static void shared_sram_init(void)
{
    volatile uint32_t *p = (volatile uint32_t *)SHARED_BASE;
    uint32_t i, words = SHARED_SIZE / 4u;
    for (i = 0u; i < words; i++) p[i] = 0u;
    MSYNC();
}

static void mode_transition(void)
{
    uint32_t mode = MC_ME->MCTL & 0xFFFF0000u;
    MC_ME->MCTL = mode | 0x5AF0u;
    MC_ME->MCTL = mode | 0xA50Fu;
    while (MC_ME->GS & MC_ME_GS_S_MTRANS_MASK) { }
}

/* CADDRn bit 0 = RMC: reset the core and start it at ADDR on the next mode
   transition.  Without RMC the core stays halted unless a debugger starts it
   (an earlier build relied on the debugger launch group for this). */
static void start_core1(void)      /* Z4b: MC_ME core 2 */
{
    MC_ME->CCTL2  = 0x00FEu;
    MC_ME->CADDR2 = CORE1_START_ADDR | MC_ME_CADDR2_RMC_MASK;
    mode_transition();
}

static void start_core2(void)      /* Z2: MC_ME core 3 */
{
    MC_ME->CCTL3  = 0x00FEu;
    MC_ME->CADDR3 = CORE2_START_ADDR | MC_ME_CADDR3_RMC_MASK;
    mode_transition();
}

static void wait_magic(volatile uint32_t *flag, uint32_t magic, const char *who)
{
    uint32_t t0 = stm0_get_count();
    while (*flag != magic) {
        if ((stm0_get_count() - t0) > 30000u * STM_TICKS_PER_MS) {
            uart_log("[MAIN] timeout waiting for ");
            uart_log(who);
            uart_log("\r\n[DIAG] C1_STEP=0x"); uart_log_hex(SHM_C1_STEP);
            uart_log(" C2_STEP=0x");          uart_log_hex(SHM_C2_STEP);
            uart_log("\r\n[DIAG] MC_ME CS=0x"); uart_log_hex(MC_ME->CS);
            uart_log(" GS=0x");               uart_log_hex(MC_ME->GS);
            uart_log(" MCTL=0x");             uart_log_hex(MC_ME->MCTL);
            uart_log("\r\n[DIAG] CCTL2=0x");  uart_log_hex(MC_ME->CCTL2);
            uart_log(" CADDR2=0x");           uart_log_hex(MC_ME->CADDR2);
            uart_log(" CCTL3=0x");            uart_log_hex(MC_ME->CCTL3);
            uart_log(" CADDR3=0x");           uart_log_hex(MC_ME->CADDR3);
            uart_log("\r\n");
            return;
        }
    }
    uart_log("[MAIN] ");
    uart_log(who);
    uart_log(" ready\r\n");
}

int main(void)
{
    clock_init();
    uart_log_init(57600u);
    uart_log("\r\n[MAIN] ChainRecon bench, core 0 (IDS)\r\n");
    stm0_init();

    shared_sram_init();
    SHM_LAYOUT_VER = SHM_LAYOUT_VERSION;
    SHM_CFG_U_PPM  = 1000000u;
    SHM_CFG_Q_CAP  = 1024u;
    SHM_CFG_IMPACT_MS = 5u;
    SHM_CFG_OBS_MASK  = 0u;     /* nothing delivered until the first START */

#if SJA_BOOT_CONFIG
    uart_log("[MAIN] SJA1105Q static config upload\r\n");
    sja1105_spi_init();
    sja1105_upload_config(sja1105_static_config, SJA1105_CONFIG_SIZE);
    if (!sja1105_verify_device())
        uart_log("[MAIN] WARNING: SJA1105Q device ID not read back\r\n");
#endif

    MSYNC();
    SHM_C0_READY = SHM_CORE0_MAGIC;
    MSYNC();

    start_core1();
    wait_magic(&SHM_C1_READY, SHM_CORE1_MAGIC, "core 1 (gateway)");
    start_core2();
    wait_magic(&SHM_C2_READY, SHM_CORE2_MAGIC, "core 2 (target)");

    uart_log("[MAIN] IDS running; UART silent from here\r\n");
    ids_init();
    for (;;) ids_poll();
    return 0;
}
