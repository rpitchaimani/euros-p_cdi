/* startup_stubs.c
** C-runtime helpers called by startup_MPC5748G.S (SDK startup assembly).
**
** SystemInit    — hardware init hook (no-op; clocks done later in main()).
**
** init_data_bss — mirrors the SDK startup.c behaviour:
**   1. Copy INTC vector table from flash to SRAM.
**   2. Point INTC_IACKR_PRC0 (Core 0 interrupt acknowledge register) at the
**      SRAM copy so that any interrupt fired after wrteei 1 (in startup_MPC5748G.S)
**      dispatches to a valid handler, not to address 0 or a stale IACKR value.
**   3. Copy ROM-image sections to SRAM (.customSection, .data, .sdata, .code_ram).
**   4. Zero .sbss and .bss.
**
** Without step 1+2, a stale INTC pending flag (left by a previous debug session)
** fires as soon as wrteei 1 runs, IVOR4_Handler dereferences INTC_IACKR0 = 0,
** and Core 0 branches into zeroed SRAM — the se_illegal crash at 0x40052E7A.
*/

#include <stdint.h>

/* ── Linker symbols from MPC5748G_core0.ld ── */

/* INTC vector table: flash location and SRAM destination */
extern uint32_t __VECTOR_TABLE[];          /* flash: .intc_vector_table VMA */
extern uint32_t __VECTOR_RAM[];            /* SRAM:  .interrupts_ram VMA    */

/* ROM-image sections */
extern uint32_t __CUSTOM_ROM[];
extern uint32_t __CUSTOM_RAM[];
extern uint32_t __CUSTOM_END[];

extern uint32_t __DATA_ROM[];
extern uint32_t __DATA_RAM[];
extern uint32_t __DATA_END[];

extern uint32_t __SDATA_ROM[];
extern uint32_t __SDATA_RAM[];
extern uint32_t __SDATA_END[];

extern uint32_t __CODE_ROM[];
extern uint32_t __CODE_RAM[];
extern uint32_t __CODE_END[];

/* BSS regions */
extern uint32_t __SBSS_START[];
extern uint32_t __SBSS_END[];
extern uint32_t __BSS_START[];
extern uint32_t __BSS_END[];

/* ── MPC5748G INTC register ── */
/* INTC_IACKR_PRC0 (0xFC040020): Interrupt Acknowledge Register for Core 0.
   Upper bits hold the Vector Table Base Address (VTBA).  Writing this register
   sets where the INTC looks up ISR function pointers (one 32-bit pointer per
   interrupt source, laid out as an array starting at VTBA). */
#define INTC_IACKR0  (*(volatile uint32_t *)0xFC040020u)

/* Size of the INTC software vector table copied to SRAM (bytes).
   Must match __RAM_VECTOR_TABLE_SIZE in MPC5748G_core0.ld = 0xC00. */
#define INTC_VECTOR_TABLE_BYTES  0xC00u

/* ────────────────────────────────────────────────────────────── */

void SystemInit(void)
{
    /* intentionally empty — clock_init() in main.c handles PLL/divider setup */
}

void init_data_bss(void)
{
    uint32_t *src, *dst, *end;
    uint32_t  i;

    /* ── 1. Copy INTC vector table: flash → SRAM ──────────────
       interrupt_vectors.S places ISR pointers in .intc_vector_table (flash).
       The INTC hardware reads through INTC_IACKR0 to dispatch interrupts.
       We copy the table to SRAM first so INTC_IACKR0 points to valid entries. */
    {
        const uint8_t *vsrc = (const uint8_t *)__VECTOR_TABLE;
        uint8_t       *vdst = (uint8_t *)__VECTOR_RAM;
        for (i = 0u; i < INTC_VECTOR_TABLE_BYTES; i++) {
            vdst[i] = vsrc[i];
        }
    }

    /* ── 2. Set INTC_IACKR0 to SRAM vector table base ─────────
       startup_MPC5748G.S calls wrteei 1 immediately after returning here.
       Any interrupt pending in INTC (e.g., residual from a prior debug session)
       will fire as soon as EE=1; without this the handler dereferences address 0. */
    INTC_IACKR0 = (uint32_t)__VECTOR_RAM;

    /* ── 3. Copy ROM-image sections to SRAM ───────────────────
       Each loop: src = ROM LMA start, end = ROM LMA end, dst = SRAM VMA start. */

    /* .customSection */
    src = __CUSTOM_ROM; dst = __CUSTOM_RAM; end = __CUSTOM_END;
    while (src < end) { *dst++ = *src++; }

    /* .data */
    src = __DATA_ROM; dst = __DATA_RAM; end = __DATA_END;
    while (src < end) { *dst++ = *src++; }

    /* .sdata */
    src = __SDATA_ROM; dst = __SDATA_RAM; end = __SDATA_END;
    while (src < end) { *dst++ = *src++; }

    /* .code_ram */
    src = __CODE_ROM; dst = __CODE_RAM; end = __CODE_END;
    while (src < end) { *dst++ = *src++; }

    /* ── 4. Zero BSS regions ──────────────────────────────────
       PEMicro already zeroed all SRAM, but the standard C ABI requires this
       to be done here in case of warm resets or standalone use. */

    dst = __SBSS_START; end = __SBSS_END;
    while (dst < end) { *dst++ = 0u; }

    dst = __BSS_START; end = __BSS_END;
    while (dst < end) { *dst++ = 0u; }
}
