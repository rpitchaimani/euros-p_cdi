/* stm_timer.h -- STM0 free-running counter, shared by all three cores.
 *
 * ChainRecon runs STM0 at 40 MHz (80 MHz input / 2): one tick is
 * 25 ns and the 32-bit counter wraps after ~107 s.  Per-event IDS costs are a
 * few microseconds, so the old 1 MHz rate would round most of them to zero.
 * All durations are unsigned differences (wrap-safe below 107 s).
 * Only core 0 calls stm0_init(); cores 1 and 2 only read the counter.
 * The host checks the tick rate against its own clock from the per-trial
 * sync beacons (python/analyze.py, clock fit).
 */
#ifndef STM_TIMER_H
#define STM_TIMER_H

#include <stdint.h>

#define STM0_BASE           0xFC068000u
#define STM0_CR_OFFSET      0x0000u
#define STM0_CNT_OFFSET     0x0004u

#ifndef STM_PRESCALER
/* Measured on the DEVKIT (7 Nov 2026): the STM input is 80 MHz with this
   clock_init (CPS=0 counted at 79.998 MHz).  CPS=1 divides by 2 -> 40 MHz. */
#define STM_PRESCALER       1u
#endif
#define STM_TICKS_PER_US    40u
#define STM_TICKS_PER_MS    40000u

static inline void stm0_init(void)
{
    volatile uint32_t *cr =
        (volatile uint32_t *)(STM0_BASE + STM0_CR_OFFSET);
    *cr = ((uint32_t)STM_PRESCALER << 8) | 0x00000001u;
}

static inline uint32_t stm0_get_count(void)
{
    return *((volatile uint32_t *)(STM0_BASE + STM0_CNT_OFFSET));
}

static inline void stm0_delay_ms(uint32_t ms)
{
    uint32_t start = stm0_get_count();
    uint32_t ticks = ms * STM_TICKS_PER_MS;
    while ((stm0_get_count() - start) < ticks) { }
}

#endif
