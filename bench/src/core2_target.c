/* core2_target.c -- Core 2 (Z2): two emulated target ECUs in the destination zone.
 *
 * Bench limitation (state it in the paper): the DEVKIT has one CAN
 * transceiver, so the targets share FlexCAN_0 with the gateway.  They receive
 * requests only after the controller has read them back from the bus
 * (self-reception, see can_drv.c), and their frames are queued to core 1,
 * which puts them on the bus.
 *
 *   ECU A: TA 0x0010, request 0x7E0, response 0x7E8
 *   ECU B: TA 0x0011, request 0x7E1, response 0x7E9
 * Both drive one shared actuator message 0x1A0 [value, counter, src, 0...]:
 *   counter = one impact counter shared by both ECUs,
 *   src     = 1 (A) / 2 (B) only if the trial sets CFGF_IMPACT_SRC, else 0.
 * After a write to DID F1A0 the ECU emits the impact after
 *   CFG_IMPACT_MS + uniform[0, CFG_JITTER_MS] ms   (PRNG seeded per trial),
 * so with two writers the impacts can come out in a different order from the
 * writes.  Which ECU produced which impact is logged in SHM_IMPLOG, which no
 * observer reads (ground truth only).
 *
 * UDS subset per ECU (single-frame ISO-TP):
 *   0x10 xx  -> 50 xx 00 32 01 F4        0x3E 00 -> 7E 00
 *   0x27 01  -> 67 01 sH sL              0x27 02 key(seed^5A5A) -> 67 02 | 7F 27 35
 *   0x22 F1A0 -> 62 F1 A0 vv
 *   0x2E F1A0 vv -> 6E F1 A0 (needs extended session 0x03, NOT security access:
 *                the test-harness weakness the chain uses)
 *   0x2E other DID -> needs security access, else 7F 2E 33
 *   anything else -> 7F sid 11
 * Core 2 is an e200z2: no FPU, no floats here.
 */
#include "shared_mem.h"
#include "bench.h"
#include "stm_timer.h"
#include <string.h>

extern uint32_t __SBSS_C2_START[], __SBSS_C2_END[], __BSS_CORE2_START[], __BSS_CORE2_END[];

typedef struct {
    uint8_t  id;             /* 1 = A, 2 = B */
    uint32_t resp_id;
    uint8_t  dsess, unlocked, state;
    uint16_t seed;
} ecu_t;

#define PEND_IMPACTS 8u
typedef struct {
    uint8_t  used, ecu, value;
    uint32_t t_due_from, delay_ticks;
} pimp_t;

static ecu_t    g_ecu[N_TARGETS];
static pimp_t   g_pimp[PEND_IMPACTS];
static uint8_t  g_impact_cnt;
static uint32_t g_seen_trial, g_rng;

static void zero(uint32_t *a, uint32_t *b) { while (a < b) *a++ = 0u; }

static uint32_t rnd(void)                     /* xorshift32 */
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
    return g_rng;
}

static void send(uint32_t id, const uint8_t *d, uint8_t n)
{
    uint32_t prod = SHM_FQ_PROD, next = (prod + 1u) % CANQ_SLOTS;
    uint8_t i;
    if (next == SHM_FQ_CONS) { SHM_C2_TXQ_FULL++; return; }
    SHM_FQ[prod].id  = id;
    SHM_FQ[prod].dlc = 8u;
    for (i = 0u; i < 8u; i++) SHM_FQ[prod].data[i] = (i < n) ? d[i] : 0xCCu;
    MSYNC();
    SHM_FQ_PROD = next;
    SHM_C2_TX++;
}

static void reply(const ecu_t *e, const uint8_t *uds, uint8_t n)
{
    uint8_t f[8];
    f[0] = n;
    memcpy(&f[1], uds, n);
    send(e->resp_id, f, (uint8_t)(n + 1u));
}

static void nrc(const ecu_t *e, uint8_t sid, uint8_t code)
{
    uint8_t r[3];
    r[0] = UDS_NEG; r[1] = sid; r[2] = code;
    reply(e, r, 3u);
}

static void reset_targets(void)
{
    uint32_t i;
    memset(g_ecu, 0, sizeof(g_ecu));
    memset(g_pimp, 0, sizeof(g_pimp));
    for (i = 0u; i < N_TARGETS; i++) {
        g_ecu[i].id = (uint8_t)(i + 1u);
        g_ecu[i].resp_id = (i == 0u) ? CANID_DIAG_RESP : CANID_DIAG_RESP_B;
        g_ecu[i].dsess = 1u;
    }
    g_impact_cnt = 0u;
    g_rng = SHM_CFG_SEED ? SHM_CFG_SEED : 0x2545F491u;
    SHM_C2_STATE = 0u; SHM_C2_IMPACTS = 0u; SHM_C2_RX = 0u; SHM_C2_TX = 0u;
    SHM_C2_TXQ_FULL = 0u;
    SHM_IMPLOG_N = 0u;
}

static void schedule_impact(const ecu_t *e)
{
    uint32_t i, jit = SHM_CFG_JITTER_MS;
    for (i = 0u; i < PEND_IMPACTS; i++) {
        if (!g_pimp[i].used) {
            uint32_t extra = jit ? (rnd() % (jit * STM_TICKS_PER_MS + 1u)) : 0u;
            g_pimp[i].used = 1u;
            g_pimp[i].ecu = e->id;
            g_pimp[i].value = e->state;
            g_pimp[i].t_due_from = stm0_get_count();
            g_pimp[i].delay_ticks = SHM_CFG_IMPACT_MS * STM_TICKS_PER_MS + extra;
            return;
        }
    }
}

static void handle(ecu_t *e, const uint8_t *f)
{
    uint8_t n = (uint8_t)(f[0] & 0x0Fu);
    const uint8_t *u = &f[1];
    uint8_t r[7];
    if ((f[0] & 0xF0u) != 0u || n == 0u || n > 7u) return;   /* SF only */

    switch (u[0]) {
    case UDS_DSC:
        if (n < 2u) { nrc(e, u[0], 0x13u); return; }
        e->dsess = u[1];
        if (e->dsess != 0x03u) e->unlocked = 0u;
        r[0] = 0x50u; r[1] = u[1]; r[2] = 0x00u; r[3] = 0x32u; r[4] = 0x01u; r[5] = 0xF4u;
        reply(e, r, 6u);
        return;
    case UDS_TP:
        r[0] = 0x7Eu; r[1] = 0x00u; reply(e, r, 2u); return;
    case UDS_SA:
        if (n < 2u) { nrc(e, u[0], 0x13u); return; }
        if (e->dsess != 0x03u) { nrc(e, u[0], 0x7Fu); return; }
        if (u[1] == 0x01u) {
            e->seed = (uint16_t)(stm0_get_count() >> 4);
            if (e->seed == 0u) e->seed = 0x1234u;
            r[0] = 0x67u; r[1] = 0x01u; r[2] = (uint8_t)(e->seed >> 8); r[3] = (uint8_t)e->seed;
            reply(e, r, 4u); return;
        }
        if (u[1] == 0x02u && n >= 4u) {
            uint16_t key = (uint16_t)((u[2] << 8) | u[3]);
            if (key == (uint16_t)(e->seed ^ SA_KEY_XOR)) {
                e->unlocked = 1u; r[0] = 0x67u; r[1] = 0x02u; reply(e, r, 2u);
            } else nrc(e, u[0], 0x35u);
            return;
        }
        nrc(e, u[0], 0x12u); return;
    case UDS_RDBI:
        if (n < 3u) { nrc(e, u[0], 0x13u); return; }
        if (((u[1] << 8) | u[2]) != DID_TEST_STATE) { nrc(e, u[0], 0x31u); return; }
        r[0] = 0x62u; r[1] = u[1]; r[2] = u[2]; r[3] = e->state; reply(e, r, 4u); return;
    case UDS_WDBI:
        if (n < 4u) { nrc(e, u[0], 0x13u); return; }
        if (((u[1] << 8) | u[2]) == DID_TEST_STATE) {
            if (e->dsess != 0x03u) { nrc(e, u[0], 0x22u); return; }
            e->state = u[3];
            SHM_C2_STATE = e->state;
            r[0] = 0x6Eu; r[1] = u[1]; r[2] = u[2]; reply(e, r, 3u);
            schedule_impact(e);
            return;
        }
        if (!e->unlocked) { nrc(e, u[0], 0x33u); return; }
        nrc(e, u[0], 0x31u); return;
    default:
        nrc(e, u[0], 0x11u); return;
    }
}

static void run_impacts(void)
{
    uint32_t i, now = stm0_get_count();
    for (i = 0u; i < PEND_IMPACTS; i++) {
        if (g_pimp[i].used && (now - g_pimp[i].t_due_from) >= g_pimp[i].delay_ticks) {
            uint8_t d[8];
            uint32_t k = SHM_IMPLOG_N;
            g_pimp[i].used = 0u;
            g_impact_cnt++;
            memset(d, 0, sizeof(d));
            d[0] = g_pimp[i].value;
            d[1] = g_impact_cnt;
            d[2] = (SHM_CFG_FLAGS & CFGF_IMPACT_SRC) ? g_pimp[i].ecu : 0u;
            send(CANID_IMPACT, d, 8u);
            if (k < IMPLOG_SLOTS) {                 /* ground truth only */
                SHM_IMPLOG[k].ecu = g_pimp[i].ecu;
                SHM_IMPLOG[k].value = g_pimp[i].value;
                SHM_IMPLOG[k].counter = g_impact_cnt;
                SHM_IMPLOG[k].t = now;
                SHM_IMPLOG_N = k + 1u;
            }
            SHM_C2_IMPACTS = g_impact_cnt;
        }
    }
}

void core2_main(void)
{
    SHM_C2_STEP = 0xC2000001u;                 /* reached main */
    zero(__SBSS_C2_START, __SBSS_C2_END);
    zero(__BSS_CORE2_START, __BSS_CORE2_END);
    SHM_C2_STEP = 0xC2000002u;
    reset_targets();
    g_seen_trial = SHM_TRIAL_SEQ;
    MSYNC();
    SHM_C2_READY = SHM_CORE2_MAGIC;
    MSYNC();

    for (;;) {
        uint32_t seq = SHM_TRIAL_SEQ;
        if (seq != g_seen_trial) {                 /* new trial */
            reset_targets();
            SHM_TQ_CONS = SHM_TQ_PROD;             /* drop stale requests */
            g_seen_trial = seq;
            MSYNC();
            SHM_C2_TRIAL_ACK = seq;
        }

        if (SHM_TQ_CONS != SHM_TQ_PROD) {
            uint32_t c = SHM_TQ_CONS, id;
            uint8_t f[8], i;
            MSYNC();
            id = SHM_TQ[c].id;
            for (i = 0u; i < 8u; i++) f[i] = SHM_TQ[c].data[i];
            SHM_TQ_CONS = (c + 1u) % CANQ_SLOTS;
            SHM_C2_RX++;
            if (id == CANID_DIAG_REQ)        handle(&g_ecu[0], f);
            else if (id == CANID_DIAG_REQ_B) handle(&g_ecu[1], f);
        }
        run_impacts();
    }
}
