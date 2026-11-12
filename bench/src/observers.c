/* observers.c -- core 1: source-zone, gateway and destination-zone observers.
 * See observers.h.  No UART in this file: it runs on the forwarding path.
 */
#include "observers.h"
#include "bench.h"
#include "stm_timer.h"
#include <string.h>

static uint32_t g_seq;   /* event sequence, reset per trial */

/* forgery experiment (see observers.h) */
static uint8_t  g_forge_mode;
static uint32_t g_forge_alpha_ppm = 1000000u;
static uint32_t g_forge_seed;
static uint8_t  g_compromised;     /* FORGE_ATTACK: set once the attack's write passes */

void obs_set_forge(uint8_t mode, uint32_t alpha_ppm, uint32_t seed)
{
    g_forge_mode = (mode <= FORGE_ATTACK) ? mode : FORGE_NONE;
    g_forge_alpha_ppm = (alpha_ppm > 1000000u) ? 1000000u : alpha_ppm;
    g_forge_seed = seed;
}

/* Is the gw observer genuine in window w?  A hash of (seed, w) only, so the
   choice is independent of the attack and of every observation. */
static int genuine_window(uint32_t w)
{
    uint32_t h = g_forge_seed ^ (w * 0x9E3779B1u) ^ 0x6A09E667u;
    h ^= h >> 16; h *= 0x7FEB352Du;
    h ^= h >> 15; h *= 0x846CA68Bu;
    h ^= h >> 16;
    return (h % 1000000u) < g_forge_alpha_ppm;
}

/* FORGE_EXO template: one fixed benign report from a fake session. */
static void forge_template(evt_t *f)
{
    memset(f->d, 0, sizeof(f->d));
    f->kind = EK_GW_ROUTE;
    f->d[0] = 192u; f->d[1] = 168u; f->d[2] = 10u; f->d[3] = 250u;   /* fake tester */
    f->d[4] = 0x9Cu; f->d[5] = 0x40u;                                  /* port 40000  */
    f->d[6] = 0x0Eu; f->d[7] = 0x7Fu;                                  /* SA 0x0E7F   */
    f->d[8] = (uint8_t)(LA_TARGET >> 8); f->d[9] = (uint8_t)LA_TARGET;
    f->d[10] = GWD_ALLOW; f->d[11] = GWR_OK;
    f->d[12] = UDS_RDBI;                                               /* a read      */
    f->d[14] = (uint8_t)(DID_TEST_STATE >> 8); f->d[15] = (uint8_t)DID_TEST_STATE;
    f->d[16] = 1u; f->d[17] = 3u;                                      /* auth, ext.  */
}

/* FORGE_ATTACK rewrite: the decision becomes "allowed, authenticated". */
static void forge_attack(evt_t *f)
{
    if (f->kind == EK_GW_ROUTE) { f->d[10] = GWD_ALLOW; f->d[11] = GWR_OK; }
    f->d[16] = 1u;
}

void obs_trial_reset(void)
{
    uint32_t o;
    g_seq = 0u;
    g_compromised = 0u;
    for (o = 0u; o < OBS_MAX; o++) {
        SHM_C1_PRODUCED(o) = 0u;
        SHM_C1_MASKED(o)   = 0u;
        SHM_C1_RINGFULL(o) = 0u;
    }
    SHM_C1_DLOG_N   = 0u;
    SHM_C1_DLOG_OVF = 0u;
    SHM_C1_FWD_ETH  = 0u;
    SHM_C1_FWD_CAN  = 0u;
    SHM_C1_CAN_TX_TO = 0u;
    SHM_C1_ENET_RX  = 0u;
    SHM_C1_CAN_RX   = 0u;
    SHM_C1_TQ_FULL  = 0u;
    MSYNC();
}

static void dlog_put(const evt_t *e)
{
    uint32_t n = SHM_C1_DLOG_N;
    if (n >= DLOG_SLOTS) { SHM_C1_DLOG_OVF++; return; }
    memcpy((void *)&SHM_DLOG[n], e, sizeof(evt_t));
    MSYNC();
    SHM_C1_DLOG_N = n + 1u;
}

/* Emit one event: forgery (gw only), scope check, ring write, delivery log. */
static void evt_emit(evt_t *e)
{
    uint8_t o = e->obs;
    e->seq   = ++g_seq;
    SHM_C1_PRODUCED(o)++;

    if (o == OBS_GW && g_forge_mode != FORGE_NONE &&
        (SHM_CFG_OBS_MASK & (1u << o)) != 0u) {
        int forge = 0;
        if (g_forge_mode == FORGE_EXO) {
            uint32_t w = (e->t_obs - SHM_T_START) / (IDS_WINDOW_MS * STM_TICKS_PER_MS);
            forge = !genuine_window(w);
        } else {
            if (!g_compromised && e->kind == EK_GW_ROUTE && e->d[10] == GWD_AUDIT)
                g_compromised = 1u;
            forge = g_compromised;
        }
        if (forge) {
            evt_t f = *e;
            e->status = DLV_FORGED_OUT;               /* genuine: logged, not delivered */
            dlog_put(e);
            if (g_forge_mode == FORGE_EXO) forge_template(&f); else forge_attack(&f);
            f.flags |= EVF_FORGED;
            f.seq = ++g_seq;
            e = &f;                                   /* deliver the forgery instead */
            o = e->obs;
            {
                uint32_t prod = SHM_EVT_PROD;
                uint32_t next = (prod + 1u) % EVT_RING_SLOTS;
                if (next == SHM_EVT_CONS) {
                    SHM_C1_RINGFULL(o)++;
                    e->status = DLV_RINGFULL;
                } else {
                    e->status = DLV_DELIVERED;
                    memcpy((void *)&SHM_EVT_RING[prod], e, sizeof(evt_t));
                    MSYNC();
                    SHM_EVT_PROD = next;
                }
            }
            dlog_put(e);
            return;
        }
    }

    if ((SHM_CFG_OBS_MASK & (1u << o)) == 0u) {
        SHM_C1_MASKED(o)++;
        e->status = DLV_MASKED;
    } else {
        uint32_t prod = SHM_EVT_PROD;
        uint32_t next = (prod + 1u) % EVT_RING_SLOTS;
        if (next == SHM_EVT_CONS) {
            SHM_C1_RINGFULL(o)++;
            e->status = DLV_RINGFULL;
        } else {
            e->status = DLV_DELIVERED;
            memcpy((void *)&SHM_EVT_RING[prod], e, sizeof(evt_t));
            MSYNC();
            SHM_EVT_PROD = next;
        }
    }
    if ((e->flags & EVF_BG) == 0u)
        dlog_put(e);
}

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

void obs_eth_frame(const uint8_t *f, uint16_t len)
{
    evt_t e;
    uint16_t et, ip = 14u, tr, sport = 0u, dport = 0u;
    uint8_t  proto, ihl;

    SHM_C1_ENET_RX++;
    memset(&e, 0, sizeof(e));
    e.t_obs = stm0_get_count();
    e.obs   = OBS_SRC;
    e.kind  = EK_ETH_OTHER;
    e.flags = EVF_BG;

    if (len < 14u) { evt_emit(&e); return; }
    et = be16(f + 12);
    if (et == 0x8100u && len >= 18u) { et = be16(f + 16); ip = 18u; }
    if (et != 0x0800u || len < (uint16_t)(ip + 20u)) { evt_emit(&e); return; }

    ihl   = (uint8_t)((f[ip] & 0x0Fu) * 4u);
    proto = f[ip + 9u];
    memcpy(&e.d[0], f + ip + 12u, 4u);            /* source IPv4 */
    tr = (uint16_t)(ip + ihl);
    if (proto == 17u && len >= (uint16_t)(tr + 8u)) {
        sport = be16(f + tr);
        dport = be16(f + tr + 2u);
    }
    e.d[4] = (uint8_t)(sport >> 8); e.d[5] = (uint8_t)sport;
    e.d[6] = (uint8_t)(dport >> 8); e.d[7] = (uint8_t)dport;

    if (dport == CTRL_PORT || sport == CTRL_PORT)
        return;                                    /* bench control: not observed */

    if (dport == DOIP_PORT && len >= (uint16_t)(tr + 8u + DOIP_HDR_LEN)) {
        const uint8_t *h = f + tr + 8u;
        uint16_t avail = (uint16_t)(len - (tr + 8u + DOIP_HDR_LEN));
        e.kind  = EK_ETH_DOIP;
        e.flags = 0u;
        e.d[8]  = h[2]; e.d[9]  = h[3];            /* payload type   */
        e.d[10] = h[6]; e.d[11] = h[7];            /* length (low16) */
        memcpy(&e.d[12], h + DOIP_HDR_LEN, (avail < 8u) ? avail : 8u);
    }
    evt_emit(&e);
}

void obs_gw_event(uint8_t kind, const uint8_t d[20])
{
    evt_t e;
    memset(&e, 0, sizeof(e));
    e.t_obs = stm0_get_count();
    e.obs   = OBS_GW;
    e.kind  = kind;
    memcpy(e.d, d, 20u);
    evt_emit(&e);
}

void obs_can_frame(uint32_t id, uint8_t dlc, const uint8_t data[8])
{
    evt_t e;
    memset(&e, 0, sizeof(e));
    e.t_obs = stm0_get_count();
    e.obs   = OBS_DST;
    e.kind  = EK_CAN;
    e.d[0] = (uint8_t)(id >> 24); e.d[1] = (uint8_t)(id >> 16);
    e.d[2] = (uint8_t)(id >> 8);  e.d[3] = (uint8_t)id;
    e.d[4] = dlc;
    memcpy(&e.d[5], data, 8u);
    if (!is_diag_req(id) && !is_diag_resp(id) &&
        id != CANID_IMPACT   && id != CANID_SYNC)
        e.flags = EVF_BG;
    evt_emit(&e);
}
