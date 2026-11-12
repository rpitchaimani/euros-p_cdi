/* observers.c -- core 1: source-zone, gateway and destination-zone observers.
 * See observers.h.  No UART in this file: it runs on the forwarding path.
 */
#include "observers.h"
#include "bench.h"
#include "stm_timer.h"
#include <string.h>

static uint32_t g_seq;   /* event sequence, reset per trial */

void obs_trial_reset(void)
{
    uint32_t o;
    g_seq = 0u;
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

/* Emit one event: scope check, ring write, delivery log. */
static void evt_emit(evt_t *e)
{
    uint8_t o = e->obs;
    e->seq   = ++g_seq;
    SHM_C1_PRODUCED(o)++;

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
