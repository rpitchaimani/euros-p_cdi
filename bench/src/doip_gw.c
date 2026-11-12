/* doip_gw.c -- core 1: diagnostic gateway between the source zone (Ethernet)
 * and the destination zone (CAN), plus the bench control endpoint.
 *
 * Transport: ISO 13400-2 (DoIP) message formats carried over UDP port 13400.
 * The real standard uses TCP for diagnostic messages; the bench uses UDP so
 * that it runs on the already-working lwIP UDP path.  Say so in the paper.
 *
 * Fixed policy (loaded at boot, never changed during a run):
 *   routing activation : tester logical addresses 0x0E00-0x0EFF only
 *   TA 0x0010 (target) : 0x10, 0x3E, 0x22, 0x27 allowed;
 *                        0x2E allowed if the session passed SecurityAccess,
 *                        0x2E on DID 0xF1A0 without it is FORWARDED and
 *                        recorded as a violation (AUDIT) -- the policy gap
 *                        the bench chain uses; other 0x2E denied
 *   TA 0x0020          : route closed (denied)
 *   anything else      : denied
 * Requests to the target go out as single-frame ISO-TP on CAN 0x7E0.  The CAN
 * request does not carry the tester's identity; only the gateway's pending
 * request FIFO links a 0x7E8 response back to a session.
 */
#include "doip_gw.h"
#include "bench.h"
#include "shared_mem.h"
#include "observers.h"
#include "can_drv.h"
#include "stm_timer.h"
#include "uart_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include <string.h>

/* ---------------------------------------------------------------- */
#define MAX_SESS      16u
#define PEND_SLOTS    8u
#define PEND_TIMEOUT_MS 1000u

typedef struct {
    uint32_t ip;          /* network byte order as in ip4_addr_t */
    uint16_t port;
    uint16_t sa;
    uint8_t  used, active;
    uint8_t  auth[N_TARGETS], dsess[N_TARGETS];   /* per target ECU */
} sess_t;

typedef struct {
    uint8_t  sess;
    uint8_t  sid;
    uint16_t route_seq;
    uint32_t t;
} pend_t;

static sess_t  g_sess[MAX_SESS];
/* one FIFO of outstanding requests per target ECU: each ECU answers its own
   requests in order, but the two ECUs are independent of each other */
static pend_t  g_pend[N_TARGETS][PEND_SLOTS];
static uint32_t g_pend_head[N_TARGETS], g_pend_n[N_TARGETS];
static uint16_t g_route_seq;

static int tidx(uint16_t ta)
{
    return (ta == LA_TARGET) ? 0 : (ta == LA_TARGET_B) ? 1 : -1;
}
static const uint16_t TA_OF[N_TARGETS]     = { LA_TARGET, LA_TARGET_B };
static const uint32_t REQID_OF[N_TARGETS]  = { CANID_DIAG_REQ, CANID_DIAG_REQ_B };
static struct udp_pcb *g_doip_pcb, *g_ctrl_pcb;

/* control-channel pending reply */
static uint8_t   g_ctl_wait;          /* 0 none, 'S' or 'E' */
static ip_addr_t g_ctl_addr;
static uint16_t  g_ctl_port;
static uint32_t  g_ctl_t0;
static uint32_t  g_ctl_mask;          /* obs mask to restore after START */

/* ---------------------------------------------------------------- */
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static void udp_send_buf(struct udp_pcb *pcb, const ip_addr_t *a, uint16_t port,
                         const uint8_t *buf, uint16_t len)
{
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, buf, len);
    udp_sendto(pcb, p, a, port);
    pbuf_free(p);
}

static void doip_send(const ip_addr_t *a, uint16_t port, uint16_t type,
                      const uint8_t *pl, uint16_t pl_len)
{
    uint8_t b[64];
    if (pl_len > sizeof(b) - DOIP_HDR_LEN) return;
    b[0] = DOIP_VER; b[1] = DOIP_INV;
    put16(&b[2], type);
    put32(&b[4], pl_len);
    memcpy(&b[DOIP_HDR_LEN], pl, pl_len);
    udp_send_buf(g_doip_pcb, a, port, b, (uint16_t)(DOIP_HDR_LEN + pl_len));
}

/* gateway observer record, layout in bench.h */
static void gw_log(uint8_t kind, const sess_t *s, uint32_t ip, uint16_t port,
                   uint16_t sa, uint16_t ta, uint8_t dec, uint8_t why,
                   uint8_t sid, uint8_t sub, uint16_t did, uint16_t rseq)
{
    uint8_t d[20];
    memset(d, 0, sizeof(d));
    memcpy(&d[0], &ip, 4u);
    put16(&d[4], port);
    put16(&d[6], sa);
    put16(&d[8], ta);
    d[10] = dec; d[11] = why; d[12] = sid; d[13] = sub;
    put16(&d[14], did);
    {
        int ti = tidx((kind == EK_GW_RESP) ? sa : ta);   /* responses: sa = ECU */
        d[16] = (s && ti >= 0) ? s->auth[ti] : 0u;
        d[17] = (s && ti >= 0) ? s->dsess[ti] : 0u;
    }
    put16(&d[18], rseq);
    obs_gw_event(kind, d);
}

static int sess_find(uint32_t ip, uint16_t port)
{
    uint32_t i;
    for (i = 0u; i < MAX_SESS; i++)
        if (g_sess[i].used && g_sess[i].ip == ip && g_sess[i].port == port)
            return (int)i;
    return -1;
}

static int sess_new(uint32_t ip, uint16_t port)
{
    uint32_t i;
    for (i = 0u; i < MAX_SESS; i++)
        if (!g_sess[i].used) {
            memset(&g_sess[i], 0, sizeof(sess_t));
            g_sess[i].used = 1u; g_sess[i].ip = ip; g_sess[i].port = port;
            g_sess[i].dsess[0] = 1u; g_sess[i].dsess[1] = 1u;
            return (int)i;
        }
    return -1;
}

static void gw_reset_sessions(void)
{
    memset(g_sess, 0, sizeof(g_sess));
    memset(g_pend, 0, sizeof(g_pend));
    memset(g_pend_head, 0, sizeof(g_pend_head));
    memset(g_pend_n, 0, sizeof(g_pend_n));
    g_route_seq = 0u;
}

/* ---------------------------------------------------------------- */
static void policy(const sess_t *s, uint16_t ta, const uint8_t *uds, uint16_t n,
                   uint8_t *dec, uint8_t *why)
{
    uint8_t sid = n ? uds[0] : 0u;
    int ti = tidx(ta);
    *dec = GWD_DENY; *why = GWR_OK;
    if (ta == LA_OTHER_ZONE) { *why = GWR_ROUTE_CLOSED; return; }
    if (ti < 0)              { *why = GWR_UNKNOWN_TA;   return; }
    switch (sid) {
    case UDS_DSC: case UDS_TP: case UDS_RDBI: case UDS_SA:
        *dec = GWD_ALLOW; return;
    case UDS_WDBI:
        if (s->auth[ti]) { *dec = GWD_ALLOW; return; }
        if (n >= 3u && get16(&uds[1]) == DID_TEST_STATE) {
            *dec = GWD_AUDIT; *why = GWR_WRITE_NOAUTH; return;
        }
        *why = GWR_WRITE_NOAUTH; return;
    default:
        *why = GWR_SID_BLOCKED; return;
    }
}

static void handle_doip(const uint8_t *b, uint16_t len, const ip_addr_t *a, uint16_t port)
{
    uint16_t type;
    uint32_t pl_len, ip = ip_addr_get_ip4_u32(a);
    const uint8_t *pl;
    int si;

    if (len < DOIP_HDR_LEN || b[0] != DOIP_VER || b[1] != DOIP_INV) return;
    type   = get16(&b[2]);
    pl_len = get32(&b[4]);
    if (pl_len > (uint32_t)(len - DOIP_HDR_LEN)) return;
    pl = b + DOIP_HDR_LEN;

    if (type == DOIP_VIR) {
        uint8_t r[33];
        memset(r, 0, sizeof(r));
        memcpy(r, "WCHAINRECON000001", 17u);       /* VIN               */
        put16(&r[17], LA_GATEWAY);                   /* logical address   */
        r[19] = 0x02u; r[24] = 0x01u;                /* EID 02:00:00:00:00:01 */
        r[25] = 0x02u; r[30] = 0x01u;                /* GID               */
        doip_send(a, port, DOIP_VAM, r, 33u);
        gw_log(EK_GW_VIR, NULL, ip, port, 0u, LA_GATEWAY, GWD_ALLOW, GWR_OK, 0u, 0u, 0u, 0u);
        return;
    }

    if (type == DOIP_RA_REQ && pl_len >= 7u) {
        uint16_t sa = get16(&pl[0]);
        uint8_t  r[9];
        si = sess_find(ip, port);
        if (si < 0) si = sess_new(ip, port);
        memset(r, 0, sizeof(r));
        put16(&r[0], sa);
        put16(&r[2], LA_GATEWAY);
        if (si >= 0 && sa >= LA_TESTER_MIN && sa <= LA_TESTER_MAX) {
            g_sess[si].sa = sa; g_sess[si].active = 1u;
            r[4] = 0x10u;                            /* activated         */
            gw_log(EK_GW_RA, &g_sess[si], ip, port, sa, LA_GATEWAY, GWD_ALLOW, GWR_OK, 0u, 0u, 0u, 0u);
        } else {
            r[4] = 0x00u;                            /* unknown SA        */
            gw_log(EK_GW_RA, NULL, ip, port, sa, LA_GATEWAY, GWD_DENY, GWR_BAD_SA, 0u, 0u, 0u, 0u);
        }
        doip_send(a, port, DOIP_RA_RESP, r, 9u);
        return;
    }

    if (type == DOIP_DIAG && pl_len >= 5u) {
        uint16_t sa = get16(&pl[0]), ta = get16(&pl[2]);
        const uint8_t *uds = pl + 4;
        uint16_t n = (uint16_t)(pl_len - 4u);
        uint8_t dec, why, r[5], sid = uds[0];
        uint8_t sub = (n > 1u) ? uds[1] : 0u;
        uint16_t did = (n > 2u) ? get16(&uds[1]) : 0u;
        put16(&r[0], ta); put16(&r[2], sa);

        si = sess_find(ip, port);
        if (si < 0 || !g_sess[si].active || g_sess[si].sa != sa) {
            r[4] = 0x02u;                            /* invalid source address */
            doip_send(a, port, DOIP_DIAG_NACK, r, 5u);
            gw_log(EK_GW_ROUTE, NULL, ip, port, sa, ta, GWD_DENY, GWR_NO_RA, sid, sub, did, 0u);
            return;
        }
        policy(&g_sess[si], ta, uds, n, &dec, &why);
        if (dec != GWD_DENY && (n > 7u || g_pend_n[tidx(ta)] >= PEND_SLOTS)) {
            r[4] = (n > 7u) ? 0x04u : 0x05u;         /* too large / out of memory */
            doip_send(a, port, DOIP_DIAG_NACK, r, 5u);
            gw_log(EK_GW_ROUTE, &g_sess[si], ip, port, sa, ta, GWD_DENY, why, sid, sub, did, 0u);
            return;
        }
        if (dec == GWD_DENY) {
            r[4] = (why == GWR_UNKNOWN_TA) ? 0x03u : 0x06u;
            doip_send(a, port, DOIP_DIAG_NACK, r, 5u);
            gw_log(EK_GW_ROUTE, &g_sess[si], ip, port, sa, ta, dec, why, sid, sub, did, 0u);
            return;
        }
        /* allowed or audited: ACK, remember, forward as ISO-TP SF */
        {
            uint8_t f[8];
            int ti = tidx(ta);
            uint32_t slot = (g_pend_head[ti] + g_pend_n[ti]) % PEND_SLOTS;
            r[4] = 0x00u;
            doip_send(a, port, DOIP_DIAG_ACK, r, 5u);
            g_route_seq++;
            g_pend[ti][slot].sess = (uint8_t)si;
            g_pend[ti][slot].sid  = sid;
            g_pend[ti][slot].route_seq = g_route_seq;
            g_pend[ti][slot].t    = stm0_get_count();
            g_pend_n[ti]++;
            gw_log(EK_GW_ROUTE, &g_sess[si], ip, port, sa, ta, dec, why, sid, sub, did, g_route_seq);
            memset(f, 0xCC, sizeof(f));
            f[0] = (uint8_t)n;
            memcpy(&f[1], uds, n);
            can_tx(REQID_OF[ti], f, 8u);
            SHM_C1_FWD_ETH++;
        }
    }
}

/* response from target ti -> oldest pending request to that target */
static void route_response(int ti, const uint8_t data[8])
{
    uint8_t n = (uint8_t)(data[0] & 0x0Fu);
    uint8_t pl[4 + 7];
    pend_t  p;
    sess_t *s;
    ip_addr_t a;

    if (n == 0u || n > 7u) return;
    if (g_pend_n[ti] == 0u) {
        gw_log(EK_GW_RESP_ORPHAN, NULL, 0u, 0u, TA_OF[ti], 0u, GWD_DENY, GWR_OK,
               data[1], data[2], 0u, 0u);
        return;
    }
    /* 0x7F xx 0x78 = response pending: keep the request outstanding */
    if (n >= 3u && data[1] == UDS_NEG && data[3] == 0x78u) return;

    p = g_pend[ti][g_pend_head[ti]];
    g_pend_head[ti] = (g_pend_head[ti] + 1u) % PEND_SLOTS;
    g_pend_n[ti]--;
    s = &g_sess[p.sess];

    if (data[1] == (uint8_t)(UDS_SA + 0x40u) && n >= 2u && data[2] == 0x02u) s->auth[ti] = 1u;
    if (data[1] == (uint8_t)(UDS_DSC + 0x40u) && n >= 2u) s->dsess[ti] = data[2];

    put16(&pl[0], TA_OF[ti]);
    put16(&pl[2], s->sa);
    memcpy(&pl[4], &data[1], n);
    ip_addr_set_ip4_u32(&a, s->ip);
    doip_send(&a, s->port, DOIP_DIAG, pl, (uint16_t)(4u + n));
    gw_log(EK_GW_RESP, s, s->ip, s->port, TA_OF[ti], s->sa, GWD_ALLOW, GWR_OK,
           data[1], data[2], (n > 3u) ? get16(&data[2]) : 0u, p.route_seq);
    SHM_C1_FWD_CAN++;
}

static void pend_expire(void)
{
    uint32_t ti;
    for (ti = 0u; ti < N_TARGETS; ti++) {
        while (g_pend_n[ti] > 0u &&
               (stm0_get_count() - g_pend[ti][g_pend_head[ti]].t) > PEND_TIMEOUT_MS * STM_TICKS_PER_MS) {
            g_pend_head[ti] = (g_pend_head[ti] + 1u) % PEND_SLOTS;
            g_pend_n[ti]--;
        }
    }
}

/* ---------------------------------------------------------------- */
/* bench control (not observed: obs_eth_frame skips CTRL_PORT)       */
/* ---------------------------------------------------------------- */
static void ctl_reply(const ip_addr_t *a, uint16_t port, const uint8_t *b, uint16_t n)
{
    udp_send_buf(g_ctrl_pcb, a, port, b, n);
}

static void handle_ctrl(const uint8_t *b, uint16_t len, const ip_addr_t *a, uint16_t port)
{
    uint8_t r[16];
    if (len < 1u) return;
    switch (b[0]) {
    case 'H': {                                     /* hello / status */
        r[0] = 'h';
        put32(&r[1], SHM_LAYOUT_VER);
        r[5] = (SHM_C0_READY == SHM_CORE0_MAGIC);
        r[6] = (SHM_C1_READY == SHM_CORE1_MAGIC);
        r[7] = (SHM_C2_READY == SHM_CORE2_MAGIC);
        put32(&r[8], stm0_get_count());
        ctl_reply(a, port, r, 12u);
        break;
    }
    case 'S':                                       /* START */
        if (len < 26u || g_ctl_wait) return;
        SHM_CFG_OBS_MASK = 0u;                      /* deliver nothing while resetting */
        g_ctl_mask = b[9];
        SHM_TRIAL_ID       = get32(&b[1]);
        SHM_CFG_U_PPM      = get32(&b[5]);
        SHM_CFG_Q_CAP      = get16(&b[10]);
        SHM_CFG_DEADLINE_MS = get32(&b[12]);
        SHM_CFG_IMPACT_MS  = get16(&b[16]);
        SHM_HOST_T_HI      = get32(&b[18]);
        SHM_HOST_T_LO      = get32(&b[22]);
        /* optional extension (33 bytes): flags, impact jitter, target seed */
        if (len >= 33u) {
            SHM_CFG_FLAGS     = b[26];
            SHM_CFG_JITTER_MS = get16(&b[27]);
            SHM_CFG_SEED      = get32(&b[29]);
        } else {
            SHM_CFG_FLAGS = CFGF_IMPACT_SRC; SHM_CFG_JITTER_MS = 0u; SHM_CFG_SEED = 0u;
        }
        MSYNC();
        SHM_TRIAL_SEQ++;
        MSYNC();
        ip_addr_copy(g_ctl_addr, *a); g_ctl_port = port;
        g_ctl_wait = 'S'; g_ctl_t0 = stm0_get_count();
        break;
    case 'E':                                       /* END */
        if (g_ctl_wait) return;
        SHM_T_END = stm0_get_count();
        SHM_CFG_OBS_MASK = 0u;
        MSYNC();
        SHM_END_SEQ++;
        MSYNC();
        ip_addr_copy(g_ctl_addr, *a); g_ctl_port = port;
        g_ctl_wait = 'E'; g_ctl_t0 = stm0_get_count();
        break;
    case 'P': {                                     /* PEEK shared region */
        static uint8_t out[7 + 1024];
        uint32_t off; uint16_t n;
        if (len < 7u) return;
        off = get32(&b[1]); n = get16(&b[5]);
        if (n > 1024u) n = 1024u;
        if (off >= SHARED_SIZE) return;
        if (off + n > SHARED_SIZE) n = (uint16_t)(SHARED_SIZE - off);
        out[0] = 'D'; put32(&out[1], off); put16(&out[5], n);
        memcpy(&out[7], (const void *)(SHARED_BASE + off), n);
        ctl_reply(a, port, out, (uint16_t)(7u + n));
        break;
    }
    default:
        break;
    }
}

static void ctl_poll(void)
{
    uint8_t r[16];
    uint32_t elapsed;
    if (!g_ctl_wait) return;
    elapsed = stm0_get_count() - g_ctl_t0;

    if (g_ctl_wait == 'S') {
        uint32_t seq = SHM_TRIAL_SEQ;
        if ((SHM_C0_TRIAL_ACK == seq && SHM_C2_TRIAL_ACK == seq) ||
            elapsed > 2000u * STM_TICKS_PER_MS) {
            uint8_t sync[8];
            r[0] = 'A';
            r[1] = (SHM_C0_TRIAL_ACK == seq && SHM_C2_TRIAL_ACK == seq) ? 0u : 1u;
            gw_reset_sessions();
            obs_trial_reset();
            SHM_CFG_OBS_MASK = g_ctl_mask;
            MSYNC();
            SHM_T_START = stm0_get_count();
            put32(&sync[0], SHM_TRIAL_ID);
            put32(&sync[4], SHM_T_START);
            can_tx(CANID_SYNC, sync, 8u);           /* PEAK timestamps this */
            SHM_T_CANSYNC = stm0_get_count();
            put32(&r[2], seq);
            put32(&r[6], SHM_T_START);
            put32(&r[10], SHM_T_CANSYNC);
            ctl_reply(&g_ctl_addr, g_ctl_port, r, 14u);
            g_ctl_wait = 0u;
        }
    } else if (g_ctl_wait == 'E') {
        uint32_t seq = SHM_END_SEQ;
        if (SHM_C0_END_ACK == seq || elapsed > 2000u * STM_TICKS_PER_MS) {
            r[0] = 'F';
            r[1] = (SHM_C0_END_ACK == seq) ? 0u : 1u;
            put32(&r[2], seq);
            put32(&r[6], SHM_T_END);
            ctl_reply(&g_ctl_addr, g_ctl_port, r, 10u);
            g_ctl_wait = 0u;
        }
    }
}

/* ---------------------------------------------------------------- */
static void doip_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    static uint8_t buf[256];
    uint16_t n;
    (void)arg; (void)pcb;
    if (!p) return;
    n = (uint16_t)((p->tot_len > sizeof(buf)) ? sizeof(buf) : p->tot_len);
    pbuf_copy_partial(p, buf, n, 0u);
    pbuf_free(p);
    handle_doip(buf, n, addr, port);
}

static void ctrl_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    static uint8_t buf[64];
    uint16_t n;
    (void)arg; (void)pcb;
    if (!p) return;
    n = (uint16_t)((p->tot_len > sizeof(buf)) ? sizeof(buf) : p->tot_len);
    pbuf_copy_partial(p, buf, n, 0u);
    pbuf_free(p);
    handle_ctrl(buf, n, addr, port);
}

/* background load: accepted and dropped (no ICMP port-unreachable replies) */
static void sink_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (p) pbuf_free(p);
}

void gw_init(void)
{
    struct udp_pcb *sink;
    gw_reset_sessions();
    g_ctl_wait = 0u;
    g_doip_pcb = udp_new();
    g_ctrl_pcb = udp_new();
    sink = udp_new();
    if (!g_doip_pcb || !g_ctrl_pcb || !sink) { uart_log("[GW] PCB alloc failed\r\n"); return; }
    udp_bind(sink, IP_ADDR_ANY, BG_PORT);
    udp_recv(sink, sink_recv_cb, NULL);
    udp_bind(g_doip_pcb, IP_ADDR_ANY, DOIP_PORT);
    udp_recv(g_doip_pcb, doip_recv_cb, NULL);
    udp_bind(g_ctrl_pcb, IP_ADDR_ANY, CTRL_PORT);
    udp_recv(g_ctrl_pcb, ctrl_recv_cb, NULL);
    uart_log("[GW] DoIP/UDP 13400, control 13499\r\n");
}

void gw_poll(void)
{
    uint32_t id; uint8_t dlc, d[8];

    /* destination-zone bus: observe every frame, then act on it */
    while (can_rx(&id, &dlc, d)) {
        SHM_C1_CAN_RX++;
        obs_can_frame(id, dlc, d);
        if (is_diag_req(id)) {                      /* deliver to target ECUs */
            uint32_t prod = SHM_TQ_PROD, next = (prod + 1u) % CANQ_SLOTS;
            if (next == SHM_TQ_CONS) { SHM_C1_TQ_FULL++; }
            else {
                SHM_TQ[prod].id = id; SHM_TQ[prod].dlc = dlc;
                memcpy((void *)SHM_TQ[prod].data, d, 8u);
                MSYNC();
                SHM_TQ_PROD = next;
            }
        } else if (id == CANID_DIAG_RESP) {
            route_response(0, d);
        } else if (id == CANID_DIAG_RESP_B) {
            route_response(1, d);
        }
    }

    /* frames the target ECU wants on the bus */
    while (SHM_FQ_CONS != SHM_FQ_PROD) {
        uint32_t c = SHM_FQ_CONS;
        canf_t f;
        MSYNC();
        memcpy(&f, (const void *)&SHM_FQ[c], sizeof(f));
        SHM_FQ_CONS = (c + 1u) % CANQ_SLOTS;
        can_tx(f.id, f.data, f.dlc);
    }

    pend_expire();
    ctl_poll();
}
