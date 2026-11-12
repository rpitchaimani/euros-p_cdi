/* ids_core0.c -- Core 0 (Z4a): the IDS under test.
 *
 * Pipeline per event (each stage is counted and, for non-background events,
 * logged with its STM time so the host can say where evidence was lost):
 *   1. delivered  : core 1 wrote it into the observation ring (delivery log)
 *   2. ingested   : core 0 took it off the ring (t_ing), never budgeted
 *   3. admitted   : the IDS queue (capacity Q from the trial config) had room;
 *                   otherwise ADMIT_DROP
 *   4. processed  : feature extraction ran (t_proc).  Processing only runs
 *                   while this T_w window's busy time is below the CPU share
 *                   U (ppm of T_w).  Processing is non-preemptive, so the last
 *                   event of a window may overrun the share by one event cost.
 *   5. on time    : decided offline against the pre-set deadline (host).
 * Chain linking itself runs offline on the host over the events this core
 * processed before the deadline (python/analyze.py).  This core does the
 * per-event work a deployed IDS would do: parse, session lookup, per-session
 * stage marks and payload byte statistics.
 */
#include "ids_core0.h"
#include "shared_mem.h"
#include "bench.h"
#include "stm_timer.h"
#include <string.h>

#define Q_MAX            1024u
#define TW_TICKS         (IDS_WINDOW_MS * STM_TICKS_PER_MS)  /* 4,000,000 */
/* budget ticks = u_ppm * TW_TICKS / 1e6 = u_ppm * 4 (exact for T_w = 100 ms) */
#define BUDGET_PER_PPM   (TW_TICKS / 1000000u)

/* on-target feature codes (idslog_t.feat) */
enum {
    F_BG = 0, F_DISC, F_RA, F_DIAG_REQ, F_GW_ALLOW, F_GW_AUDIT, F_GW_DENY,
    F_GW_RESP, F_CAN_REQ, F_CAN_RESP, F_CAN_IMPACT, F_SYNC, F_OTHER, F_DOIP_RESP
};

typedef struct {
    evt_t    e;
    uint16_t log_idx;     /* 0xFFFF = not logged (background) */
    uint16_t pad;
} qent_t;

#define MAX_SESS 16u
typedef struct {
    uint8_t  ip[4];
    uint16_t port;
    uint8_t  used;
    uint8_t  marks;       /* bit per feature class seen in this session */
    uint32_t last_t;
} ids_sess_t;

static qent_t     g_q[Q_MAX];
static uint32_t   g_qh, g_qn;
static ids_sess_t g_sess[MAX_SESS];
static uint32_t   g_hist[256];
static uint32_t   g_flow[64];

static uint32_t g_seen_trial, g_seen_end;
static uint32_t g_wstart, g_busy, g_w_arr, g_w_proc, g_w_drop;
static uint32_t g_budget, g_qcap;
static uint8_t  g_active;            /* between START and END */

/* ---------------------------------------------------------------- */
static uint8_t sess_lookup(const uint8_t ip[4], uint16_t port, uint32_t t)
{
    uint32_t i, free_i = MAX_SESS, old_i = 0u;
    for (i = 0u; i < MAX_SESS; i++) {
        if (g_sess[i].used && g_sess[i].port == port &&
            memcmp(g_sess[i].ip, ip, 4u) == 0) {
            g_sess[i].last_t = t;
            return (uint8_t)i;
        }
        if (!g_sess[i].used && free_i == MAX_SESS) free_i = i;
        if (g_sess[i].last_t < g_sess[old_i].last_t) old_i = i;
    }
    i = (free_i < MAX_SESS) ? free_i : old_i;   /* evict least recent */
    memset(&g_sess[i], 0, sizeof(ids_sess_t));
    g_sess[i].used = 1u;
    memcpy(g_sess[i].ip, ip, 4u);
    g_sess[i].port = port;
    g_sess[i].last_t = t;
    return (uint8_t)i;
}

static void payload_stats(const uint8_t *d, uint32_t n)
{
    uint32_t i;
    for (i = 0u; i < n; i++) g_hist[d[i]]++;
}

/* one event's feature extraction; returns feature code, sets *sess */
static uint8_t process_event(const evt_t *e, uint8_t *sess)
{
    uint8_t f = F_OTHER;
    *sess = 0xFFu;

    if (e->obs == OBS_SRC) {
        uint16_t sport = (uint16_t)((e->d[4] << 8) | e->d[5]);
        uint16_t dport = (uint16_t)((e->d[6] << 8) | e->d[7]);
        payload_stats(e->d, 20u);
        if (e->kind != EK_ETH_DOIP) {
            g_flow[(e->d[3] ^ sport ^ dport) & 63u]++;
            return F_BG;
        }
        *sess = sess_lookup(&e->d[0], sport, e->t_obs);
        switch ((uint16_t)((e->d[8] << 8) | e->d[9])) {
        case DOIP_VIR:    f = F_DISC; break;
        case DOIP_RA_REQ: f = F_RA; break;
        case DOIP_DIAG:   f = F_DIAG_REQ; break;
        default:          f = F_OTHER; break;
        }
    } else if (e->obs == OBS_GW) {
        uint16_t port = (uint16_t)((e->d[4] << 8) | e->d[5]);
        if (e->kind != EK_GW_RESP_ORPHAN) *sess = sess_lookup(&e->d[0], port, e->t_obs);
        switch (e->kind) {
        case EK_GW_VIR:   f = F_DISC; break;
        case EK_GW_RA:    f = (e->d[10] == GWD_ALLOW) ? F_RA : F_GW_DENY; break;
        case EK_GW_ROUTE: f = (e->d[10] == GWD_ALLOW) ? F_GW_ALLOW :
                              (e->d[10] == GWD_AUDIT) ? F_GW_AUDIT : F_GW_DENY; break;
        case EK_GW_RESP:  f = F_GW_RESP; break;
        default:          f = F_OTHER; break;
        }
    } else if (e->obs == OBS_DST) {
        uint32_t id = ((uint32_t)e->d[0] << 24) | ((uint32_t)e->d[1] << 16) |
                      ((uint32_t)e->d[2] << 8) | e->d[3];
        payload_stats(&e->d[5], 8u);
        if (is_diag_req(id))            f = F_CAN_REQ;
        else if (is_diag_resp(id))      f = F_CAN_RESP;
        else if (id == CANID_IMPACT)    f = F_CAN_IMPACT;
        else if (id == CANID_SYNC)      f = F_SYNC;
        else { g_flow[id & 63u]++; return F_BG; }
    }
    if (*sess != 0xFFu && f < 8u) g_sess[*sess].marks |= (uint8_t)(1u << f);
    return f;
}

/* ---------------------------------------------------------------- */
static void trial_reset(uint32_t seq)
{
    uint32_t now;
    SHM_EVT_CONS = SHM_EVT_PROD;          /* discard anything from before */
    g_qh = 0u; g_qn = 0u;
    memset(g_sess, 0, sizeof(g_sess));
    memset(g_hist, 0, sizeof(g_hist));
    memset(g_flow, 0, sizeof(g_flow));
    SHM_C0_ING = 0u; SHM_C0_ADMIT = 0u; SHM_C0_ADMIT_DROP = 0u;
    SHM_C0_PROC = 0u; SHM_C0_UNPROC_END = 0u; SHM_C0_WINDOWS = 0u;
    SHM_C0_BUSY_TICKS = 0u; SHM_C0_MAX_BACKLOG = 0u;
    SHM_C0_LOG_N = 0u; SHM_C0_LOG_OVF = 0u; SHM_C0_WLOG_N = 0u;
    SHM_C0_WCET_TICKS = 0u;
    SHM_C0_BCET_TICKS = 0xFFFFFFFFu;
    g_qcap = SHM_CFG_Q_CAP;
    if (g_qcap == 0u || g_qcap > Q_MAX) g_qcap = Q_MAX;
    {
        uint32_t u = SHM_CFG_U_PPM;
        if (u > 1000000u) u = 1000000u;
        g_budget = u * BUDGET_PER_PPM;
    }
    now = stm0_get_count();
    g_wstart = now; g_busy = 0u; g_w_arr = 0u; g_w_proc = 0u; g_w_drop = 0u;
    g_seen_trial = seq;
    g_active = 1u;
    MSYNC();
    SHM_C0_TRIAL_ACK = seq;
}

static void window_close(void)
{
    uint32_t n = SHM_C0_WLOG_N;
    if (!g_active) { g_busy = 0u; g_w_arr = 0u; g_w_proc = 0u; g_w_drop = 0u; return; }
    if (n < WLOG_SLOTS) {
        SHM_WLOG[n].arrivals  = (uint16_t)g_w_arr;
        SHM_WLOG[n].processed = (uint16_t)g_w_proc;
        SHM_WLOG[n].dropped   = (uint16_t)g_w_drop;
        SHM_WLOG[n].backlog   = (uint16_t)g_qn;
        SHM_WLOG[n].busy      = g_busy;
        SHM_C0_WLOG_N = n + 1u;
    }
    SHM_C0_WINDOWS++;
    SHM_C0_BUSY_TICKS += g_busy;
    g_busy = 0u; g_w_arr = 0u; g_w_proc = 0u; g_w_drop = 0u;
}

static uint16_t log_new(const evt_t *e, uint32_t t_ing, uint8_t status)
{
    uint32_t n = SHM_C0_LOG_N;
    if (n >= IDSLOG_SLOTS) { SHM_C0_LOG_OVF++; return 0xFFFFu; }
    SHM_IDSLOG[n].seq    = e->seq;
    SHM_IDSLOG[n].t_ing  = t_ing;
    SHM_IDSLOG[n].t_proc = 0u;
    SHM_IDSLOG[n].obs    = e->obs;
    SHM_IDSLOG[n].status = status;
    SHM_IDSLOG[n].feat   = 0u;
    SHM_IDSLOG[n].sess   = 0xFFu;
    SHM_C0_LOG_N = n + 1u;
    return (uint16_t)n;
}

static void ingest(void)
{
    while (SHM_EVT_CONS != SHM_EVT_PROD) {
        uint32_t c = SHM_EVT_CONS;
        uint32_t t = stm0_get_count();
        evt_t e;
        MSYNC();
        memcpy(&e, (const void *)&SHM_EVT_RING[c], sizeof(evt_t));
        MSYNC();
        SHM_EVT_CONS = (c + 1u) % EVT_RING_SLOTS;
        SHM_C0_ING++;
        g_w_arr++;

        if (g_qn < g_qcap) {
            qent_t *q = &g_q[(g_qh + g_qn) % Q_MAX];
            q->e = e;
            q->log_idx = (e.flags & EVF_BG) ? 0xFFFFu : log_new(&e, t, IDS_UNPROCESSED);
            g_qn++;
            SHM_C0_ADMIT++;
            if (g_qn > SHM_C0_MAX_BACKLOG) SHM_C0_MAX_BACKLOG = g_qn;
        } else {
            SHM_C0_ADMIT_DROP++;
            g_w_drop++;
            if (!(e.flags & EVF_BG)) (void)log_new(&e, t, IDS_ADMIT_DROP);
        }
    }
}

static void process_budgeted(void)
{
    while (g_qn > 0u && g_busy < g_budget) {
        qent_t  *q = &g_q[g_qh];
        uint32_t t0 = stm0_get_count(), t1, cost;
        uint8_t  sess, f = process_event(&q->e, &sess);
        t1 = stm0_get_count();
        cost = t1 - t0;
        g_busy += cost;
        if (cost > SHM_C0_WCET_TICKS) SHM_C0_WCET_TICKS = cost;
        if (cost < SHM_C0_BCET_TICKS) SHM_C0_BCET_TICKS = cost;
        if (q->log_idx != 0xFFFFu) {
            SHM_IDSLOG[q->log_idx].t_proc = t1;
            SHM_IDSLOG[q->log_idx].status = IDS_PROCESSED;
            SHM_IDSLOG[q->log_idx].feat   = f;
            SHM_IDSLOG[q->log_idx].sess   = sess;
        }
        g_qh = (g_qh + 1u) % Q_MAX;
        g_qn--;
        g_w_proc++;
        SHM_C0_PROC++;
    }
}

static void trial_end(uint32_t seq)
{
    ingest();
    window_close();                        /* partial last window */
    SHM_C0_UNPROC_END = g_qn;              /* their log status stays UNPROCESSED */
    g_active = 0u;                         /* no processing until next START */
    g_seen_end = seq;
    MSYNC();
    SHM_C0_END_ACK = seq;
}

/* ---------------------------------------------------------------- */
void ids_init(void)
{
    g_seen_trial = SHM_TRIAL_SEQ;
    g_seen_end   = SHM_END_SEQ;
    g_qh = 0u; g_qn = 0u;
    g_qcap = Q_MAX;
    g_budget = TW_TICKS;                   /* until the first START */
    g_wstart = stm0_get_count();
    g_active = 0u;
}

void ids_poll(void)
{
    uint32_t seq = SHM_TRIAL_SEQ, endseq = SHM_END_SEQ;
    if (seq != g_seen_trial) trial_reset(seq);
    if (endseq != g_seen_end) trial_end(endseq);

    ingest();
    if (g_active) process_budgeted();

    while ((stm0_get_count() - g_wstart) >= TW_TICKS) {
        window_close();
        g_wstart += TW_TICKS;
    }
}
