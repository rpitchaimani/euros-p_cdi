/* shared_mem.h -- ChainRecon bench, shared SRAM contract for all three cores.
 *
 * Physical base 0x40080000, size 0x20000 (128 KB) -> ends 0x400A0000.
 * Core 0 (Z4a) private SRAM : 0x40000000-0x4003FFFF
 * Core 1 (Z4b) private SRAM : 0x40040000-0x4007FFFF
 * Core 2 (Z2)  private SRAM : 0x400A0000-0x400BFFFF (see MPC5748G_core2.ld)
 *
 * Core 0 zeroes the whole region (ECC init) before releasing cores 1 and 2.
 *
 * Producers / consumers:
 *   event ring (observation interface) : core 1 -> core 0   (SPSC)
 *   CAN queue to target                 : core 1 -> core 2   (SPSC)
 *   CAN queue from target               : core 2 -> core 1   (SPSC)
 *   delivery log                        : core 1 only
 *   IDS log, window log                 : core 0 only
 *   all logs are read by the host through the PEEK control command (core 1).
 */
#ifndef SHARED_MEM_H
#define SHARED_MEM_H

#include <stdint.h>
#include "enet_dma.h"

#define SHARED_BASE   0x40080000u
#define SHARED_SIZE   0x00020000u

#define SHM_U32(off)  (*(volatile uint32_t *)(SHARED_BASE + (off)))
#define MSYNC()       __asm__ volatile("msync" ::: "memory")

/* ---------------------------------------------------------------- */
/* 0x0000  control block                                             */
/* ---------------------------------------------------------------- */
#define SHM_C0_READY        SHM_U32(0x0000u)
#define SHM_C1_READY        SHM_U32(0x0004u)
#define SHM_C2_READY        SHM_U32(0x0008u)
#define SHM_LAYOUT_VER      SHM_U32(0x000Cu)
#define SHM_CORE0_MAGIC     0xCAFEBABEu
#define SHM_CORE1_MAGIC     0xDEADF00Du
#define SHM_CORE2_MAGIC     0x7A26E7C2u
#define SHM_LAYOUT_VERSION  0x00020001u

/* trial configuration, written by core 1 on START, then trial_seq++ */
#define SHM_TRIAL_SEQ       SHM_U32(0x0010u)  /* incremented last          */
#define SHM_TRIAL_ID        SHM_U32(0x0014u)
#define SHM_CFG_U_PPM       SHM_U32(0x0018u)  /* IDS CPU share, ppm of T_w */
#define SHM_CFG_OBS_MASK    SHM_U32(0x001Cu)  /* bit (1<<obs) = delivered  */
#define SHM_CFG_Q_CAP       SHM_U32(0x0020u)  /* IDS queue capacity        */
#define SHM_CFG_DEADLINE_MS SHM_U32(0x0024u)  /* logged only (offline cut) */
#define SHM_CFG_IMPACT_MS   SHM_U32(0x0028u)  /* target impact delay       */
#define SHM_T_START         SHM_U32(0x002Cu)  /* STM at START receipt      */
#define SHM_T_CANSYNC       SHM_U32(0x0030u)  /* STM at CAN sync TX done   */
#define SHM_HOST_T_HI       SHM_U32(0x0034u)
#define SHM_HOST_T_LO       SHM_U32(0x0038u)
#define SHM_END_SEQ         SHM_U32(0x003Cu)  /* incremented on END        */

#define SHM_C0_TRIAL_ACK    SHM_U32(0x0040u)  /* = TRIAL_SEQ once reset    */
#define SHM_C0_END_ACK      SHM_U32(0x0044u)  /* = END_SEQ once finalised  */
#define SHM_C2_TRIAL_ACK    SHM_U32(0x0048u)
#define SHM_T_END           SHM_U32(0x004Cu)  /* STM at END receipt        */
/* 0x00E4..0x00EF: further trial configuration (written on START) */
#define SHM_CFG_FLAGS       SHM_U32(0x00E4u)  /* CFGF_* (bench.h)          */
#define SHM_CFG_JITTER_MS   SHM_U32(0x00E8u)  /* extra random impact delay */
#define SHM_CFG_SEED        SHM_U32(0x00ECu)  /* target-side PRNG seed     */

/* core 1 counters (reset on START) -- index by observer id 1..3 */
#define SHM_C1_PRODUCED(o)  SHM_U32(0x0050u + 4u * (o))  /* 0x50..0x5F */
#define SHM_C1_MASKED(o)    SHM_U32(0x0060u + 4u * (o))  /* 0x60..0x6F */
#define SHM_C1_RINGFULL(o)  SHM_U32(0x0070u + 4u * (o))  /* 0x70..0x7F */
#define SHM_C1_DLOG_OVF     SHM_U32(0x0080u)
#define SHM_C1_FWD_ETH      SHM_U32(0x0084u)  /* DoIP diag msgs routed     */
#define SHM_C1_FWD_CAN      SHM_U32(0x0088u)  /* CAN responses routed back */
#define SHM_C1_CAN_TX_TO    SHM_U32(0x008Cu)  /* CAN TX timeouts           */
#define SHM_C1_ENET_RX      SHM_U32(0x0090u)
#define SHM_C1_CAN_RX       SHM_U32(0x0094u)
#define SHM_C1_TQ_FULL      SHM_U32(0x0098u)  /* to-target queue full      */
#define SHM_C0_BCET_TICKS   SHM_U32(0x009Cu)  /* min single-event cost (core 0) */

/* core 0 counters (reset on START) */
#define SHM_C0_ING          SHM_U32(0x00A0u)  /* events taken off the ring */
#define SHM_C0_ADMIT        SHM_U32(0x00A4u)
#define SHM_C0_ADMIT_DROP   SHM_U32(0x00A8u)
#define SHM_C0_PROC         SHM_U32(0x00ACu)
#define SHM_C0_UNPROC_END   SHM_U32(0x00B0u)  /* still queued at END       */
#define SHM_C0_WINDOWS      SHM_U32(0x00B4u)
#define SHM_C0_BUSY_TICKS   SHM_U32(0x00B8u)  /* sum over windows          */
#define SHM_C0_MAX_BACKLOG  SHM_U32(0x00BCu)
#define SHM_C0_LOG_N        SHM_U32(0x00C0u)
#define SHM_C0_LOG_OVF      SHM_U32(0x00C4u)
#define SHM_C0_WLOG_N       SHM_U32(0x00C8u)
#define SHM_C0_WCET_TICKS   SHM_U32(0x00CCu)  /* max single-event cost     */

/* core 2 (target ECU) counters */
#define SHM_C2_RX           SHM_U32(0x00D0u)
#define SHM_C2_TX           SHM_U32(0x00D4u)
#define SHM_C2_STATE        SHM_U32(0x00D8u)  /* test state (DID F1A0)     */
#define SHM_C2_IMPACTS      SHM_U32(0x00DCu)
#define SHM_C2_TXQ_FULL     SHM_U32(0x00E0u)

#define SHM_C1_DLOG_N       SHM_U32(0x00F0u)
#define SHM_C1_STEP         SHM_U32(0x00F4u)  /* core 1 boot progress marker */
#define SHM_C2_STEP         SHM_U32(0x00F8u)  /* core 2 boot progress marker */
#define SHM_BUILD_FLAGS     SHM_U32(0x00FCu)  /* set at boot, never reset    */
#define BUILD_FLAG_CAN_INTERNAL_LOOPBACK  0x1u    /* dev build: no bus traffic */

/* ---------------------------------------------------------------- */
/* 0x0100  ENET buffer descriptors and indices (core 1 only)         */
/* ---------------------------------------------------------------- */
#define SHM_RX_RING   ((volatile enet_bd_t *)(SHARED_BASE + 0x0100u)) /* 16x8 */
#define SHM_TX_RING   ((volatile enet_bd_t *)(SHARED_BASE + 0x0180u)) /*  8x8 */
#define SHM_RX_IDX    SHM_U32(0x01C0u)
#define SHM_TX_IDX    SHM_U32(0x01C4u)

/* ring indices */
#define SHM_EVT_PROD  SHM_U32(0x01C8u)
#define SHM_EVT_CONS  SHM_U32(0x01CCu)
#define SHM_TQ_PROD   SHM_U32(0x01D0u)
#define SHM_TQ_CONS   SHM_U32(0x01D4u)
#define SHM_FQ_PROD   SHM_U32(0x01D8u)
#define SHM_FQ_CONS   SHM_U32(0x01DCu)

/* ---------------------------------------------------------------- */
/* 0x0200  observation interface: event ring (core 1 -> core 0)      */
/* ---------------------------------------------------------------- */
#define OBS_SRC   1u   /* source-zone Ethernet view at gateway ingress */
#define OBS_GW    2u   /* gateway policy / routing decisions           */
#define OBS_DST   3u   /* destination-zone CAN bus view                */
#define OBS_MAX   4u

#define EVF_BG    0x01u  /* background traffic (counted, not logged)  */

typedef struct {
    uint32_t seq;      /* core-1 event sequence number (all observers) */
    uint32_t t_obs;    /* STM ticks at observation                      */
    uint8_t  obs;      /* OBS_*                                         */
    uint8_t  kind;     /* evt kind, see evt_kinds.h                     */
    uint8_t  flags;    /* EVF_*                                         */
    uint8_t  status;   /* delivery status (delivery log only)           */
    uint8_t  d[20];    /* observer payload, layout per kind             */
} evt_t;               /* 32 bytes                                      */

#define EVT_RING_SLOTS  256u
#define SHM_EVT_RING    ((volatile evt_t *)(SHARED_BASE + 0x0200u)) /* ..0x21FF */

/* delivery status */
#define DLV_DELIVERED   1u
#define DLV_MASKED      2u   /* observer not in this trial's scope      */
#define DLV_RINGFULL    3u   /* observation interface overflow          */

/* ---------------------------------------------------------------- */
/* 0x2200  CAN queues between gateway (core 1) and target (core 2)   */
/* ---------------------------------------------------------------- */
typedef struct {
    uint32_t id;
    uint8_t  dlc;
    uint8_t  pad[3];
    uint8_t  data[8];
} canf_t;              /* 16 bytes */

#define CANQ_SLOTS      16u
#define SHM_TQ          ((volatile canf_t *)(SHARED_BASE + 0x2200u)) /* to target   */
#define SHM_FQ          ((volatile canf_t *)(SHARED_BASE + 0x2300u)) /* from target */

/* ---------------------------------------------------------------- */
/* 0x2400  IDS log (core 0): one record per non-background event     */
/* ---------------------------------------------------------------- */
typedef struct {
    uint32_t seq;
    uint32_t t_ing;    /* STM when taken off the observation ring      */
    uint32_t t_proc;   /* STM when processing finished, 0 = never      */
    uint8_t  obs;
    uint8_t  status;   /* IDS_* below                                  */
    uint8_t  feat;     /* on-target feature code (ids_core0.c)         */
    uint8_t  sess;     /* on-target session slot, 0xFF = none          */
} idslog_t;            /* 16 bytes */

#define IDS_PROCESSED     1u
#define IDS_UNPROCESSED   2u   /* admitted, still queued at END        */
#define IDS_ADMIT_DROP    3u   /* IDS queue full                       */

#define IDSLOG_SLOTS    1536u
#define SHM_IDSLOG      ((volatile idslog_t *)(SHARED_BASE + 0x2400u)) /* ..0x83FF */

/* ---------------------------------------------------------------- */
/* 0x8400  delivery log (core 1): every non-background event         */
/* ---------------------------------------------------------------- */
#define DLOG_SLOTS      512u
#define SHM_DLOG        ((volatile evt_t *)(SHARED_BASE + 0x8400u))   /* ..0xC3FF */

/* ---------------------------------------------------------------- */
/* 0xC400  window log (core 0): one record per T_w window            */
/* ---------------------------------------------------------------- */
typedef struct {
    uint16_t arrivals;   /* events taken off the ring in the window   */
    uint16_t processed;  /* events processed in the window            */
    uint16_t dropped;    /* admission drops in the window             */
    uint16_t backlog;    /* queue length at window end                */
    uint32_t busy;       /* STM ticks spent processing                */
} wlog_t;                /* 12 bytes */

#define WLOG_SLOTS      1024u
#define SHM_WLOG        ((volatile wlog_t *)(SHARED_BASE + 0xC400u))  /* ..0xF3FF */

/* ---------------------------------------------------------------- */
/* 0xF400  impact log (core 2): GROUND TRUTH ONLY.  No observer reads */
/* it; the host uses it to know which ECU produced which impact.     */
/* ---------------------------------------------------------------- */
typedef struct {
    uint8_t  ecu;        /* 1 = target A, 2 = target B                */
    uint8_t  value;      /* state written                              */
    uint8_t  counter;    /* impact counter carried in the 0x1A0 frame  */
    uint8_t  pad;
    uint32_t t;          /* STM when the impact frame was queued       */
} implog_t;              /* 8 bytes */

#define IMPLOG_SLOTS    64u
#define SHM_IMPLOG_N    SHM_U32(0xF400u)
#define SHM_IMPLOG      ((volatile implog_t *)(SHARED_BASE + 0xF410u)) /* ..0xF60F */

/* ---------------------------------------------------------------- */
/* 0x10000 ENET DMA buffers (core 1 only)                            */
/* ---------------------------------------------------------------- */
#define SHM_RX_BUF(i) \
    ((uint8_t *)(SHARED_BASE + 0x10000u + (uint32_t)(i) * ENET_BUFFER_SIZE))
#define SHM_TX_BUF(i) \
    ((uint8_t *)(SHARED_BASE + 0x16000u + (uint32_t)(i) * ENET_BUFFER_SIZE))
/* 0x16000 + 8*1536 = 0x19000 <= SHARED_SIZE */

#endif /* SHARED_MEM_H */
