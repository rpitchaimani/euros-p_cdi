/* can_drv.c -- FlexCAN_0, 500 kbit/s, RX FIFO + one TX mailbox.
 * Pin mux and CTRL1 bit timing are the values the earlier PoC used on this
 * DEVKIT (PB0 = CAN0_TX, PB1 = CAN0_RX, TJA1044 transceiver).
 */
#include "MPC5748G.h"
#include "can_drv.h"
#include "shared_mem.h"
#include "stm_timer.h"
#include "uart_log.h"

#define FLEXCAN0_BASE   0xFFEC0000u
#define CAN_MCR         0x0000u
#define CAN_CTRL1       0x0004u
#define CAN_TIMER       0x0008u
#define CAN_RXMGMASK    0x0010u
#define CAN_RX14MASK    0x0014u
#define CAN_RX15MASK    0x0018u
#define CAN_ESR1        0x0020u
#define CAN_IMASK1      0x0028u
#define CAN_IFLAG1      0x0030u
#define CAN_CTRL2       0x0034u
#define CAN_RXFGMASK    0x0048u
#define CAN_MB_BASE     0x0080u
#define CAN_MB_SIZE     16u

#define MCR_MDIS        (1u << 31)
#define MCR_FRZ         (1u << 30)
#define MCR_RFEN        (1u << 29)
#define MCR_HALT        (1u << 28)
#define MCR_NOTRDY      (1u << 27)
#define MCR_FRZACK      (1u << 24)
#define MCR_SRXDIS      (1u << 17)
#define MCR_MAXMB_63    0x3Fu

#define MB_TX           8u            /* first MB after FIFO + filter table */
#define CS_CODE_TX_INACTIVE 0x08000000u
#define CS_CODE_TX_DATA     0x0C000000u
#define CS_SRR              0x00400000u
#define IFLAG_FIFO_AVAIL    (1u << 5)
#define IFLAG_FIFO_WARN     (1u << 6)
#define IFLAG_FIFO_OVF      (1u << 7)

#define SIUL2_MSCR16    (*((volatile uint32_t *)0xFFFC0280u))
#define SIUL2_MSCR17    (*((volatile uint32_t *)0xFFFC0284u))
#define SIUL2_IMCR188   (*((volatile uint32_t *)0xFFFC0D30u))

static inline void wr(uint32_t off, uint32_t v) { *((volatile uint32_t *)(FLEXCAN0_BASE + off)) = v; }
static inline uint32_t rd(uint32_t off)         { return *((volatile uint32_t *)(FLEXCAN0_BASE + off)); }

/* Fallback if hardware self-reception does not behave as assumed: build with
   -DCAN_SW_LOOPBACK=1.  Self-reception is then disabled and every frame that
   was ACKed on the bus is handed back to can_rx() by software.  The frames
   are still on the wire (PEAK sees them); only the read-back path differs. */
#ifndef CAN_SW_LOOPBACK
#define CAN_SW_LOOPBACK 0
#endif
#ifndef CAN_INTERNAL_LOOPBACK
#define CAN_INTERNAL_LOOPBACK 0
#endif
#if CAN_SW_LOOPBACK
#define SWQ_SLOTS 16u
static uint32_t g_swq_id[SWQ_SLOTS];
static uint8_t  g_swq_d[SWQ_SLOTS][8], g_swq_dlc[SWQ_SLOTS];
static uint32_t g_swq_h, g_swq_n;
#endif

void can_init(void)
{
    uint32_t n, to;

    MC_ME->PCTLn[70] = 0x01u;          /* FlexCAN_0 clock on (RUN_PC[1])  */
    SIUL2_MSCR16  = 0x32000001u;       /* PB0 CAN0_TX                     */
    SIUL2_MSCR17  = 0x00080000u;       /* PB1 input                       */
    SIUL2_IMCR188 = 0x00000002u;       /* CAN0_RX <- PB1                  */

    wr(CAN_MCR, rd(CAN_MCR) | MCR_MDIS);          /* disable             */
    wr(CAN_CTRL1, rd(CAN_CTRL1) & ~(1u << 13));   /* CLKSRC = oscillator */
    wr(CAN_MCR, rd(CAN_MCR) & ~MCR_MDIS);         /* enable -> freeze    */
    to = 1000000u;
    while (!(rd(CAN_MCR) & MCR_FRZACK) && --to) { }

    wr(CAN_CTRL1, 0x04DB0086u);                    /* 500 kbit/s timing  */
#if CAN_INTERNAL_LOOPBACK
    /* DEV ONLY: LPB = 1, the controller ACKs and receives its own frames
       internally and nothing reaches the physical bus.  Runs made with this
       build are stamped in SHM_BUILD_FLAGS and never count as results. */
    wr(CAN_CTRL1, rd(CAN_CTRL1) | (1u << 12));
#endif
    for (n = 0u; n < 96u; n++)
        wr(CAN_MB_BASE + n * CAN_MB_SIZE, 0u);     /* clear MB RAM       */

    /* still frozen: enable RX FIFO, accept all IDs, keep self-reception */
#if CAN_SW_LOOPBACK
    wr(CAN_MCR, rd(CAN_MCR) | MCR_RFEN | MCR_FRZ | MCR_HALT | MCR_SRXDIS);
#else
    wr(CAN_MCR, (rd(CAN_MCR) | MCR_RFEN | MCR_FRZ | MCR_HALT) & ~MCR_SRXDIS);
#endif
    wr(CAN_RXMGMASK, 0u);
    wr(CAN_RX14MASK, 0u);
    wr(CAN_RX15MASK, 0u);
    wr(CAN_RXFGMASK, 0u);                          /* FIFO filters: don't care */
    wr(CAN_CTRL2, rd(CAN_CTRL2) & ~(0xFu << 24));   /* RFFN = 0: 8 filters      */
    wr(CAN_MB_BASE + MB_TX * CAN_MB_SIZE, CS_CODE_TX_INACTIVE);
    wr(CAN_IFLAG1, 0xFFFFFFFFu);

    /* leave freeze: FIFO on, MAXMB = 63, SRXDIS per CAN_SW_LOOPBACK */
#if CAN_SW_LOOPBACK
    wr(CAN_MCR, MCR_RFEN | MCR_SRXDIS | MCR_MAXMB_63);
#else
    wr(CAN_MCR, MCR_RFEN | MCR_MAXMB_63);
#endif
    to = 1000000u;
    while ((rd(CAN_MCR) & (MCR_FRZACK | MCR_NOTRDY)) && --to) { }
#if CAN_INTERNAL_LOOPBACK
    SHM_BUILD_FLAGS |= BUILD_FLAG_CAN_INTERNAL_LOOPBACK;
    uart_log("[CAN] FlexCAN_0 ready (INTERNAL LOOPBACK, DEV ONLY)\r\n");
#else
    uart_log("[CAN] FlexCAN_0 ready (FIFO, self-rx)\r\n");
#endif
}

uint8_t can_tx(uint32_t id, const uint8_t *d, uint8_t dlc)
{
    uint32_t mb = CAN_MB_BASE + MB_TX * CAN_MB_SIZE;
    uint32_t t0;
    if (dlc > 8u) dlc = 8u;
    wr(mb + 4u, (id & 0x7FFu) << 18);
    wr(mb + 8u,  ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
                 ((uint32_t)d[2] << 8)  |  (uint32_t)d[3]);
    wr(mb + 12u, ((uint32_t)d[4] << 24) | ((uint32_t)d[5] << 16) |
                 ((uint32_t)d[6] << 8)  |  (uint32_t)d[7]);
    wr(mb, CS_CODE_TX_DATA | ((uint32_t)dlc << 16));
    t0 = stm0_get_count();
    while (!(rd(CAN_IFLAG1) & (1u << MB_TX))) {
        if ((stm0_get_count() - t0) > 5u * STM_TICKS_PER_MS) {   /* no ACK? */
            wr(mb, CS_CODE_TX_INACTIVE);
            SHM_C1_CAN_TX_TO++;
            return 0u;
        }
    }
    wr(CAN_IFLAG1, (1u << MB_TX));
#if CAN_SW_LOOPBACK
    if (g_swq_n < SWQ_SLOTS) {
        uint32_t s = (g_swq_h + g_swq_n) % SWQ_SLOTS, i;
        g_swq_id[s] = id & 0x7FFu; g_swq_dlc[s] = dlc;
        for (i = 0u; i < 8u; i++) g_swq_d[s][i] = d[i];
        g_swq_n++;
    }
#endif
    return 1u;
}

uint8_t can_rx(uint32_t *id, uint8_t *dlc, uint8_t data[8])
{
    uint32_t cs, w0, w1;
#if CAN_SW_LOOPBACK
    if (g_swq_n > 0u) {
        uint32_t i;
        *id = g_swq_id[g_swq_h]; *dlc = g_swq_dlc[g_swq_h];
        for (i = 0u; i < 8u; i++) data[i] = g_swq_d[g_swq_h][i];
        g_swq_h = (g_swq_h + 1u) % SWQ_SLOTS;
        g_swq_n--;
        return 1u;
    }
#endif
    if (rd(CAN_IFLAG1) & IFLAG_FIFO_OVF)
        wr(CAN_IFLAG1, IFLAG_FIFO_OVF | IFLAG_FIFO_WARN);
    if (!(rd(CAN_IFLAG1) & IFLAG_FIFO_AVAIL))
        return 0u;
    cs = rd(CAN_MB_BASE + 0u);
    *id = (rd(CAN_MB_BASE + 4u) >> 18) & 0x7FFu;
    w0 = rd(CAN_MB_BASE + 8u);
    w1 = rd(CAN_MB_BASE + 12u);
    (void)rd(CAN_TIMER);                           /* unlock             */
    wr(CAN_IFLAG1, IFLAG_FIFO_AVAIL);              /* pop                */
    *dlc = (uint8_t)((cs >> 16) & 0xFu);
    data[0] = (uint8_t)(w0 >> 24); data[1] = (uint8_t)(w0 >> 16);
    data[2] = (uint8_t)(w0 >> 8);  data[3] = (uint8_t)w0;
    data[4] = (uint8_t)(w1 >> 24); data[5] = (uint8_t)(w1 >> 16);
    data[6] = (uint8_t)(w1 >> 8);  data[7] = (uint8_t)w1;
    return 1u;
}
