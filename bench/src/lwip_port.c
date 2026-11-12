/* lwip_port.c — LwIP port for MPC5748G ENET / KSZ8081 PHY
   RMII 100BASE-TX, DMA rings in shared SRAM at 0x40080000.
   ChainRecon changes: wrap-safe sys_now() for the 40 MHz STM, every received
   frame is handed to the source-zone observer (obs_eth_frame) before lwIP,
   and TX waits for a free buffer descriptor instead of overwriting it. */

#include "MPC5748G.h"
#include "lwip_port.h"
#include "shared_mem.h"
#include "observers.h"
#include "stm_timer.h"
#include "uart_log.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include <string.h>
#include <stdint.h>

/* STM wraps every ~107 s at 40 MHz; extend to a monotonic ms count.
   Called on every lwip_poll() pass, far more often than once per wrap. */
static uint32_t g_now_last;
static uint32_t g_now_frac;
static uint32_t g_now_ms;

u32_t sys_now(void)
{
    uint32_t c = stm0_get_count();
    g_now_frac += c - g_now_last;
    g_now_last  = c;
    while (g_now_frac >= STM_TICKS_PER_MS) {
        g_now_frac -= STM_TICKS_PER_MS;
        g_now_ms++;
    }
    return (u32_t)g_now_ms;
}

/* KSZ8081 MDIO address depends on a board strap: scanned in phy_init(). */
static uint8_t g_phy_addr = 0u;
#define PHY_ADDR            g_phy_addr
#define PHY_REG_BCR        0u
#define PHY_REG_BSR         1u
#define PHY_REG_ID1         2u
#define PHY_REG_ID2         3u
#define PHY_REG_ANAR        4u
#define PHY_REG_ANLPAR      5u
#define PHY_REG_CTRL2       0x1Fu

#define PHY_BCR_RESET       (1u << 15)
#define PHY_BCR_AN_EN       (1u << 12)
#define PHY_BCR_AN_RESTART  (1u << 9)
#define PHY_BSR_LINK_UP     (1u << 2)
#define PHY_BSR_AN_DONE     (1u << 5)

static struct netif enet_netif;

static inline void enet_write(uint32_t offset, uint32_t val)
{
    *((volatile uint32_t*)(ENET0_BASE + offset)) = val;
}

static inline uint32_t enet_read(uint32_t offset)
{
    return *((volatile uint32_t*)(ENET0_BASE + offset));
}

uint16_t phy_read(uint8_t reg)
{
    uint32_t timeout = 100000u;

    enet_write(ENET_EIR, (1u << 23));

    enet_write(ENET_MMFR,
               (0x01u << 30) | (0x02u << 28) |
               ((uint32_t)(PHY_ADDR & 0x1Fu) << 23) |
               ((uint32_t)(reg & 0x1Fu) << 18) |
               (0x02u << 16));

    while(!(enet_read(ENET_EIR) & (1u << 23)) && --timeout);
    enet_write(ENET_EIR, (1u << 23));

    return (uint16_t)(enet_read(ENET_MMFR) & 0xFFFFu);
}

void phy_write(uint8_t reg, uint16_t val)
{
    uint32_t timeout = 100000u;

    enet_write(ENET_EIR, (1u << 23));

    enet_write(ENET_MMFR,
               (0x01u << 30) | (0x01u << 28) |
               ((uint32_t)(PHY_ADDR & 0x1Fu) << 23) |
               ((uint32_t)(reg & 0x1Fu) << 18) |
               (0x02u << 16) | (uint32_t)val);

    while(!(enet_read(ENET_EIR) & (1u << 23)) && --timeout);
    enet_write(ENET_EIR, (1u << 23));
}

void phy_init(void)
{
    uint8_t a;
    uint16_t id1 = 0u;
    for (a = 0u; a < 32u; a++) {              /* find the PHY on MDIO */
        g_phy_addr = a;
        id1 = phy_read(PHY_REG_ID1);
        if (id1 != 0x0000u && id1 != 0xFFFFu) break;
    }
    if (a == 32u) {
        g_phy_addr = 0u;
        uart_log("[PHY] no PHY answered on MDIO (0..31)\r\n");
    } else {
        uart_log("[PHY] found at MDIO address ");
        uart_log_uint(a);
        uart_log("\r\n");
    }

    uart_log("[PHY] Resetting KSZ8081\r\n");

    phy_write(PHY_REG_BCR, PHY_BCR_RESET);

    uint32_t start = stm0_get_count();
    while((stm0_get_count() - start) < 500u * STM_TICKS_PER_MS)
    {
        if(!(phy_read(PHY_REG_BCR) & PHY_BCR_RESET))
            break;
        stm0_delay_ms(1u);
    }

    uart_log("[PHY] ID1=0x");
    uart_log_hex((uint32_t)phy_read(PHY_REG_ID1));
    uart_log(" ID2=0x");
    uart_log_hex((uint32_t)phy_read(PHY_REG_ID2));
    uart_log("\r\n");

    phy_write(PHY_REG_ANAR,
              (1u << 8) | (1u << 7) |
              (1u << 6) | (1u << 5) | (1u << 0));

    phy_write(PHY_REG_BCR,
              PHY_BCR_AN_EN | PHY_BCR_AN_RESTART);

    uart_log("[PHY] Autonegotiation started\r\n");
}

uint8_t phy_wait_link(uint32_t timeout_ms)
{
    uart_log("[PHY] Waiting for link (");
    uart_log_uint(timeout_ms);
    uart_log(" ms)...\r\n");

    uint32_t start = stm0_get_count();
    uint32_t limit = timeout_ms * STM_TICKS_PER_MS;

    while((stm0_get_count() - start) < limit)
    {
        uint16_t bsr = phy_read(PHY_REG_BSR);

        if((bsr & PHY_BSR_LINK_UP) &&
           (bsr & PHY_BSR_AN_DONE))
        {
            uart_log("[PHY] Link UP — BSR=0x");
            uart_log_hex((uint32_t)bsr);
            uart_log("\r\n");
            return 1u;
        }

        stm0_delay_ms(10u);
    }

    uart_log("[PHY] Link timeout — continuing anyway\r\n");
    return 0u;
}

static void enet_gpio_init(void)
{
    SIUL2->MSCR[94]  = SIUL2_MSCR_SRC(3u)|SIUL2_MSCR_OBE_MASK|
                       SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_SSS(4u);
    SIUL2->IMCR[450] = SIUL2_IMCR_SSS(1u);

    SIUL2->MSCR[96]  = SIUL2_MSCR_SRC(3u)|SIUL2_MSCR_OBE_MASK|
                       SIUL2_MSCR_SSS(3u);

    SIUL2->MSCR[114] = SIUL2_MSCR_SRC(3u)|SIUL2_MSCR_OBE_MASK|
                       SIUL2_MSCR_SSS(4u);

    SIUL2->MSCR[113] = SIUL2_MSCR_SRC(3u)|SIUL2_MSCR_OBE_MASK|
                       SIUL2_MSCR_SSS(4u);

    SIUL2->MSCR[112] = SIUL2_MSCR_SRC(3u)|SIUL2_MSCR_OBE_MASK|
                       SIUL2_MSCR_SSS(3u);

    SIUL2->MSCR[97]  = SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_PUE_MASK;
    SIUL2->IMCR[449] = SIUL2_IMCR_SSS(1u);

    SIUL2->MSCR[95]  = SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_PUE_MASK;
    SIUL2->IMCR[457] = SIUL2_IMCR_SSS(1u);

    SIUL2->MSCR[9]   = SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_PUE_MASK;
    SIUL2->IMCR[451] = SIUL2_IMCR_SSS(1u);

    SIUL2->MSCR[8]   = SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_PUE_MASK;
    SIUL2->IMCR[452] = SIUL2_IMCR_SSS(1u);

    SIUL2->MSCR[11]  = SIUL2_MSCR_IBE_MASK|SIUL2_MSCR_PUE_MASK;
    SIUL2->IMCR[455] = SIUL2_IMCR_SSS(1u);
}

static void enet_hw_init(void)
{
    uart_log("[ENET] Hardware init\r\n");

    enet_gpio_init();
    uart_log("[ENET] GPIO ok\r\n");

    enet_write(ENET_ECR, 0x00000001u);
    {
        uint32_t t0 = stm0_get_count();
        while(enet_read(ENET_ECR) & 0x00000001u)
        {
            if((stm0_get_count() - t0) > 10u * STM_TICKS_PER_MS)
                break;
        }
    }
    uart_log("[ENET] Reset ok\r\n");

    enet_write(ENET_PALR,
               ((uint32_t)GATEWAY_MAC0 << 24) |
               ((uint32_t)GATEWAY_MAC1 << 16) |
               ((uint32_t)GATEWAY_MAC2 << 8)  |
               ((uint32_t)GATEWAY_MAC3));

    enet_write(ENET_PAUR,
               ((uint32_t)GATEWAY_MAC4 << 24) |
               ((uint32_t)GATEWAY_MAC5 << 16) |
               0x8808u);

    /* MDC = f_enet / ((MII_SPEED+1)*2) must stay <= 2.5 MHz; MII_SPEED=39
       gives 1-2 MHz for an 80-160 MHz module clock (old value 4: 8-16 MHz). */
    enet_write(ENET_MSCR, (39u << 1));
    uart_log("[ENET] MSCR ok\r\n");

    enet_write(ENET_RCR,
               (1518u << 16) | (1u << 8) | (1u << 2));

    enet_write(ENET_TCR, (1u << 2));
    enet_write(ENET_TFWR, 0x00000002u);

    enet_write(ENET_IAUR, 0u);
    enet_write(ENET_IALR, 0u);
    enet_write(ENET_GAUR, 0u);
    enet_write(ENET_GALR, 0u);

    uart_log("[ENET] Hardware ready\r\n");
}

static void enet_dma_init(void)
{
    uart_log("[ENET] DMA ring init\r\n");

    for(uint16_t i = 0u; i < RX_RING_SIZE; i++)
    {
        SHM_RX_RING[i].status = BD_RX_EMPTY;
        SHM_RX_RING[i].length = 0u;
        SHM_RX_RING[i].buffer = SHM_RX_BUF(i);
    }
    SHM_RX_RING[RX_RING_SIZE - 1u].status |= BD_RX_WRAP;

    for(uint16_t i = 0u; i < TX_RING_SIZE; i++)
    {
        SHM_TX_RING[i].status = 0u;
        SHM_TX_RING[i].length = 0u;
        SHM_TX_RING[i].buffer = SHM_TX_BUF(i);
    }
    SHM_TX_RING[TX_RING_SIZE - 1u].status |= BD_TX_WRAP;

    enet_write(ENET_RDSR, (uint32_t)&SHM_RX_RING[0]);
    enet_write(ENET_TDSR, (uint32_t)&SHM_TX_RING[0]);
    enet_write(ENET_MRBR, ENET_BUFFER_SIZE);

    SHM_RX_IDX  = 0u;
    SHM_TX_IDX  = 0u;

    uart_log("[ENET] DMA rings ready\r\n");
}

static err_t enet_netif_output(
    struct netif *netif, struct pbuf *p)
{
    uint32_t tidx = SHM_TX_IDX;
    uint8_t  *buf = SHM_TX_BUF(tidx);
    uint16_t  len = 0u;

    (void)netif;
    {   /* wait (bounded, 2 ms) until the DMA has released this BD */
        uint32_t t0 = stm0_get_count();
        while (SHM_TX_RING[tidx].status & BD_TX_READY) {
            if ((stm0_get_count() - t0) > 2u * STM_TICKS_PER_MS)
                return ERR_MEM;
        }
    }

    struct pbuf *q;
    for(q = p; q != NULL; q = q->next)
    {
        if(len + (uint16_t)q->len > ENET_BUFFER_SIZE)
            break;
        memcpy(buf + len, q->payload, q->len);
        len += (uint16_t)q->len;
    }

    SHM_TX_RING[tidx].length = len;
    SHM_TX_RING[tidx].status =
        BD_TX_READY | BD_TX_LAST | BD_TX_TC |
        (SHM_TX_RING[tidx].status & BD_TX_WRAP);

    enet_write(ENET_TDAR, 0xFFFFFFFFu);
    SHM_TX_IDX = (tidx + 1u) % TX_RING_SIZE;

    return ERR_OK;
}

static err_t enet_netif_init(struct netif *netif)
{
    netif->linkoutput = enet_netif_output;
    netif->output     = etharp_output;
    netif->mtu        = 1500u;
    netif->flags      = NETIF_FLAG_BROADCAST |
                        NETIF_FLAG_ETHARP    |
                        NETIF_FLAG_LINK_UP;

    netif->hwaddr_len = 6u;
    netif->hwaddr[0]  = GATEWAY_MAC0;
    netif->hwaddr[1]  = GATEWAY_MAC1;
    netif->hwaddr[2]  = GATEWAY_MAC2;
    netif->hwaddr[3]  = GATEWAY_MAC3;
    netif->hwaddr[4]  = GATEWAY_MAC4;
    netif->hwaddr[5]  = GATEWAY_MAC5;

    return ERR_OK;
}

void lwip_init_port(void)
{
    uart_log("[LWIP] Initialising\r\n");

    enet_hw_init();
    enet_dma_init();

    enet_write(ENET_ECR,
               enet_read(ENET_ECR) | 0x00000002u);

    phy_init();
    phy_wait_link(15000u);

    enet_write(ENET_RDAR, 0xFFFFFFFFu);

    lwip_init();

    ip4_addr_t ip, mask, gw;

    IP4_ADDR(&ip,
             GATEWAY_IP_ADDR0, GATEWAY_IP_ADDR1,
             GATEWAY_IP_ADDR2, GATEWAY_IP_ADDR3);

    IP4_ADDR(&mask,
             GATEWAY_NETMASK0, GATEWAY_NETMASK1,
             GATEWAY_NETMASK2, GATEWAY_NETMASK3);

    IP4_ADDR(&gw,
             GATEWAY_GW0, GATEWAY_GW1,
             GATEWAY_GW2, GATEWAY_GW3);

    netif_add(&enet_netif, &ip, &mask, &gw,
              NULL, enet_netif_init, ethernet_input);

    netif_set_default(&enet_netif);
    netif_set_up(&enet_netif);

    uart_log("[LWIP] Ready at 192.168.10.1\r\n");
}

void lwip_poll(void)
{
    uint32_t ridx = SHM_RX_IDX;

    while(!(SHM_RX_RING[ridx].status & BD_RX_EMPTY))
    {
        uint16_t len = SHM_RX_RING[ridx].length;

        if(len > 0u &&
           !(SHM_RX_RING[ridx].status & BD_RX_ERROR))
        {
            /* source-zone observer sees the frame first (packet level) */
            obs_eth_frame(SHM_RX_BUF(ridx), len);

            struct pbuf *p = pbuf_alloc(
                PBUF_RAW, len, PBUF_POOL);

            if(p != NULL)
            {
                memcpy(p->payload, SHM_RX_BUF(ridx), len);

                if(enet_netif.input(
                       p, &enet_netif) != ERR_OK)
                {
                    pbuf_free(p);
                }
            }
        }

        SHM_RX_RING[ridx].status =
            BD_RX_EMPTY |
            (SHM_RX_RING[ridx].status & BD_RX_WRAP);

        ridx = (ridx + 1u) % RX_RING_SIZE;
        SHM_RX_IDX = ridx;

        enet_write(ENET_RDAR, 0xFFFFFFFFu);
    }

    sys_check_timeouts();
}

err_t enet_dma_send_frame(uint8_t *buf, uint16_t len)
{
    if(len > ENET_BUFFER_SIZE) return ERR_MEM;

    uint32_t tidx = SHM_TX_IDX;

    memcpy(SHM_TX_BUF(tidx), buf, len);

    SHM_TX_RING[tidx].length = len;
    SHM_TX_RING[tidx].status =
        BD_TX_READY | BD_TX_LAST | BD_TX_TC |
        (SHM_TX_RING[tidx].status & BD_TX_WRAP);

    enet_write(ENET_TDAR, 0xFFFFFFFFu);
    SHM_TX_IDX = (tidx + 1u) % TX_RING_SIZE;

    return ERR_OK;
}
