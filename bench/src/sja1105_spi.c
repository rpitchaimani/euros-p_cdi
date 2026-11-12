/* ─────────────────────────────────────────
   sja1105_spi.c

   SJA1105Q SPI driver
   Runs on MPC5748G Core 0
   Uses DSPI_0 peripheral

   Covers:
   1. DSPI_0 init
   2. SPI read/write
   3. (mirror is static config; no runtime mirror API)
   5. VLAN table configure
   6. VLAN retag configure
   ───────────────────────────────────────── */

#include "MPC5748G.h"
#include "sja1105_spi.h"
#include "uart_log.h"
#include <stdint.h>
#include <stddef.h>

/* ─────────────────────────────────────────
   DSPI_0 register base address
   From MPC5748G reference manual
   Table 5-1 Memory Map
   ───────────────────────────────────────── */
#define DSPI0_BASE          0xFFF90000u

/* DSPI register offsets                   */
#define DSPI_MCR            0x0000u  /* Mode       */
#define DSPI_TCR            0x0008u  /* Transfer   */
#define DSPI_CTAR0          0x000Cu  /* Clock/Xfer */
#define DSPI_SR             0x002Cu  /* Status     */
#define DSPI_RSER           0x0030u  /* DMA/IRQ    */
#define DSPI_PUSHR          0x0034u  /* TX FIFO    */
#define DSPI_POPR           0x0038u  /* RX FIFO    */
#define DSPI_TXFR0          0x003Cu  /* TX FIFO 0  */
#define DSPI_RXFR0          0x007Cu  /* RX FIFO 0  */

/* DSPI_MCR bits
   SDK defines these as function-like macros;
   undef first so our object-like versions work */
#undef  DSPI_MCR_MSTR
#define DSPI_MCR_MSTR       (1u << 31) /* Master   */
#undef  DSPI_MCR_HALT
#define DSPI_MCR_HALT       (1u << 0)  /* Halt     */
#undef  DSPI_MCR_CLR_TXF
#define DSPI_MCR_CLR_TXF    (1u << 11) /* Clr TX   */
#undef  DSPI_MCR_CLR_RXF
#define DSPI_MCR_CLR_RXF    (1u << 10) /* Clr RX   */

/* DSPI_SR bits                            */
#undef  DSPI_SR_TCF
#define DSPI_SR_TCF         (1u << 31) /* TX done  */
#undef  DSPI_SR_TXRXS
#define DSPI_SR_TXRXS       (1u << 30) /* Running  */
#undef  DSPI_SR_RFDF
#define DSPI_SR_RFDF        (1u << 17) /* RX ready */
#undef  DSPI_SR_TXCTR_MASK
#define DSPI_SR_TXCTR_MASK  0x0000F000u
#undef  DSPI_SR_RXCTR_MASK
#define DSPI_SR_RXCTR_MASK  0x000000F0u

/* DSPI_PUSHR bits                         */
#undef  DSPI_PUSHR_CONT
#define DSPI_PUSHR_CONT     (1u << 31) /* CS cont  */
#define DSPI_PUSHR_CTAS_0   (0u << 28) /* CTAR 0   */
#undef  DSPI_PUSHR_EOQ
#define DSPI_PUSHR_EOQ      (1u << 27) /* End queue*/
#undef  DSPI_PUSHR_CTCNT
#define DSPI_PUSHR_CTCNT    (1u << 26) /* Clr TC   */
#define DSPI_PUSHR_PCS0     (1u << 16) /* CS0 sel  */

/* ─────────────────────────────────────────
   GPIO for SPI chip select
   PA13 = SPI_CS on DEVKIT-MPC5748G
   Connected to SJA1105Q SS pin
   SIUL2 base = 0xFFFC0000
   GPDO offset = 0x1300
   ───────────────────────────────────────── */
#undef  SIUL2_BASE
#define SIUL2_BASE          0xFFFC0000u
#define SIUL2_GPDO_PA13     (SIUL2_BASE + 0x1300u \
                             + 13u)

/* ─────────────────────────────────────────
   Internal helpers
   ───────────────────────────────────────── */
static inline void dspi_write_reg(
    uint32_t offset,
    uint32_t value)
{
    *((volatile uint32_t*)(DSPI0_BASE + offset))
        = value;
}

static inline uint32_t dspi_read_reg(
    uint32_t offset)
{
    return *((volatile uint32_t*)
             (DSPI0_BASE + offset));
}

static inline void ss_assert(void)
{
    /* Pull CS LOW = select SJA1105Q      */
    *((volatile uint8_t*)SIUL2_GPDO_PA13) = 0u;
}

static inline void ss_deassert(void)
{
    /* Pull CS HIGH = deselect SJA1105Q   */
    *((volatile uint8_t*)SIUL2_GPDO_PA13) = 1u;
}

static inline void dspi_wait_tcf(void)
{
    /* Wait for Transfer Complete Flag    */
    while(!(dspi_read_reg(DSPI_SR) & 
            DSPI_SR_TCF));
    
    /* Clear TCF by writing 1             */
    dspi_write_reg(DSPI_SR, DSPI_SR_TCF);
}

static inline void dspi_wait_tx_empty(void)
{
    /* Wait until TX FIFO empty           */
    while(dspi_read_reg(DSPI_SR) & 
          DSPI_SR_TXCTR_MASK);
}

/* ─────────────────────────────────────────
   STEP 1: DSPI_0 Initialisation
   
   SJA1105Q SPI requirements:
   - CPOL = 1 (clock idle HIGH)
   - CPHA = 1 (sample on falling edge)
   - MSB first
   - Max 25MHz
   - 32-bit frame size
   We do two 32-bit transfers per
   SJA1105Q 64-bit frame
   ───────────────────────────────────────── */
void sja1105_spi_init(void)
{
    uart_log("[SPI] Initialising DSPI_0\r\n");

    /* ── Configure PA13 as GPIO output ─── */
    /* SIUL2 MSCR for PA13 = output GPIO   */
    *((volatile uint32_t*)
      (SIUL2_BASE + 0x0034u)) = 0x02000000u;
    /* OBE=1 output buffer enable          */

    /* ── Halt DSPI_0 ───────────────────── */
    dspi_write_reg(DSPI_MCR,
                   DSPI_MCR_MSTR |
                   DSPI_MCR_HALT |
                   DSPI_MCR_CLR_TXF |
                   DSPI_MCR_CLR_RXF);

    /* ── Configure CTAR0 ───────────────── */
    /* CPOL=1 CPHA=1 FMSZ=31 (32-bit)     */
    /* PBR=0 BR=3 → 160MHz/2/16 = 5MHz    */
    /* Conservative speed for reliability  */
    dspi_write_reg(DSPI_CTAR0,
                   (1u  << 26) |  /* CPOL=1      */
                   (1u  << 25) |  /* CPHA=1      */
                   (31u << 27) |  /* FMSZ=31     */
                   (0u  << 16) |  /* PBR=0 (/2)  */
                   (3u  << 12) |  /* BR=3 (/16)  */
                   (1u  << 8)  |  /* CSSCK=1     */
                   (1u  << 4)  |  /* ASC=1       */
                   (1u  << 0));   /* DT=1        */

    /* ── Disable DMA/IRQ ───────────────── */
    dspi_write_reg(DSPI_RSER, 0x00000000u);

    /* ── Start DSPI_0 ──────────────────── */
    dspi_write_reg(DSPI_MCR,
                   DSPI_MCR_MSTR);
    /* HALT=0 → running                    */

    /* ── Deassert CS initially ─────────── */
    ss_deassert();

    uart_log("[SPI] DSPI_0 ready at 5MHz\r\n");
}

/* ─────────────────────────────────────────
   STEP 2: Low level SPI transfer
   Sends one 64-bit SJA1105Q frame
   = two 32-bit DSPI transfers
   ───────────────────────────────────────── */
static void spi_transfer_64(
    uint32_t high_word,
    uint32_t low_word,
    uint32_t *rx_high,
    uint32_t *rx_low)
{
    uint32_t rx_h = 0;
    uint32_t rx_l = 0;

    /* ── Assert CS ─────────────────────── */
    ss_assert();

    /* ── Small setup delay ─────────────── */
    for(volatile int i = 0; i < 10; i++);

    /* ── Send high word ────────────────── */
    /* CONT=1 keeps CS asserted            */
    dspi_write_reg(DSPI_PUSHR,
                   DSPI_PUSHR_CONT |
                   DSPI_PUSHR_CTAS_0 |
                   DSPI_PUSHR_PCS0 |
                   high_word);

    dspi_wait_tcf();

    /* Read RX FIFO                        */
    if(dspi_read_reg(DSPI_SR) & 
       DSPI_SR_RXCTR_MASK)
    {
        rx_h = dspi_read_reg(DSPI_POPR);
    }

    /* ── Send low word ─────────────────── */
    /* CONT=0 releases CS after this word  */
    dspi_write_reg(DSPI_PUSHR,
                   DSPI_PUSHR_CTAS_0 |
                   DSPI_PUSHR_PCS0 |
                   low_word);

    dspi_wait_tcf();

    /* Read RX FIFO                        */
    if(dspi_read_reg(DSPI_SR) & 
       DSPI_SR_RXCTR_MASK)
    {
        rx_l = dspi_read_reg(DSPI_POPR);
    }

    /* ── Deassert CS ───────────────────── */
    ss_deassert();

    /* ── Small hold delay ──────────────── */
    for(volatile int i = 0; i < 10; i++);

    if(rx_high) *rx_high = rx_h;
    if(rx_low)  *rx_low  = rx_l;
}

/* ─────────────────────────────────────────
   STEP 3: Register write
   SJA1105Q 64-bit write frame:
   Bit 63:     1 (write)
   Bits 62-32: address (31 bits)
   Bits 31-0:  data
   ───────────────────────────────────────── */
void sja1105_reg_write(
    uint32_t addr,
    uint32_t data)
{
    /* Build high word:
       bit31 = 1 (write)
       bits30-0 = address                 */
    uint32_t high = 0x80000000u | 
                    (addr & 0x7FFFFFFFu);

    spi_transfer_64(high, data, NULL, NULL);
}

/* ─────────────────────────────────────────
   STEP 4: Register read
   SJA1105Q 64-bit read frame:
   Bit 63:     0 (read)
   Bits 62-32: address (31 bits)
   Bits 31-0:  0 (dummy)
   Response comes in next 32 bits
   ───────────────────────────────────────── */
uint32_t sja1105_reg_read(uint32_t addr)
{
    uint32_t high = addr & 0x7FFFFFFFu;
    uint32_t rx_l = 0;

    spi_transfer_64(high, 0x00000000u,
                    NULL, &rx_l);

    return rx_l;
}

/* ─────────────────────────────────────────
   STEP 5: Verify SJA1105Q device ID
   Expected: 0x9F00030E (SJA1105Q)
   ───────────────────────────────────────── */
uint32_t sja1105_read_device_id(void)
{
    return sja1105_reg_read(
               SJA1105_REG_DEVICE_ID);
}

uint8_t sja1105_verify_device(void)
{
    uint32_t id = sja1105_read_device_id();

    uart_log("[SPI] SJA1105Q Device ID: 0x");
    uart_log_hex(id);
    uart_log("\r\n");

    /* SJA1105Q = 0x9F00030E
       SJA1105S = 0xAE00030E (same EVB, different silicon) */
    if(id == 0x9F00030Eu || id == 0xAE00030Eu)
    {
        uart_log("[SPI] Device verified OK\r\n");
        return 1u;
    }
    else
    {
        uart_log("[SPI] Device ID MISMATCH\r\n");
        return 0u;
    }
}

/* ─────────────────────────────────────────
   STEP 6: Configure VLAN table

   PoC VLAN layout:
   ════════════════
   VLAN 10 → Attacker laptop port (Port 0)
   VLAN 20 → MPC5748G RGMII port (Port 4)
   VLAN 30 → IDS monitor port    (Port 1)

   Retag rule:
   VLAN 10 ingress Port 0
   → retag to VLAN 20
   → forward to Port 4 (MPC5748G)

   VLAN 20 ingress Port 4
   → retag to VLAN 10
   → forward to Port 0 (attacker)

   Mirror rule:
   All traffic on Port 0
   → copy to Port 1 (IDS monitor)
   ───────────────────────────────────────── */
void sja1105_configure_vlan(void)
{
    uart_log("[SPI] Configuring VLAN table\r\n");

    /* ── VLAN 10: Attacker port ─────────── */
    /* Member ports: Port 0 + Port 4        */
    /* Tag on egress: Port 0 (to attacker)  */
    /* Untag on egress: Port 4 (to gateway) */
    sja1105_vlan_add_entry(
        VLAN_ATTACKER,   /* vlan_id = 10    */
        0x11u,           /* members: P0+P4  */
        0x01u,           /* tag: P0         */
        0x10u            /* untag: P4       */
    );

    /* ── VLAN 20: Gateway port ──────────── */
    /* Member ports: Port 0 + Port 4        */
    /* Tag on egress: Port 4 (to gateway)   */
    /* Untag on egress: Port 0 (to attacker)*/
    sja1105_vlan_add_entry(
        VLAN_GATEWAY,    /* vlan_id = 20    */
        0x11u,           /* members: P0+P4  */
        0x10u,           /* tag: P4         */
        0x01u            /* untag: P0       */
    );

    /* ── VLAN 30: Monitor port ──────────── */
    /* Member ports: Port 1 only            */
    /* Tag on egress: Port 1 (to IDS)       */
    sja1105_vlan_add_entry(
        VLAN_MONITOR,    /* vlan_id = 30    */
        0x02u,           /* members: P1     */
        0x02u,           /* tag: P1         */
        0x00u            /* untag: none     */
    );

    uart_log("[SPI] VLAN table configured\r\n");
}

/* ─────────────────────────────────────────
   STEP 7: Add one VLAN entry to SJA1105Q
   VLAN lookup table entry format:
   Word 0 (high):
     bits 31-12: VLANID (12 bits at [31:20])
     bits 19-15: TAGPORT (5 bits)
     bits 14-10: VLANBC  (5 bits)
     bits 9-5:   VMEMB   (5 bits)
     bits 4-0:   VEGR    (5 bits)
   Word 1 (low):
     bits 31-27: VEGR continued
     ...
   ───────────────────────────────────────── */
void sja1105_vlan_add_entry(
    uint16_t vlan_id,
    uint8_t  member_ports,
    uint8_t  tag_ports,
    uint8_t  untag_ports)
{
    /* Calculate register address for
       this VLAN ID in lookup table       */
    uint32_t addr = SJA1105_REG_VLAN_LOOKUP
                    + vlan_id;

    /* Build entry word
       Simplified: pack fields into 32-bit */
    uint32_t entry =
        ((uint32_t)(vlan_id    & 0xFFFu) << 20) |
        ((uint32_t)(tag_ports  & 0x1Fu)  << 15) |
        ((uint32_t)(member_ports & 0x1Fu) << 10) |
        ((uint32_t)(untag_ports & 0x1Fu) << 5);

    sja1105_reg_write(addr, entry);

    uart_log("[SPI] VLAN ");
    uart_log_uint(vlan_id);
    uart_log(" entry written\r\n");
}

/* ─────────────────────────────────────────
   STEP 8: Configure VLAN retag

   Retag = change VLAN tag on packet
   as it passes through switch

   Used to:
   - Strip VLAN 10 from attacker packet
   - Add VLAN 20 before sending to gateway
   - Strip VLAN 20 from gateway reply
   - Add VLAN 10 before sending to attacker

   SJA1105Q retag via L2 forwarding table
   ───────────────────────────────────────── */
void sja1105_configure_retag(
    uint16_t src_vlan,
    uint16_t dst_vlan,
    uint8_t  src_port,
    uint8_t  dst_port)
{
    uart_log("[SPI] Configuring retag ");
    uart_log_uint(src_vlan);
    uart_log(" → ");
    uart_log_uint(dst_vlan);
    uart_log("\r\n");

    /* L2 forwarding table entry:
       Ingress VLAN src_vlan on src_port
       → Egress VLAN dst_vlan on dst_port

       Register: SJA1105_REG_L2_FWD
       + port offset                      */

    uint32_t fwd_addr = SJA1105_REG_L2_FWD
                        + src_port;

    /* Build forwarding entry:
       DESTPORTS = dst_port bitmask
       VLAN_PMAP = dst_vlan mapping       */
    uint32_t fwd_entry =
        ((uint32_t)(1u << dst_port) << 16) |
        ((uint32_t)(dst_vlan & 0xFFFu));

    sja1105_reg_write(fwd_addr, fwd_entry);

    /* Write retag entry in VLAN table    */
    uint32_t retag_addr = 
        SJA1105_REG_VLAN_LOOKUP + src_vlan;

    uint32_t retag_entry =
        ((uint32_t)(dst_vlan & 0xFFFu) << 20) |
        ((uint32_t)(1u << dst_port) << 10);

    sja1105_reg_write(retag_addr, retag_entry);

    uart_log("[SPI] Retag configured\r\n");
}

/* Runtime mirror writes were removed for ChainRecon: mirroring is part of
   the static configuration uploaded at boot (MIRR_PTACU = 0 locks it).  */

/* ─────────────────────────────────────────
   STEP 12: Upload static config block
   Must be called BEFORE sja1105_verify_device()
   because verification reads the device ID
   which is written as first word of config.

   SJA1105Q config upload SPI protocol:
   Write len/4 consecutive 32-bit words
   starting at config area address 0.
   Each word written as a 64-bit SJA frame
   (WRITE | addr, data).
   ───────────────────────────────────────── */
void sja1105_upload_config(
    const uint8_t *cfg,
    uint32_t       len)
{
    uint32_t word_count = len / 4u;
    uint32_t i;

    uart_log("[SPI] Uploading static config...\r\n");
    uart_log("[SPI] Size: ");
    uart_log_uint(len);
    uart_log(" bytes\r\n");

    for(i = 0u; i < word_count; i++)
    {
        uint32_t word =
            ((uint32_t)cfg[i*4u + 0u])       |
            ((uint32_t)cfg[i*4u + 1u] << 8)  |
            ((uint32_t)cfg[i*4u + 2u] << 16) |
            ((uint32_t)cfg[i*4u + 3u] << 24);

        /* Config area addressed as word index */
        sja1105_reg_write(i, word);
    }

    uart_log("[SPI] Config upload done\r\n");
}