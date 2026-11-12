/* ─────────────────────────────────────────
   sja1105_spi.h
   SJA1105Q SPI driver header
   Covers:
   - SPI init
   - Register read/write
   - Mirror configure
   - VLAN retag configure
   ───────────────────────────────────────── */

#ifndef SJA1105_SPI_H
#define SJA1105_SPI_H

#include <stdint.h>

/* ─────────────────────────────────────────
   SJA1105Q Register Addresses
   All addresses are 32-bit word addresses
   ───────────────────────────────────────── */

/* Device ID register                      */
#define SJA1105_REG_DEVICE_ID       0x000000u

/* Port status registers                   */
#define SJA1105_REG_PORT_STATUS_MII0 0x000900u
#define SJA1105_REG_PORT_STATUS_MII1 0x000901u
#define SJA1105_REG_PORT_STATUS_MII2 0x000902u
#define SJA1105_REG_PORT_STATUS_MII3 0x000903u
#define SJA1105_REG_PORT_STATUS_MII4 0x000904u

/* General parameters                      */
#define SJA1105_REG_GENERAL_PARAMS  0x000B00u

/* Mirror port register
   Controls which port is mirrored
   and where mirror traffic goes          */
#define SJA1105_REG_MIRROR_PORT     0x000C04u

/* VLAN lookup table base                  */
#define SJA1105_REG_VLAN_LOOKUP     0x002700u

/* MAC configuration table base            */
#define SJA1105_REG_MAC_CONFIG      0x000E00u

/* L2 forwarding table base                */
#define SJA1105_REG_L2_FWD          0x001000u

/* L2 forwarding parameters                */
#define SJA1105_REG_L2_FWD_PARAMS   0x001F00u

/* Clock synchronisation                   */
#define SJA1105_REG_PTP_CTRL        0x001700u

/* ─────────────────────────────────────────
   SJA1105Q Port Definitions
   ───────────────────────────────────────── */
#define SJA_PORT_0      0u  /* MII  - ETH PHY 1  */
#define SJA_PORT_1      1u  /* MII  - ETH PHY 2  */
#define SJA_PORT_2      2u  /* RMII - ETH PHY 3  */
#define SJA_PORT_3      3u  /* RMII - ETH PHY 4  */
#define SJA_PORT_4      4u  /* RGMII - to MPC5748G */

/* ─────────────────────────────────────────
   VLAN IDs used in PoC
   ───────────────────────────────────────── */
#define VLAN_ATTACKER   10u  /* attacker laptop   */
#define VLAN_GATEWAY    20u  /* MPC5748G          */
#define VLAN_MONITOR    30u  /* IDS monitor port  */

/* ─────────────────────────────────────────
   Mirror configuration structure
   ───────────────────────────────────────── */
typedef struct {
    uint8_t  mirror_src_port;
    uint8_t  mirror_dst_port;
    uint8_t  mirror_enabled;
    uint32_t mirror_reg_value;
} sja1105_mirror_cfg_t;

/* ─────────────────────────────────────────
   VLAN retag entry structure
   ───────────────────────────────────────── */
typedef struct {
    uint16_t vlan_id;
    uint8_t  port_mask;
    uint8_t  tag_port_mask;
    uint8_t  untag_port_mask;
} sja1105_vlan_entry_t;

/* ─────────────────────────────────────────
   SPI frame format for SJA1105Q
   64-bit frame:
   Bit 63:     1=write 0=read
   Bits 62-32: register address (31 bits)
   Bits 31-0:  data
   ───────────────────────────────────────── */
typedef struct {
    uint32_t high_word;  /* address + RW bit  */
    uint32_t low_word;   /* data              */
} sja1105_spi_frame_t;

/* ─────────────────────────────────────────
   Function prototypes
   ───────────────────────────────────────── */

/* Init DSPI_0 peripheral                  */
void sja1105_spi_init(void);

/* Low level SPI read/write                */
uint32_t sja1105_reg_read(uint32_t addr);
void     sja1105_reg_write(uint32_t addr,
                            uint32_t data);

/* No runtime mirror API: mirroring is static boot configuration. */

/* VLAN configuration                      */
void sja1105_configure_vlan(void);

void sja1105_vlan_add_entry(
    uint16_t vlan_id,
    uint8_t  member_ports,
    uint8_t  tag_ports,
    uint8_t  untag_ports);

/* VLAN retag between ports                */
void sja1105_configure_retag(
    uint16_t src_vlan,
    uint16_t dst_vlan,
    uint8_t  src_port,
    uint8_t  dst_port);

/* Static config upload (call before verify) */
void sja1105_upload_config(const uint8_t *cfg,
                           uint32_t       len);

/* Device verification                     */
uint32_t sja1105_read_device_id(void);
uint8_t  sja1105_verify_device(void);

#endif /* SJA1105_SPI_H */