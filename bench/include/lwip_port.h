/* lwip_port.h — LWIP port for MPC5748G ENET / KSZ8081 */
#ifndef LWIP_PORT_H
#define LWIP_PORT_H

#include <stdint.h>
#include "enet_dma.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

#define GATEWAY_IP_ADDR0    192u
#define GATEWAY_IP_ADDR1    168u
#define GATEWAY_IP_ADDR2    10u
#define GATEWAY_IP_ADDR3    1u

#define GATEWAY_NETMASK0    255u
#define GATEWAY_NETMASK1    255u
#define GATEWAY_NETMASK2    255u
#define GATEWAY_NETMASK3    0u

#define GATEWAY_GW0         192u
#define GATEWAY_GW1         168u
#define GATEWAY_GW2         10u
#define GATEWAY_GW3         254u

#define GATEWAY_MAC0        0x02u
#define GATEWAY_MAC1        0x00u
#define GATEWAY_MAC2        0x00u
#define GATEWAY_MAC3        0x00u
#define GATEWAY_MAC4        0x00u
#define GATEWAY_MAC5        0x01u

/* ENET register offsets */
#define ENET_ECR            0x0024u
#define ENET_MMFR           0x0040u
#define ENET_MSCR           0x0044u
#define ENET_MIBC           0x0064u
#define ENET_RCR            0x0084u
#define ENET_TCR            0x00C4u
#define ENET_PALR           0x00E4u
#define ENET_PAUR           0x00E8u
#define ENET_OPD            0x00ECu
#define ENET_IAUR           0x0118u
#define ENET_IALR           0x011Cu
#define ENET_GAUR           0x0120u
#define ENET_GALR           0x0124u
#define ENET_TFWR           0x0144u
#define ENET_RDSR           0x0180u
#define ENET_TDSR           0x0184u
#define ENET_MRBR           0x0188u
#define ENET_RDAR           0x0010u
#define ENET_TDAR           0x0014u
#define ENET_EIR            0x0004u
#define ENET_EIMR           0x0008u

void     lwip_init_port(void);
void     lwip_poll(void);
err_t    enet_dma_send_frame(uint8_t *buf, uint16_t len);
void     phy_init(void);
uint16_t phy_read(uint8_t reg);
void     phy_write(uint8_t reg, uint16_t val);
uint8_t  phy_wait_link(uint32_t timeout_ms);

#endif
