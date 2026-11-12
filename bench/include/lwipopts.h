/* lwipopts.h — LwIP configuration, bare-metal MPC5748G */
#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0

#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (16 * 1024)
#define MEMP_NUM_PBUF               32
#define MEMP_NUM_UDP_PCB            4
#define MEMP_NUM_TCP_PCB            4
#define MEMP_NUM_TCP_SEG            32
#define PBUF_POOL_SIZE              32
#define PBUF_POOL_BUFSIZE           1536

#define LWIP_ARP                    1
#define LWIP_ETHERNET               1
#define LWIP_IPV4                   1
#define LWIP_UDP                    1
#define LWIP_TCP                    1
#define LWIP_ICMP                   1
#define LWIP_RAW                    0
#define LWIP_DHCP                   0

#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_UDP            1
#define CHECKSUM_GEN_TCP            1
#define CHECKSUM_CHECK_IP           1
#define CHECKSUM_CHECK_UDP          0
#define CHECKSUM_CHECK_TCP          0

#define LWIP_STATS                  0
#define LWIP_PROVIDE_ERRNO          1
#define ETH_PAD_SIZE                0

#endif
