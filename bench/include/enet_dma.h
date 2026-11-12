/* enet_dma.h — ENET DMA ring types, no LwIP dependency */
#ifndef ENET_DMA_H
#define ENET_DMA_H

#include <stdint.h>

#define ENET0_BASE          0xFFCC4000u

#define RX_RING_SIZE        16u
#define TX_RING_SIZE        8u
#define ENET_BUFFER_SIZE    1536u

typedef struct {
    uint16_t  status;
    uint16_t  length;
    uint8_t  *buffer;
} enet_bd_t;

/* RX BD status bits */
#define BD_RX_EMPTY         0x8000u
#define BD_RX_WRAP          0x2000u
#define BD_RX_LAST          0x0800u
#define BD_RX_MISS          0x0100u
#define BD_RX_ERROR         0x0037u

/* TX BD status bits */
#define BD_TX_READY         0x8000u
#define BD_TX_WRAP          0x2000u
#define BD_TX_LAST          0x0800u
#define BD_TX_TC            0x0400u

uint16_t enet_dma_read_frame(uint8_t *buf, uint16_t buf_size);

#endif /* ENET_DMA_H */
