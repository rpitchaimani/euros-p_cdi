/* can_drv.h -- FlexCAN_0 driver (core 1 only), 500 kbit/s.
 * Legacy RX FIFO (6 deep) accepts every standard frame; self-reception is on,
 * so frames this controller sends are also read back from the bus.  That is
 * how the destination-zone observer and the target ECU see the gateway's
 * requests: through the controller's receive path, not through software.
 */
#ifndef CAN_DRV_H
#define CAN_DRV_H

#include <stdint.h>

void    can_init(void);
/* returns 1 on success, 0 on TX timeout (counted in SHM_C1_CAN_TX_TO) */
uint8_t can_tx(uint32_t id, const uint8_t *data, uint8_t dlc);
/* returns 1 and fills the frame if one was waiting */
uint8_t can_rx(uint32_t *id, uint8_t *dlc, uint8_t data[8]);

#endif
