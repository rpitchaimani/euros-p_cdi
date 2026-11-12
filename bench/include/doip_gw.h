/* doip_gw.h -- core 1: diagnostic gateway and bench control endpoint. */
#ifndef DOIP_GW_H
#define DOIP_GW_H

#include <stdint.h>

void gw_init(void);                 /* binds UDP DOIP_PORT and CTRL_PORT     */
void gw_poll(void);                 /* CAN RX, target TX queue, control acks */

#endif
