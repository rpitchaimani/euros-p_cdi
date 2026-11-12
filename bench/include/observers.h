/* observers.h -- core 1 observers and the observation interface.
 *
 * Three observers run on the gateway core and write fixed 32-byte events into
 * one SPSC ring that the IDS core (core 0) drains:
 *   OBS_SRC  every Ethernet frame received from the source zone (packet level)
 *   OBS_GW   every gateway routing / policy decision (semantic)
 *   OBS_DST  every frame on the destination-zone CAN bus (frame level)
 * The trial's observer mask selects which observers are delivered (scope).
 * Every non-background event is also written to the delivery log with its
 * status (delivered / masked / ring full), so the host can tell missing
 * evidence from late evidence.
 */
#ifndef OBSERVERS_H
#define OBSERVERS_H

#include <stdint.h>
#include "shared_mem.h"

void obs_trial_reset(void);                 /* core 1, on START          */
void obs_eth_frame(const uint8_t *frame, uint16_t len);
void obs_gw_event(uint8_t kind, const uint8_t d[20]);
void obs_can_frame(uint32_t id, uint8_t dlc, const uint8_t data[8]);

#endif
