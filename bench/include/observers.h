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

/* Emulated compromise of the gw observer (forgery experiment).
 *   FORGE_NONE    genuine reports only
 *   FORGE_EXO     in each T_w window, independently of the attack, the gw
 *                 observer is genuine with probability alpha (ppm); in other
 *                 windows each of its reports is replaced by a fixed benign
 *                 template from a fake session (Assumption 1(iii))
 *   FORGE_ATTACK  once the attacker's unauthorised write passes the gateway,
 *                 the gw observer reports that write and every later decision
 *                 as allowed and authenticated (forgery caused by the attack)
 * Replaced genuine reports stay in the delivery log as DLV_FORGED_OUT; the
 * forgeries are delivered and logged with EVF_FORGED. */
#define FORGE_NONE    0u
#define FORGE_EXO     1u
#define FORGE_ATTACK  2u
void obs_set_forge(uint8_t mode, uint32_t alpha_ppm, uint32_t seed);
void obs_eth_frame(const uint8_t *frame, uint16_t len);
void obs_gw_event(uint8_t kind, const uint8_t d[20]);
void obs_can_frame(uint32_t id, uint8_t dlc, const uint8_t data[8]);

#endif
