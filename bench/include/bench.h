/* bench.h -- ChainRecon bench constants shared by all cores and mirrored in
 * python/bench_proto.py.  Change both together.
 */
#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>

/* ---------------- timing ---------------- */
#define IDS_WINDOW_MS        100u      /* T_w                           */

/* ---------------- UDP ports ---------------- */
#define DOIP_PORT            13400u    /* DoIP messages carried over UDP */
#define CTRL_PORT            13499u    /* bench control (not observed)   */
#define BG_PORT              30490u    /* background load sink (observed as BG) */

/* ---------------- DoIP (ISO 13400-2 message formats) ---------------- */
#define DOIP_VER             0x02u
#define DOIP_INV             0xFDu
#define DOIP_HDR_LEN         8u
#define DOIP_VIR             0x0001u   /* vehicle identification request */
#define DOIP_VAM             0x0004u   /* vehicle announcement / resp     */
#define DOIP_RA_REQ          0x0005u   /* routing activation request      */
#define DOIP_RA_RESP         0x0006u
#define DOIP_DIAG            0x8001u   /* diagnostic message              */
#define DOIP_DIAG_ACK        0x8002u
#define DOIP_DIAG_NACK       0x8003u

#define LA_GATEWAY           0x1000u   /* gateway logical address        */
#define LA_TARGET            0x0010u   /* target ECU A, destination zone */
#define LA_TARGET_B          0x0011u   /* target ECU B, destination zone */
#define LA_OTHER_ZONE        0x0020u   /* ECU behind a closed route       */
#define N_TARGETS            2u
#define LA_TESTER_MIN        0x0E00u   /* external test equipment range  */
#define LA_TESTER_MAX        0x0EFFu

/* ---------------- CAN identifiers (destination zone) ---------------- */
#define CANID_DIAG_REQ       0x7E0u    /* gateway -> target A (ISO-TP SF) */
#define CANID_DIAG_RESP      0x7E8u    /* target A -> gateway             */
#define CANID_DIAG_REQ_B     0x7E1u    /* gateway -> target B             */
#define CANID_DIAG_RESP_B    0x7E9u    /* target B -> gateway             */
#define CANID_IMPACT         0x1A0u    /* shared test-actuator message:
                                          [value, counter, src, 0...]; src
                                          = 1/2 (ECU A/B) only if the trial
                                          sets CFGF_IMPACT_SRC, else 0     */
#define CANID_SYNC           0x7F0u    /* bench time-sync beacon          */

/* trial flags (SHM_CFG_FLAGS) */
#define CFGF_IMPACT_SRC      0x01u     /* impact message names its ECU    */

static inline int is_diag_req(uint32_t id)  { return id == CANID_DIAG_REQ  || id == CANID_DIAG_REQ_B; }
static inline int is_diag_resp(uint32_t id) { return id == CANID_DIAG_RESP || id == CANID_DIAG_RESP_B; }

/* ---------------- UDS ---------------- */
#define UDS_DSC              0x10u     /* DiagnosticSessionControl       */
#define UDS_SA               0x27u     /* SecurityAccess                 */
#define UDS_RDBI             0x22u
#define UDS_WDBI             0x2Eu
#define UDS_TP               0x3Eu
#define UDS_NEG              0x7Fu
#define DID_TEST_STATE       0xF1A0u   /* test-mode DID on the target    */
#define SA_KEY_XOR           0x5A5Au   /* key = seed ^ SA_KEY_XOR        */

/* ---------------- gateway decisions ---------------- */
#define GWD_ALLOW            1u
#define GWD_AUDIT            2u   /* forwarded, recorded as violation   */
#define GWD_DENY             3u

#define GWR_OK               0u
#define GWR_NO_RA            1u   /* no routing activation for session  */
#define GWR_ROUTE_CLOSED     2u   /* target in a zone with no route     */
#define GWR_UNKNOWN_TA       3u
#define GWR_SID_BLOCKED      4u
#define GWR_WRITE_NOAUTH     5u   /* write without security access      */
#define GWR_BAD_SA           6u

/* ---------------- event kinds ----------------
 * OBS_SRC payload d[20]:
 *   [0..3] src IPv4  [4..5] src port  [6..7] dst port
 *   [8..9] DoIP payload type (0 if not DoIP)  [10..11] DoIP payload length
 *   [12..19] first 8 bytes of DoIP payload (SA,TA,UDS...)
 * OBS_GW payload d[20]:
 *   [0..3] tester IPv4  [4..5] tester port  [6..7] SA  [8..9] TA
 *   [10] decision  [11] reason  [12] UDS SID (or resp SID)  [13] sub/NRC
 *   [14..15] DID  [16] auth  [17] diag session  [18..19] route sequence
 * OBS_DST payload d[20]:
 *   [0..3] CAN id  [4] dlc  [5..12] data  [13..19] zero
 */
#define EK_ETH_OTHER         1u
#define EK_ETH_DOIP          2u
#define EK_GW_VIR            10u
#define EK_GW_RA             11u
#define EK_GW_ROUTE          12u  /* request decision (allow/audit/deny)  */
#define EK_GW_RESP           13u  /* response routed back to a session    */
#define EK_GW_RESP_ORPHAN    14u
#define EK_CAN               20u

#endif /* BENCH_H */
