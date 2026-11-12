/* clock_init.c
   System clock init for DEVKIT-MPC5748G.
   Result: sysclk=160MHz, LINCLK(S80)=80MHz
*/

#include "MPC5748G.h"
#include "clock_init.h"
#include <stdint.h>

void clock_init(void)
{
    /* ── 1. Clock dividers (must be set before PLL) ──────── */
    MC_CGM->SC_DC0 = MC_CGM_SC_DC0_DE_MASK |
                     MC_CGM_SC_DC0_DIV(0u);   /* F160 = sysclk/1 = 160MHz  */

    MC_CGM->SC_DC1 = MC_CGM_SC_DC1_DE_MASK |
                     MC_CGM_SC_DC1_DIV(1u);   /* S80  = sysclk/2 = 80MHz   */

    MC_CGM->SC_DC5 = MC_CGM->SC_DC1;          /* FS80 must equal S80       */

    MC_CGM->SC_DC2 = 0x80030000u;             /* S40  = sysclk/4 = 40MHz   */

    /* ── 2. PLL input = XOSC (40 MHz crystal) ───────────── */
    MC_CGM->AC5_SC = (MC_CGM->AC5_SC & ~MC_CGM_AC5_SC_SELCTL_MASK) |
                      MC_CGM_AC5_SC_SELCTL(1u);

    /* ── 3. PLL config: 40MHz XOSC → 160MHz PHI0 ────────── */
    /* PREDIV=1  MFD=16  RFDPHI=1  → VCO=640MHz, PHI0=160MHz */
    PLLDIG->PLLDV = PLLDIG_PLLDV_PREDIV(1u) |
                    PLLDIG_PLLDV_MFD(16u)    |
                    PLLDIG_PLLDV_RFDPHI(1u);

    PLLDIG->PLLCAL3 = 0x09C3C000u;
    PLLDIG->PLLFD   = PLLDIG_PLLFD_SMDEN_MASK;

    /* ── 4. Enable peripheral clocks ────────────────────── */
    MC_ME->RUN_PC[0] = 0x00000000u;
    MC_ME->RUN_PC[1] = 0x000000FEu;
    MC_ME->PCTLn[15] = 0x01u;         /* ENET      → use RUN_PC[1]       */
    MC_ME->PCTLn[52] = 0x01u;         /* LINFlex_2 → use RUN_PC[1]       */
    MC_ME->PCTLn[70] = 0x01u;         /* FlexCAN_0 → use RUN_PC[1]       */

    /* ── 5. DRUN mode: SYSCLK=PLL, PLL+XOSC+IRC on ──────── */
    MC_ME->DRUN_MC = 0x00130072u;

    /* ── 6. Mode transition → applies all config above ───── */
    MC_ME->MCTL = 0x30005AF0u;   /* Enter DRUN, key1 */
    MC_ME->MCTL = 0x3000A50Fu;   /* Enter DRUN, key2 */
    while (MC_ME->GS & MC_ME_GS_S_MTRANS_MASK);
}
