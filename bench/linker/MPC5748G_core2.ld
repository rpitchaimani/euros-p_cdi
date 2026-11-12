/*
** MPC5748G_core2.ld
** Core 2 (Z2, 80 MHz) — Observer Core (pure IDS, no app code)
** Flash: 0x013A0000, 768 KB
** SRAM:  0x400A0000, 128 KB (Core 2 private bss/stack)
**        SMPU Region 1 blocks Z4a and Z4b from accessing this range.
**
** Entry point: core2_entry  (core2_entry.S)
** core2_entry sets SP = _stack_core2_top then calls core2_main()
** core2_main() is core2_observer.c::core2_main()
**
** CPU: e200z2 — no PMC, no cache, single-issue VLE.
** Use -mcpu=e200z2 (not e200z4) for this project.
*/

ENTRY(core2_entry)

__C2_STACK_SIZE = 0x00001000;   /* 4 KB stack for Core 2 */

MEMORY
{
    m_text  : org = 0x013A0000, len = 768K
    m_sram2 : org = 0x400A0000, len = 128K
}

SECTIONS
{
    /* Entry stub must be first — MC_ME CADDR2 = 0x013A0000 */
    .core2_startup : ALIGN(0x10)
    {
        KEEP(*(.core2_startup))
    } > m_text

    .text   : { *(.text) *(.text.*) } > m_text
    .rodata : { *(.rodata) *(.rodata.*) } > m_text

    /* Small-data area — core2_observer.c has module-static variables like
       g_alert_seq that the compiler places in .sbss.* via SDA21 reloc.
       r13 must hold _SDA_BASE_ at entry (set by core2_entry.S). */
    .sdata : ALIGN(4)
    {
        __SDATA_C2_START = .;
        *(.sdata)
        *(.sdata.*)
        *(.gnu.linkonce.s.*)
        . = ALIGN(4);
        __SDATA_C2_END = .;
    } > m_sram2

    .sbss (NOLOAD) : ALIGN(4)
    {
        __SBSS_C2_START = .;
        *(.sbss)
        *(.sbss.*)
        *(.gnu.linkonce.sb.*)
        . = ALIGN(4);
        __SBSS_C2_END = .;
    } > m_sram2

    .bss_core2 (NOLOAD) : ALIGN(16)
    {
        . = ALIGN(4);
        __BSS_CORE2_START = .;
        *(.bss)
        *(.bss.*)
        *(.bss_core2)
        *(.bss_core2.*)
        *(COMMON)
        . = ALIGN(4);
        __BSS_CORE2_END = .;
    } > m_sram2

    .stack_core2 (NOLOAD) : ALIGN(16)
    {
        . += __C2_STACK_SIZE;
        . = ALIGN(16);
        _stack_core2_top = .;
    } > m_sram2

    /* SDA base pointers — loaded into r13 / r2 by core2_entry.S.
       Core 2 has no .sdata2 content, so _SDA2_BASE_ points to the
       .rodata base (safe; all SDA2 accesses would be read-only anyway). */
    _SDA_BASE_  = __SDATA_C2_START;
    _SDA2_BASE_ = ADDR(.rodata);
}
