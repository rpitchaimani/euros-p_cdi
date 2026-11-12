/*
** MPC5748G_core1.ld
** Core 1 (Z4b, 160 MHz) — Ethernet/UDP/CAN gateway
** Flash: 0x011D0000, 1856 KB
** SRAM:  0x40040000, 256 KB (Core 1 bss/stack)
**
** Entry point: core1_entry  (core1_entry.S)
** core1_entry sets SP = _stack_core1_top then calls main()
** main() is core1_gateway.c::main()
**
** NOTE: Core 1 BSS at 0x40040000 is already ECC-initialised
** by Core 0's startup_MPC5748G.S before Core 0 releases Core 1.
** No separate data-copy startup is needed because all Core 1
** globals are zero-initialised (BSS only, no non-zero .data).
*/

ENTRY(core1_entry)

__STACK_SIZE = 0x00002000;   /* 8 KB stack for Core 1 */

MEMORY
{
    m_text  : org = 0x011D0000, len = 1856K
    m_sram1 : org = 0x40040000, len = 256K
}

SECTIONS
{
    /* Entry stub must be first — MC_ME CADDR1 = 0x011D0000 */
    .core1_startup : ALIGN(0x10)
    {
        KEEP(*(.core1_startup))
    } > m_text

    .text   : { *(.text) *(.text.*) KEEP(*(.init)) KEEP(*(.fini)) } > m_text
    .rodata : { *(.rodata) *(.rodata.*) } > m_text
    .sdata2 : { __sdata2_c1_start__ = .; *(.sdata2) *(.sdata2.*) __sdata2_c1_end__ = .; } > m_text
    .got2   : { *(.got2*) } > m_text

    __TEXT_END_C1 = .;

    /* No .data copy — all Core 1 globals are BSS (zero-init).
       If non-zero initialised globals are ever added, add a .data
       section with AT(__TEXT_END_C1) and a startup copy loop. */

    /* Small-data area (.sdata/.sbss) — must be placed so r13 (_SDA_BASE_)
       can reach every element via a 21-bit signed offset (±1 MB).
       LwIP uses SDA21 relocations for module-static variables like
       etharp_cached_entry, so these sections must be explicit. */
    .sdata : ALIGN(4)
    {
        __SDATA_C1_START = .;
        *(.sdata)
        *(.sdata.*)
        *(.gnu.linkonce.s.*)
        . = ALIGN(4);
        __SDATA_C1_END = .;
    } > m_sram1

    .sbss (NOLOAD) : ALIGN(4)
    {
        __SBSS_C1_START = .;
        *(.sbss)
        *(.sbss.*)
        *(.gnu.linkonce.sb.*)
        . = ALIGN(4);
        __SBSS_C1_END = .;
    } > m_sram1

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        __BSS_C1_START = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(4);
        __BSS_C1_END = .;
    } > m_sram1

    .stack_core1 (NOLOAD) : ALIGN(16)
    {
        . += __STACK_SIZE;
        . = ALIGN(16);
        _stack_core1_top = .;
    } > m_sram1

    /* SDA base pointers loaded into r13 / r2 by core1_entry.S.
       _SDA_BASE_  must be reachable from all .sdata/.sbss via ±1 MB offset.
       _SDA2_BASE_ points to .sdata2 (read-only, in flash). */
    _SDA_BASE_  = __SDATA_C1_START;
    _SDA2_BASE_ = __sdata2_c1_start__;
}
