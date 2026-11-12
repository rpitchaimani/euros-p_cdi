/*
** MPC5748G_core0.ld
** Core 0 (Z4a, 80 MHz) — attack target + PMC sampler
** Flash: 0x01000000, 1856 KB
** SRAM:  0x40000000, 256 KB (Core 0 data/bss/stack)
** Shared SRAM: 0x40080000, 8 KB
*/

ENTRY(_start)

__STACK_SIZE    = 0x00002000;
__HEAP_SIZE     = 0x00000000;

FLASH_BASE_ADDR = 0x01000000;
FLASH_SIZE      = 1856K;
SRAM_BASE_ADDR  = 0x40000000;
SRAM_SIZE       = 256K;

MEMORY
{
    flash_rchw      : org = 0x00FA0000,         len = 0x4
    cpu0_reset_vec  : org = 0x00FA0010,         len = 0x4
    cpu1_reset_vec  : org = 0x00FA0014,         len = 0x4
    cpu2_reset_vec  : org = 0x00FA0004,         len = 0x4

    m_text          : org = 0x01000000,         len = 1856K
    m_data          : org = 0x40000000,         len = 256K
    m_shared        : org = 0x40080000,         len = 128K
}

__RAM_VECTOR_TABLE_SIZE = 0xC00;

SECTIONS
{
    .rchw :
    {
        KEEP(*(.rchw))
    } > flash_rchw

    .cpu0_reset_vector :
    {
        KEEP(*(.cpu0_reset_vector))
    } > cpu0_reset_vec

    .cpu1_reset_vector :
    {
        KEEP(*(.cpu1_reset_vector))
    } > cpu1_reset_vec

    .cpu2_reset_vector :
    {
        KEEP(*(.cpu2_reset_vector))
    } > cpu2_reset_vec

    .startup : ALIGN(0x400)
    {
        __start = .;
        *(.startup)
    } > m_text

    .core_exceptions_table : ALIGN(4096)
    {
        __IVPR_VALUE = .;
        *(.core_exceptions_table)
    } > m_text

    .intc_vector_table : ALIGN(4096)
    {
        __VECTOR_TABLE = .;
        __interrupts_start__ = .;
        KEEP(*(.intc_vector_table))
        __interrupts_end__ = .;
    } > m_text

    __VECTOR_TABLE_COPY_END = __VECTOR_TABLE + __RAM_VECTOR_TABLE_SIZE;

    .text :
    {
        *(.text.startup)
        *(.text)
        *(.text.*)
        KEEP(*(.init))
        KEEP(*(.fini))
        . = ALIGN(16);
    } > m_text

    .rodata  : { *(.rodata) *(.rodata.*) } > m_text
    .sdata2  : { __sdata2_start__ = .; *(.sdata2) *(.sdata2.*) __sdata2_end__ = .; } > m_text
    .got2    : { *(.got2*) } > m_text

    .preinit_array : { PROVIDE_HIDDEN(__preinit_array_start = .); KEEP(*(.preinit_array)); PROVIDE_HIDDEN(__preinit_array_end = .); } > m_text
    .init_array    : { PROVIDE_HIDDEN(__init_array_start = .); KEEP(*(SORT(.init_array.*))); KEEP(*(.init_array)); PROVIDE_HIDDEN(__init_array_end = .); } > m_text
    .fini_array    : { PROVIDE_HIDDEN(__fini_array_start = .); KEEP(*(SORT(.fini_array.*))); KEEP(*(.fini_array)); PROVIDE_HIDDEN(__fini_array_end = .); } > m_text

    .ctors : { KEEP(*(.ctors)) KEEP(*(SORT(.ctors.*))) } > m_text
    .dtors : { KEEP(*(.dtors)) KEEP(*(SORT(.dtors.*))) } > m_text

    .init_table : { . = ALIGN(4); __COPY_TABLE = .; KEEP(*(.init_table)) } > m_text
    .zero_table : { . = ALIGN(4); __ZERO_TABLE = .; KEEP(*(.zero_table)) } > m_text

    __TEXT_END = .;

    /* ── SRAM sections ──────────────────────────────── */

    .interrupts_ram : ALIGN(4096)
    {
        __VECTOR_RAM = .;
        *(.m_interrupts_ram)
        . += __RAM_VECTOR_TABLE_SIZE;
    } > m_data

    /* Required by startup_MPC5748G.S init_table */
    __CUSTOM_ROM = __TEXT_END;
    .customSectionBlock : AT(__CUSTOM_ROM)
    {
        . = ALIGN(4);
        __CUSTOM_RAM = .;
        __customSection_start__ = .;
        KEEP(*(.customSection))
        . = ALIGN(4);
        __customSection_end__ = .;
    } > m_data
    __CUSTOM_END = __CUSTOM_ROM + (__customSection_end__ - __customSection_start__);

    __DATA_ROM = __CUSTOM_END;
    .data : AT(__DATA_ROM)
    {
        . = ALIGN(4);
        __DATA_RAM = .;
        __data_start__ = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4);
        __data_end__ = .;
    } > m_data
    __DATA_END = __DATA_ROM + (__data_end__ - __data_start__);

    __SDATA_ROM = __DATA_END;
    .sdata : AT(__SDATA_ROM)
    {
        . = ALIGN(4);
        __SDATA_RAM = .;
        *(.sdata) *(.sdata.*)
        . = ALIGN(4);
        __sdata_end__ = .;
    } > m_data
    __SDATA_END = __SDATA_ROM + (__sdata_end__ - __SDATA_RAM);

    .sbss (NOLOAD) : { . = ALIGN(4); __SBSS_START = .; *(.sbss) *(.sbss.*) . = ALIGN(4); __SBSS_END = .; } > m_data
    .bss  (NOLOAD) : { . = ALIGN(4); __BSS_START  = .; *(.bss)  *(.bss.*)  *(COMMON) . = ALIGN(4); __BSS_END  = .; } > m_data

    /* Required by startup_MPC5748G.S init_table */
    __CODE_ROM = __SDATA_END;
    .code : AT(__CODE_ROM)
    {
        . = ALIGN(4);
        __CODE_RAM = .;
        KEEP(*(.code_ram))
        . = ALIGN(4);
        __code_end__ = .;
    } > m_data
    __CODE_END = __CODE_ROM + (__code_end__ - __CODE_RAM);

    .stack (NOLOAD) : ALIGN(16)
    {
        __HEAP = .;
        PROVIDE(_end = .);
        PROVIDE(end = .);
        . += __HEAP_SIZE;
        __HEAP_END  = .;
        _stack_end  = .;
        . += __STACK_SIZE;
        . = ALIGN(4);
        _stack_addr = .;
        __SP_INIT   = .;
    } > m_data

    .shared_ram (NOLOAD) :
    {
        . = ALIGN(4);
        KEEP(*(.shared_ram))
    } > m_shared

    /* Symbols required by startup_MPC5748G.S */
    __SRAM_SIZE      = SRAM_SIZE;
    __SRAM_BASE_ADDR = SRAM_BASE_ADDR;
    __BSS_SIZE       = __BSS_END - __BSS_START;
}
