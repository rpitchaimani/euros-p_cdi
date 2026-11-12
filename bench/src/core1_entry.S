/* core1_entry.S — VLE startup stub for Core 1
   Loads _stack_core1_top into SP then calls main()
   Uses .core1_startup so the linker can place it at a known address
   (MC_ME CADDR1 must point to core1_entry exactly). */

    .section .core1_startup, "ax"
    .global  core1_entry

core1_entry:
    e_li    r0,  0
    /* r2 = _SDA2_BASE_ (small read-only data base, used by SDA21 relocs) */
    e_lis   r2,  _SDA2_BASE_@h
    e_or2i  r2,  _SDA2_BASE_@l
    e_li    r3,  0
    e_li    r4,  0
    e_li    r5,  0
    e_li    r6,  0
    e_li    r7,  0
    e_li    r8,  0
    e_li    r9,  0
    e_li    r10, 0
    e_li    r11, 0
    e_li    r12, 0
    /* r13 = _SDA_BASE_ (small data base, used by SDA21 relocs into .sdata/.sbss) */
    e_lis   r13, _SDA_BASE_@h
    e_or2i  r13, _SDA_BASE_@l
    e_li    r14, 0
    e_li    r15, 0
    e_li    r16, 0
    e_li    r17, 0
    e_li    r18, 0
    e_li    r19, 0
    e_li    r20, 0
    e_li    r21, 0
    e_li    r22, 0
    e_li    r23, 0
    e_li    r24, 0
    e_li    r25, 0
    e_li    r26, 0
    e_li    r27, 0
    e_li    r28, 0
    e_li    r29, 0
    e_li    r30, 0
    e_li    r31, 0

    e_lis   r1, _stack_core1_top@h
    e_or2i  r1, _stack_core1_top@l

    e_bl    main

.Lcore1_hang:
    e_b     .Lcore1_hang
