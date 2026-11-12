/* arch/cc.h — LwIP port for MPC5748G PowerPC e200z4, GCC, big-endian */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

#define BYTE_ORDER  BIG_ENDIAN

typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
typedef uintptr_t mem_ptr_t;

#define U16_F  "u"
#define S16_F  "d"
#define X16_F  "x"
#define U32_F  "u"
#define S32_F  "d"
#define X32_F  "x"
#define SZT_F  "u"

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT  __attribute__((packed))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x)  x

#define LWIP_PLATFORM_DIAG(x)  do {} while(0)
#define LWIP_PLATFORM_ASSERT(x) \
    do { if(!(x)) { for(;;); } } while(0)
#define LWIP_UNUSED_ARG(x)  ((void)(x))

#endif
