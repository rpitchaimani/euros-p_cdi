# -----------------------------------------------------------------
# Makefile -- ChainRecon bench firmware, MPC5748G DEVKIT, tri-core AMP
#
#   Core 0 (Z4a) : IDS under test (ingest, queue, CPU-share limiter, logs)
#   Core 1 (Z4b) : zonal gateway (DoIP-over-UDP <-> CAN), three observers,
#                  bench control endpoint
#   Core 2 (Z2)  : emulated target ECU in the destination zone
#
# Three ELFs, one per core flash region:
#   chainrecon_c0.elf 0x01000000   chainrecon_c1.elf 0x011D0000
#   chainrecon_c2.elf 0x013A0000
#
# Build (Git Bash):
#   export PATH="/c/NXP/S32DS_Power_v2.1/S32DS/build_tools/msys32/usr/bin:$PATH"
#   python python/sja_config_gen.py      # writes include/sja1105_config.h
#   make all
# Toolchain fixes over the older PoC Makefiles: -std=gnu99, -Wa,-mregnames,
# newlib sysroot + nano.specs, libraries after the objects, __eabi stub.
# -----------------------------------------------------------------

S32DS_HOME ?= C:/NXP/S32DS_Power_v2.1

TOOLCHAIN := $(S32DS_HOME)/S32DS/build_tools/powerpc-eabivle-4_9/bin
CC        := $(TOOLCHAIN)/powerpc-eabivle-gcc
LD        := $(TOOLCHAIN)/powerpc-eabivle-gcc
OBJCOPY   := $(TOOLCHAIN)/powerpc-eabivle-objcopy
SIZE      := $(TOOLCHAIN)/powerpc-eabivle-size
GDB       := $(TOOLCHAIN)/powerpc-eabivle-gdb

SDK         := $(S32DS_HOME)/S32DS/software/S32_SDK_S32PA_RTM_3.0.0
SDK_DEV_INC := $(SDK)/platform/devices/MPC5748G/include
STARTUP_DIR := $(SDK)/platform/devices/MPC5748G/startup/gcc
LWIP_SRC    := $(SDK)/middleware/tcpip/lwip/src

SRC_DIR    := ./src
INC_DIR    := ./include
LINKER_DIR := ./linker
BUILD_DIR  := ./build

# ── Compiler flag sets ──────────────────────────────────────────

# Z4 flags (Core 0 and Core 1)
CPU_Z4 := -mcpu=e200z4 -mvle -std=gnu99 -mno-spe -mfloat-gprs=single \
           -ffunction-sections -fdata-sections

# Z2 flags (Core 2 Observer — no PMC, no FPU, single-issue)
CPU_Z2 := -mcpu=e200z2 -mvle -std=gnu99 \
           -ffunction-sections -fdata-sections

INCLUDES := -I$(INC_DIR) \
            -I$(SDK_DEV_INC) \
            -I$(LWIP_SRC)/include

DEFS_C0 := -DMPC5748G -DTURN_ON_CPU0
DEFS_C1 := -DMPC5748G $(EXTRA_DEFS_C1)
DEFS_C2 := -DMPC5748G

CFLAGS_C0    := -MMD -MP $(CPU_Z4) $(INCLUDES) $(DEFS_C0) -O2 -g -Wall -Wextra
CFLAGS_C1    := -MMD -MP $(CPU_Z4) $(INCLUDES) $(DEFS_C1) -O2 -g -Wall -Wextra
CFLAGS_C2   := -MMD -MP $(CPU_Z2) $(INCLUDES) $(DEFS_C2) -O2 -g -Wall -Wextra

ASFLAGS_C0 := $(CPU_Z4) $(INCLUDES) $(DEFS_C0) -x assembler-with-cpp -Wa,-mregnames
ASFLAGS_C1 := $(CPU_Z4) $(INCLUDES) $(DEFS_C1) -x assembler-with-cpp -Wa,-mregnames
ASFLAGS_C2 := $(CPU_Z2) $(INCLUDES) $(DEFS_C2) -x assembler-with-cpp -Wa,-mregnames

LIBS_END := -Wl,--start-group -lc -lgcc -lm -Wl,--end-group
LDFLAGS_BASE := --sysroot=$(TOOLCHAIN)/../powerpc-eabivle/newlib -specs=nano.specs \
                -Wl,--gc-sections -nostdlib

LDFLAGS_C0 := $(CPU_Z4) -T $(LINKER_DIR)/MPC5748G_core0.ld \
              -Wl,-Map=$(BUILD_DIR)/chainrecon_c0.map $(LDFLAGS_BASE)

LDFLAGS_C1 := $(CPU_Z4) -T $(LINKER_DIR)/MPC5748G_core1.ld \
              -Wl,-Map=$(BUILD_DIR)/chainrecon_c1.map $(LDFLAGS_BASE)

LDFLAGS_C2 := --sysroot=$(TOOLCHAIN)/../powerpc-eabivle/newlib -specs=nano.specs $(CPU_Z2) -T $(LINKER_DIR)/MPC5748G_core2.ld \
              -Wl,-Map=$(BUILD_DIR)/chainrecon_c2.map \
              -Wl,--gc-sections -nostdlib

# ── Core 0 sources ──────────────────────────────────────────────
C0_C := \
    $(SRC_DIR)/main.c           \
    $(SRC_DIR)/eabi_stub.c      \
    $(SRC_DIR)/startup_stubs.c  \
    $(SRC_DIR)/ids_core0.c      \
    $(SRC_DIR)/sja1105_spi.c    \
    $(SRC_DIR)/clock_init.c     \
    $(SRC_DIR)/uart_log.c

C0_S := \
    $(STARTUP_DIR)/startup_MPC5748G.S       \
    $(STARTUP_DIR)/interrupt_vectors.S      \
    $(STARTUP_DIR)/core0_intc_sw_handlers.S

# ── Core 1 sources ──────────────────────────────────────────────
C1_C := \
    $(SRC_DIR)/eabi_stub.c      \
    $(SRC_DIR)/core1_gateway.c  \
    $(SRC_DIR)/doip_gw.c        \
    $(SRC_DIR)/observers.c      \
    $(SRC_DIR)/can_drv.c        \
    $(SRC_DIR)/lwip_port.c      \
    $(SRC_DIR)/uart_log.c

C1_S := \
    $(SRC_DIR)/core1_entry.S

C1_LWIP := \
    $(LWIP_SRC)/core/init.c          \
    $(LWIP_SRC)/core/def.c           \
    $(LWIP_SRC)/core/mem.c           \
    $(LWIP_SRC)/core/memp.c          \
    $(LWIP_SRC)/core/pbuf.c          \
    $(LWIP_SRC)/core/netif.c         \
    $(LWIP_SRC)/core/ip.c            \
    $(LWIP_SRC)/core/tcp.c           \
    $(LWIP_SRC)/core/tcp_in.c        \
    $(LWIP_SRC)/core/tcp_out.c       \
    $(LWIP_SRC)/core/udp.c           \
    $(LWIP_SRC)/core/raw.c           \
    $(LWIP_SRC)/core/inet_chksum.c   \
    $(LWIP_SRC)/core/timeouts.c      \
    $(LWIP_SRC)/core/sys.c           \
    $(LWIP_SRC)/core/stats.c         \
    $(LWIP_SRC)/core/ipv4/etharp.c   \
    $(LWIP_SRC)/core/ipv4/icmp.c     \
    $(LWIP_SRC)/core/ipv4/ip4.c      \
    $(LWIP_SRC)/core/ipv4/ip4_addr.c \
    $(LWIP_SRC)/core/ipv4/ip4_frag.c \
    $(LWIP_SRC)/netif/ethernet.c

# ── Core 2 sources ──────────────────────────────────────────────
C2_C := \
    $(SRC_DIR)/eabi_stub.c      \
    $(SRC_DIR)/core2_target.c

C2_S := \
    $(SRC_DIR)/core2_entry.S

# ── Object file lists ──────────────────────────────────────────

C0_OBJS   := $(patsubst $(SRC_DIR)/%.c,    $(BUILD_DIR)/c0/src/%.o,     $(C0_C))
C0_S_OBJS := $(patsubst $(STARTUP_DIR)/%.S,$(BUILD_DIR)/c0/startup/%.o, $(C0_S))

C1_OBJS      := $(patsubst $(SRC_DIR)/%.c,  $(BUILD_DIR)/c1/src/%.o,      $(C1_C))
C1_S_OBJS    := $(patsubst $(SRC_DIR)/%.S,  $(BUILD_DIR)/c1/src/%.o,      $(C1_S))
C1_LWIP_OBJS := $(patsubst $(LWIP_SRC)/%.c, $(BUILD_DIR)/c1/lwip/%.o,     $(C1_LWIP))

C2_OBJS   := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/c2/src/%.o, $(C2_C))
C2_S_OBJS := $(patsubst $(SRC_DIR)/%.S, $(BUILD_DIR)/c2/src/%.o, $(C2_S))

ALL_C0_OBJS := $(C0_OBJS) $(C0_S_OBJS)
ALL_C1_OBJS := $(C1_OBJS) $(C1_S_OBJS) $(C1_LWIP_OBJS)
ALL_C2_OBJS := $(C2_OBJS) $(C2_S_OBJS)

ELF_C0 := $(BUILD_DIR)/chainrecon_c0.elf
ELF_C1 := $(BUILD_DIR)/chainrecon_c1.elf
ELF_C2 := $(BUILD_DIR)/chainrecon_c2.elf
HEX_C0 := $(BUILD_DIR)/chainrecon_c0.hex
HEX_C1 := $(BUILD_DIR)/chainrecon_c1.hex
HEX_C2 := $(BUILD_DIR)/chainrecon_c2.hex

.PHONY: all clean size flash_c0 flash_c1 flash_c2 flash_all

all: $(HEX_C0) $(HEX_C1) $(HEX_C2) size

# ── Link ────────────────────────────────────────────────────────

$(ELF_C0): $(ALL_C0_OBJS)
	@echo "[LD C0] $@"
	$(LD) $(LDFLAGS_C0) $(ALL_C0_OBJS) $(LIBS_END) -o $@

$(ELF_C1): $(ALL_C1_OBJS)
	@echo "[LD C1] $@"
	$(LD) $(LDFLAGS_C1) $(ALL_C1_OBJS) $(LIBS_END) -o $@

$(ELF_C2): $(ALL_C2_OBJS)
	@echo "[LD C2] $@"
	$(LD) $(LDFLAGS_C2) $(ALL_C2_OBJS) $(LIBS_END) -o $@

# ── HEX ─────────────────────────────────────────────────────────

$(HEX_C0): $(ELF_C0)
	@echo "[HEX C0] $@"
	$(OBJCOPY) -O ihex $< $@

$(HEX_C1): $(ELF_C1)
	@echo "[HEX C1] $@"
	$(OBJCOPY) -O ihex $< $@

$(HEX_C2): $(ELF_C2)
	@echo "[HEX C2] $@"
	$(OBJCOPY) -O ihex $< $@

size: $(ELF_C0) $(ELF_C1) $(ELF_C2)
	@echo "=== Core 0 ==="
	$(SIZE) $(ELF_C0)
	@echo "=== Core 1 ==="
	$(SIZE) $(ELF_C1)
	@echo "=== Core 2 ==="
	$(SIZE) $(ELF_C2)

# ── Compile: Core 0 ─────────────────────────────────────────────

$(BUILD_DIR)/c0/src/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	@echo "[CC C0] $<"
	$(CC) $(CFLAGS_C0) -c $< -o $@

$(BUILD_DIR)/c0/startup/%.o: $(STARTUP_DIR)/%.S
	@mkdir -p $(@D)
	@echo "[AS C0] $<"
	$(CC) $(ASFLAGS_C0) -c $< -o $@

# ── Compile: Core 1 ─────────────────────────────────────────────

$(BUILD_DIR)/c1/src/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	@echo "[CC C1] $<"
	$(CC) $(CFLAGS_C1) -c $< -o $@

$(BUILD_DIR)/c1/src/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(@D)
	@echo "[AS C1] $<"
	$(CC) $(ASFLAGS_C1) -c $< -o $@

$(BUILD_DIR)/c1/lwip/core/%.o: $(LWIP_SRC)/core/%.c
	@mkdir -p $(@D)
	@echo "[CC C1 lwip] $<"
	$(CC) $(CFLAGS_C1) -c $< -o $@

$(BUILD_DIR)/c1/lwip/core/ipv4/%.o: $(LWIP_SRC)/core/ipv4/%.c
	@mkdir -p $(@D)
	@echo "[CC C1 lwip] $<"
	$(CC) $(CFLAGS_C1) -c $< -o $@

$(BUILD_DIR)/c1/lwip/netif/%.o: $(LWIP_SRC)/netif/%.c
	@mkdir -p $(@D)
	@echo "[CC C1 lwip] $<"
	$(CC) $(CFLAGS_C1) -c $< -o $@

# ── Compile: Core 2 ─────────────────────────────────────────────

$(BUILD_DIR)/c2/src/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	@echo "[CC C2] $<"
	$(CC) $(CFLAGS_C2) -c $< -o $@

$(BUILD_DIR)/c2/src/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(@D)
	@echo "[AS C2] $<"
	$(CC) $(ASFLAGS_C2) -c $< -o $@

# ── Flash targets ───────────────────────────────────────────────

GDB_PORT ?= 7224

flash_c0: $(ELF_C0)
	@echo "set architecture powerpc:e200"       >  $(BUILD_DIR)/flash_c0.gdb
	@echo "target remote localhost:$(GDB_PORT)" >> $(BUILD_DIR)/flash_c0.gdb
	@echo "monitor reset"                       >> $(BUILD_DIR)/flash_c0.gdb
	@echo "load"                                >> $(BUILD_DIR)/flash_c0.gdb
	@echo "monitor go"                          >> $(BUILD_DIR)/flash_c0.gdb
	@echo "quit"                                >> $(BUILD_DIR)/flash_c0.gdb
	$(GDB) $(ELF_C0) --batch -x $(BUILD_DIR)/flash_c0.gdb

flash_c1: $(ELF_C1)
	@echo "set architecture powerpc:e200"       >  $(BUILD_DIR)/flash_c1.gdb
	@echo "target remote localhost:$(GDB_PORT)" >> $(BUILD_DIR)/flash_c1.gdb
	@echo "monitor reset halt"                  >> $(BUILD_DIR)/flash_c1.gdb
	@echo "load"                                >> $(BUILD_DIR)/flash_c1.gdb
	@echo "monitor go"                          >> $(BUILD_DIR)/flash_c1.gdb
	@echo "quit"                                >> $(BUILD_DIR)/flash_c1.gdb
	$(GDB) $(ELF_C1) --batch -x $(BUILD_DIR)/flash_c1.gdb

flash_c2: $(ELF_C2)
	@echo "set architecture powerpc:e200"       >  $(BUILD_DIR)/flash_c2.gdb
	@echo "target remote localhost:$(GDB_PORT)" >> $(BUILD_DIR)/flash_c2.gdb
	@echo "monitor reset halt"                  >> $(BUILD_DIR)/flash_c2.gdb
	@echo "load"                                >> $(BUILD_DIR)/flash_c2.gdb
	@echo "monitor go"                          >> $(BUILD_DIR)/flash_c2.gdb
	@echo "quit"                                >> $(BUILD_DIR)/flash_c2.gdb
	$(GDB) $(ELF_C2) --batch -x $(BUILD_DIR)/flash_c2.gdb

flash_all: flash_c0 flash_c1 flash_c2

clean:
	rm -rf $(BUILD_DIR)

# header dependencies (-MMD): editing a .h now rebuilds the objects that use it
-include $(shell find $(BUILD_DIR) -name '*.d' 2>/dev/null)
