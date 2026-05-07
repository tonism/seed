TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)
LOADER_SECTORS := 4
CORE_START_LBA := 11
BASIC_BOOTSTRAP_ADDR := 0x3a00
BASIC_BOOTSTRAP_CLEAR_TOP := 14847
BASIC_BOOTSTRAP_RAM_TOP := 0x6000
BASIC_BOOTSTRAP_A_DRIVE := 0
BASIC_BOOTSTRAP_B_DRIVE := 1

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
LOADER_SRC := targets/$(TARGET)/boot/loader.asm
CORE_SRC := targets/$(TARGET)/boot/core.asm
BASIC_BOOT_SRC := targets/$(TARGET)/basic/bootstrap.asm
PHASE_NOOP_SRC := targets/$(TARGET)/boot/phases/noop.asm
CORE_INCLUDES := $(wildcard targets/$(TARGET)/boot/core/*.inc)
BOOT_BIN := $(BUILD_DIR)/boot.bin
LOADER_BIN := $(BUILD_DIR)/loader.bin
CORE_SYS := $(BUILD_DIR)/CORE.SYS
PHASE_NOOP_BIN := $(BUILD_DIR)/phase-noop.bin
BASIC_BOOT_A_BIN := $(BUILD_DIR)/seed24a-loader.bin
BASIC_BOOT_A_BAS := $(BUILD_DIR)/SEED24A.BAS
BASIC_BOOT_B_BIN := $(BUILD_DIR)/seed24b-loader.bin
BASIC_BOOT_B_BAS := $(BUILD_DIR)/SEED24B.BAS
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
IMAGE_BUILDER := tools/build-fat12-image.py
BASIC_BOOT_BUILDER := tools/build-basic-bootstrap.py
CORE_SYS_INFO := tools/core-sys-info.py
AGENT_CFG := $(wildcard config/AGENTS.CFG)
NET_CFG := $(wildcard config/NET.CFG)
USER_CFG := $(wildcard config/USER.CFG)
INCLUDE_USER_CFG ?= 1
NASM_FLAGS := -DLOADER_SECTORS=$(LOADER_SECTORS) -Itargets/$(TARGET)/boot/ -I$(BUILD_DIR)/
FAT_FILES := --file $(CORE_SYS):CORE.SYS

ifneq ($(AGENT_CFG),)
FAT_FILES += --file $(AGENT_CFG):AGENTS.CFG
endif

ifneq ($(NET_CFG),)
FAT_FILES += --file $(NET_CFG):NET.CFG
endif

ifeq ($(INCLUDE_USER_CFG),1)
ifneq ($(USER_CFG),)
FAT_FILES += --file $(USER_CFG):USER.CFG
endif
endif

FAT_FILES += --file $(BASIC_BOOT_A_BAS):SEED24A.BAS
FAT_FILES += --file $(BASIC_BOOT_B_BAS):SEED24B.BAS

.PHONY: all clean inspect basic-bootstrap test

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(PHASE_NOOP_BIN): $(PHASE_NOOP_SRC) $(CORE_INCLUDES) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(CORE_SYS): $(CORE_SRC) $(CORE_INCLUDES) $(PHASE_NOOP_BIN) $(CORE_SYS_INFO) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<
	python3 $(CORE_SYS_INFO) --check $@

$(BASIC_BOOT_A_BIN): $(BASIC_BOOT_SRC) $(CORE_SYS) Makefile | $(BUILD_DIR)
	core_sectors=$$(python3 $(CORE_SYS_INFO) --field resident-sectors $(CORE_SYS)); \
	nasm $(NASM_FLAGS) \
		-DBASIC_BOOTSTRAP_ADDR=$(BASIC_BOOTSTRAP_ADDR) \
		-DSEED_CORE_START_LBA=$(CORE_START_LBA) \
		-DSEED_CORE_SECTORS=$$core_sectors \
		-DSEED_RAM_TOP=$(BASIC_BOOTSTRAP_RAM_TOP) \
		-DSEED_BOOT_DRIVE=$(BASIC_BOOTSTRAP_A_DRIVE) \
		-f bin -o $@ $<

$(BASIC_BOOT_B_BIN): $(BASIC_BOOT_SRC) $(CORE_SYS) Makefile | $(BUILD_DIR)
	core_sectors=$$(python3 $(CORE_SYS_INFO) --field resident-sectors $(CORE_SYS)); \
	nasm $(NASM_FLAGS) \
		-DBASIC_BOOTSTRAP_ADDR=$(BASIC_BOOTSTRAP_ADDR) \
		-DSEED_CORE_START_LBA=$(CORE_START_LBA) \
		-DSEED_CORE_SECTORS=$$core_sectors \
		-DSEED_RAM_TOP=$(BASIC_BOOTSTRAP_RAM_TOP) \
		-DSEED_BOOT_DRIVE=$(BASIC_BOOTSTRAP_B_DRIVE) \
		-f bin -o $@ $<

$(BASIC_BOOT_A_BAS): $(BASIC_BOOT_A_BIN) $(BASIC_BOOT_BUILDER) | $(BUILD_DIR)
	python3 $(BASIC_BOOT_BUILDER) \
		--input $(BASIC_BOOT_A_BIN) \
		--output $@ \
		--load-addr $(BASIC_BOOTSTRAP_ADDR) \
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP)

$(BASIC_BOOT_B_BAS): $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_BUILDER) | $(BUILD_DIR)
	python3 $(BASIC_BOOT_BUILDER) \
		--input $(BASIC_BOOT_B_BIN) \
		--output $@ \
		--load-addr $(BASIC_BOOTSTRAP_ADDR) \
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP)

$(FLOPPY_IMG): $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS) $(AGENT_CFG) $(NET_CFG) $(USER_CFG) $(IMAGE_BUILDER) | $(BUILD_DIR)
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_BIN) \
		--loader $(LOADER_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--output $@ \
		$(FAT_FILES)

inspect: $(FLOPPY_IMG)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	python3 $(CORE_SYS_INFO) $(CORE_SYS)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)
	python3 $(IMAGE_BUILDER) list $(FLOPPY_IMG)

basic-bootstrap: $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	ls -l $(BASIC_BOOT_A_BIN) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_B_BAS)

test:
	python3 tools/check-p256.py
	python3 tools/check-tls-prf.py
	python3 tools/check-chacha-poly1305.py

clean:
	rm -rf build
