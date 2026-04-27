TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)
STAGE2_SECTORS := 24

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
STAGE2_SRC := targets/$(TARGET)/boot/stage2.asm
BOOT_BIN := $(BUILD_DIR)/boot.bin
STAGE2_BIN := $(BUILD_DIR)/stage2.bin
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
IMAGE_BUILDER := tools/build-fat12-image.py
AGENT_CFG := $(wildcard config/AGENTS.CFG)
NET_CFG := $(wildcard config/NET.CFG)
USER_CFG := $(wildcard config/SEED.CFG)
INCLUDE_USER_CFG ?= 1
NASM_FLAGS := -DSTAGE2_SECTORS=$(STAGE2_SECTORS)
FAT_FILES :=

ifneq ($(AGENT_CFG),)
FAT_FILES += --file $(AGENT_CFG):AGENTS.CFG
endif

ifneq ($(NET_CFG),)
FAT_FILES += --file $(NET_CFG):NET.CFG
endif

ifeq ($(INCLUDE_USER_CFG),1)
ifneq ($(USER_CFG),)
FAT_FILES += --file $(USER_CFG):SEED.CFG
endif
endif

.PHONY: all clean inspect

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(STAGE2_BIN): $(STAGE2_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(FLOPPY_IMG): $(BOOT_BIN) $(STAGE2_BIN) $(AGENT_CFG) $(NET_CFG) $(USER_CFG) $(IMAGE_BUILDER) | $(BUILD_DIR)
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_BIN) \
		--stage2 $(STAGE2_BIN) \
		--stage2-sectors $(STAGE2_SECTORS) \
		--output $@ \
		$(FAT_FILES)

inspect: $(FLOPPY_IMG)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(STAGE2_BIN)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)
	python3 $(IMAGE_BUILDER) list $(FLOPPY_IMG)

clean:
	rm -rf build
