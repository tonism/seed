TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)
LOADER_SECTORS := 4

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
LOADER_SRC := targets/$(TARGET)/boot/loader.asm
CORE_SRC := targets/$(TARGET)/boot/core.asm
CORE_INCLUDES := $(wildcard targets/$(TARGET)/boot/core/*.inc)
BOOT_BIN := $(BUILD_DIR)/boot.bin
LOADER_BIN := $(BUILD_DIR)/loader.bin
CORE_SYS := $(BUILD_DIR)/CORE.SYS
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
IMAGE_BUILDER := tools/build-fat12-image.py
AGENT_CFG := $(wildcard config/AGENTS.CFG)
NET_CFG := $(wildcard config/NET.CFG)
USER_CFG := $(wildcard config/USER.CFG)
INCLUDE_USER_CFG ?= 1
NASM_FLAGS := -DLOADER_SECTORS=$(LOADER_SECTORS) -Itargets/$(TARGET)/boot/
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

.PHONY: all clean inspect

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(CORE_SYS): $(CORE_SRC) $(CORE_INCLUDES) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(FLOPPY_IMG): $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(AGENT_CFG) $(NET_CFG) $(USER_CFG) $(IMAGE_BUILDER) | $(BUILD_DIR)
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_BIN) \
		--loader $(LOADER_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--output $@ \
		$(FAT_FILES)

inspect: $(FLOPPY_IMG)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)
	python3 $(IMAGE_BUILDER) list $(FLOPPY_IMG)

clean:
	rm -rf build
