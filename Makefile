TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)
STAGE2_SECTORS := 10

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
STAGE2_SRC := targets/$(TARGET)/boot/stage2.asm
BOOT_BIN := $(BUILD_DIR)/boot.bin
STAGE2_BIN := $(BUILD_DIR)/stage2.bin
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
NASM_FLAGS := -DSTAGE2_SECTORS=$(STAGE2_SECTORS)

.PHONY: all clean inspect

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(STAGE2_BIN): $(STAGE2_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(FLOPPY_IMG): $(BOOT_BIN) $(STAGE2_BIN) | $(BUILD_DIR)
	dd if=/dev/zero of=$@ bs=1024 count=160
	dd if=$(BOOT_BIN) of=$@ bs=512 count=1 conv=notrunc
	dd if=$(STAGE2_BIN) of=$@ bs=512 seek=1 conv=notrunc

inspect: $(FLOPPY_IMG)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(STAGE2_BIN)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)

clean:
	rm -rf build
