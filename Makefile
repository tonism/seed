TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
BOOT_BIN := $(BUILD_DIR)/boot.bin
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img

.PHONY: all clean inspect

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm -f bin -o $@ $<

$(FLOPPY_IMG): $(BOOT_BIN) | $(BUILD_DIR)
	dd if=/dev/zero of=$@ bs=1024 count=160
	dd if=$(BOOT_BIN) of=$@ bs=512 count=1 conv=notrunc

inspect: $(FLOPPY_IMG)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN)
	xxd -g 1 -l 192 $(FLOPPY_IMG)

clean:
	rm -rf build
