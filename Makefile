TARGET := ibm_pc_5150
BUILD_DIR := build/$(TARGET)
LOADER_SECTORS := 4
CORE_START_LBA := 11
CORE_LOAD_ADDR := 0x1000
BASIC_BOOTSTRAP_ADDR := 0x3a00
BASIC_BOOTSTRAP_CLEAR_TOP := 14847
BASIC_BOOTSTRAP_RAM_TOP := 0x4000
BASIC_BOOTSTRAP_STACK_GUARD := 0x0200
BASIC_BOOTSTRAP_24K_RAM_TOP := 0x6000
BASIC_BOOTSTRAP_24K_STACK_GUARD := 0x0100
BASIC_BOOTSTRAP_16K_RAM_TOP := 0x4000
BASIC_BOOTSTRAP_16K_STACK_GUARD := 0x0100   # Build 9: mirror of basic_sidecar_stack_guard_len_16k (layout.inc); inspect display only
BASIC_BOOTSTRAP_MAX_ADDR := $(BASIC_BOOTSTRAP_RAM_TOP)
BASIC_BOOTSTRAP_A_DRIVE := 0
BASIC_BOOTSTRAP_B_DRIVE := 1
HIGH_CRYPTO_SCRATCH_START := 0x3400
HIGH_CRYPTO_SCRATCH_LEN := 194
CRITICAL_SCRATCH_START := 0x34c2
CRITICAL_SCRATCH_LEN := 2097

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
LOADER_SRC := targets/$(TARGET)/boot/loader.asm
CORE_SRC := targets/$(TARGET)/boot/core.asm
BASIC_BOOT_SRC := targets/$(TARGET)/basic/bootstrap.asm
CORE_INCLUDES := $(wildcard targets/$(TARGET)/boot/core/*.inc)
CORE_PHASE_INCLUDES := $(wildcard targets/$(TARGET)/boot/phases/*.inc)
BOOT_BIN := $(BUILD_DIR)/boot.bin
LOADER_BIN := $(BUILD_DIR)/loader.bin
CORE_SYS := $(BUILD_DIR)/CORE.SYS
BASIC_BOOT_A_BIN := $(BUILD_DIR)/seed24a-loader.bin
BASIC_BOOT_A_BAS := $(BUILD_DIR)/SEED24A.BAS
BASIC_BOOT_B_BIN := $(BUILD_DIR)/seed24b-loader.bin
BASIC_BOOT_B_BAS := $(BUILD_DIR)/SEED24B.BAS
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
IMAGE_BUILDER := tools/build-fat12-image.py
BASIC_BOOT_BUILDER := tools/build-basic-bootstrap.py
CORE_SYS_INFO := tools/core-sys-info.py
AGENT_CFG := $(wildcard config/AGENTS.CFG)
USER_CFG := $(wildcard config/USER.CFG)
INCLUDE_USER_CFG ?= 1
# Build 11 #4 real compaction: the static system prompts (identity + the compaction contract) live on
# the floppy and are STREAMED into the request mid-chat (frees ~600-800 phase bytes + lifts the
# in-phase prompt-length cap). Portable/hardware-agnostic content -> a top-level prompts/ dir, not the
# target tree. The streamer appends each file RAW into the JSON "instructions" value (control bytes
# flatten to space), so a file MUST NOT contain a " or \ (those would need escaping, breaking the
# size==sent-bytes invariant Content-Length relies on); the guard below enforces it at build time.
IDENTITY_PROMPT := prompts/identity.txt
COMPACT_PROMPT := prompts/compact.txt
NASM_FLAGS := -DLOADER_SECTORS=$(LOADER_SECTORS) -Itargets/$(TARGET)/boot/ -I$(BUILD_DIR)/
FAT_FILES := --file $(CORE_SYS):CORE.SYS

ifneq ($(AGENT_CFG),)
FAT_FILES += --file $(AGENT_CFG):AGENTS.CFG
endif

ifeq ($(INCLUDE_USER_CFG),1)
ifneq ($(USER_CFG),)
FAT_FILES += --file $(USER_CFG):USER.CFG
endif
endif

FAT_FILES += --file $(IDENTITY_PROMPT):IDENTITY --file $(COMPACT_PROMPT):COMPACT

.PHONY: all clean inspect basic-bootstrap memory-map test

all: $(FLOPPY_IMG)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(CORE_SYS): $(CORE_SRC) $(CORE_INCLUDES) $(CORE_PHASE_INCLUDES) $(CORE_SYS_INFO) | $(BUILD_DIR)
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
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP) \
		--max-addr $(BASIC_BOOTSTRAP_MAX_ADDR)

$(BASIC_BOOT_B_BAS): $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_BUILDER) | $(BUILD_DIR)
	python3 $(BASIC_BOOT_BUILDER) \
		--input $(BASIC_BOOT_B_BIN) \
		--output $@ \
		--load-addr $(BASIC_BOOTSTRAP_ADDR) \
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP) \
		--max-addr $(BASIC_BOOTSTRAP_MAX_ADDR)

$(FLOPPY_IMG): $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(IMAGE_BUILDER) | $(BUILD_DIR)
	@LC_ALL=C grep -l '["\\]' $(IDENTITY_PROMPT) $(COMPACT_PROMPT) >/dev/null 2>&1 \
		&& { echo "error: a streamed prompt contains a \" or \\ (breaks JSON / Content-Length)"; exit 1; } || true
	@# A streamed TLS record must stay <= the ~440 B api_request_plain body so its TX frame fits the
	@# 512 B scratch below the stream phase (an oversized frame overwrites the phase's own code mid-send).
	@# The identity now streams as <=440 B records like the contract, so cap it at 512 B. The contract is
	@# streamed as <=440 B records but staged one 512 B sector at a time in tls_rx_copy, so cap it at 512 B.
	@test $$(wc -c < $(IDENTITY_PROMPT)) -le 512 \
		|| { echo "error: $(IDENTITY_PROMPT) > 512 B (must fit one sector, streamed as <=440 B records)"; exit 1; }
	@test $$(wc -c < $(COMPACT_PROMPT)) -le 512 \
		|| { echo "error: $(COMPACT_PROMPT) > 512 B (contract staging reads one sector into tls_rx_copy)"; exit 1; }
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_BIN) \
		--loader $(LOADER_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--output $@ \
		$(FAT_FILES)

inspect: $(FLOPPY_IMG) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	python3 $(CORE_SYS_INFO) \
		--load-addr $(CORE_LOAD_ADDR) \
		--range high-crypto:$(HIGH_CRYPTO_SCRATCH_START):$(HIGH_CRYPTO_SCRATCH_LEN) \
		--range critical:$(CRITICAL_SCRATCH_START):$(CRITICAL_SCRATCH_LEN) \
		--packed-phase K \
		--packed-range high-crypto:$(HIGH_CRYPTO_SCRATCH_LEN) \
		--packed-range critical:$(CRITICAL_SCRATCH_LEN) \
		--budget 24k-basic:$(BASIC_BOOTSTRAP_24K_RAM_TOP):$(BASIC_BOOTSTRAP_24K_STACK_GUARD) \
		--budget 16k-target:$(BASIC_BOOTSTRAP_16K_RAM_TOP):$(BASIC_BOOTSTRAP_16K_STACK_GUARD) \
		$(CORE_SYS)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)
	python3 $(IMAGE_BUILDER) list $(FLOPPY_IMG)

basic-bootstrap: $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	ls -l $(BASIC_BOOT_A_BIN) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_B_BAS)

memory-map: $(CORE_SYS)
	python3 tools/memory-map.py --update docs/memory.md

test:
	python3 tools/check-p256.py
	python3 tools/check-tls-prf.py
	python3 tools/check-chacha-poly1305.py

clean:
	rm -rf build
