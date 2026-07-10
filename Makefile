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
# Build 12 (O7, single source of truth): derive the inspect/budget ranges from
# layout.inc via check-layout.py rather than hand-syncing them here. The old
# hardcoded CRITICAL_SCRATCH_LEN (2097) had silently drifted from the real value
# (1229) after the Build 11 RX-buffer shrink — the inspect budget view was wrong.
HIGH_CRYPTO_SCRATCH_START := $(shell python3 tools/check-layout.py --emit high_crypto_scratch_start)
HIGH_CRYPTO_SCRATCH_LEN := $(shell python3 tools/check-layout.py --emit high_crypto_scratch_len)
CRITICAL_SCRATCH_START := $(shell python3 tools/check-layout.py --emit critical_scratch_start)
CRITICAL_SCRATCH_LEN := $(shell python3 tools/check-layout.py --emit critical_scratch_len)

BOOT_SRC := targets/$(TARGET)/boot/boot.asm
LOADER_SRC := targets/$(TARGET)/boot/loader.asm
CORE_SRC := targets/$(TARGET)/boot/core.asm
P256_MODULE_SRC := targets/$(TARGET)/boot/core/p256_module.asm
BASIC_BOOT_SRC := targets/$(TARGET)/basic/bootstrap.asm
CORE_INCLUDES := $(wildcard targets/$(TARGET)/boot/core/*.inc)
CORE_PHASE_INCLUDES := $(wildcard targets/$(TARGET)/boot/phases/*.inc)
BOOT_BIN := $(BUILD_DIR)/boot.bin
LOADER_BIN := $(BUILD_DIR)/loader.bin
CORE_SYS := $(BUILD_DIR)/CORE.SYS
P256_MODULE_BIN := $(BUILD_DIR)/p256_module.bin
BASIC_BOOT_A_BIN := $(BUILD_DIR)/seed24a-loader.bin
BASIC_BOOT_A_BAS := $(BUILD_DIR)/SEED24A.BAS
BASIC_BOOT_B_BIN := $(BUILD_DIR)/seed24b-loader.bin
BASIC_BOOT_B_BAS := $(BUILD_DIR)/SEED24B.BAS
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
FLOPPY_IMG_360K := $(BUILD_DIR)/floppy-360k.img
BOOT_360K_BIN := $(BUILD_DIR)/boot-360k.bin
LOADER_360K_BIN := $(BUILD_DIR)/loader-360k.bin
IMAGE_BUILDER := tools/build-fat12-image.py
BASIC_BOOT_BUILDER := tools/build-basic-bootstrap.py
CORE_SYS_INFO := tools/core-sys-info.py
LAYOUT_CHECK := tools/check-layout.py
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
# Native tool-calling (Build 12): the tools JSON schema, streamed RAW as the "tools" array value into
# ready requests. Preloaded once at boot into a resident pool-carved buffer on loop-cache tiers. Kept
# to one sector so the 32K context pool remains usable. Unlike identity/compact it is literal JSON, so
# its quotes are structural (NOT run through the "no quotes" guard).
TOOLS_SCHEMA := prompts/tools.json
NASM_FLAGS := -DLOADER_SECTORS=$(LOADER_SECTORS) -Itargets/$(TARGET)/boot/ -I$(BUILD_DIR)/
# 360 KiB double-sided geometry (the 286 tier — the IBM AT's drive rejects the
# single-sided 160K image). Same CORE.SYS + same FAT12 internal layout (data at
# LBA 11); only the physical geometry the AT requires differs. The .asm geometry
# defines default to 160K, so the 160K artifacts stay byte-identical.
NASM_FLAGS_360K := $(NASM_FLAGS) -DFLOPPY_TOTAL_SECTORS=720 -DFLOPPY_SPT=9 -DFLOPPY_HEADS=2 -DFLOPPY_MEDIA=0xfd
FAT_FILES := --file $(CORE_SYS):CORE.SYS

ifneq ($(AGENT_CFG),)
FAT_FILES += --file $(AGENT_CFG):AGENTS.CFG
endif

ifeq ($(INCLUDE_USER_CFG),1)
ifneq ($(USER_CFG),)
FAT_FILES += --file $(USER_CFG):USER.CFG
endif
endif

FAT_FILES += --file $(IDENTITY_PROMPT):IDENTITY --file $(COMPACT_PROMPT):COMPACT --file $(TOOLS_SCHEMA):TOOLS

.PHONY: all clean inspect basic-bootstrap memory-map test

all: $(FLOPPY_IMG) $(FLOPPY_IMG_360K)

$(BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

# Build 12 286 secure tier: the P-256 ECDHE module is assembled as its own flat binary at its run
# address (so p256.inc's absolute self-references resolve), then incbin'd into CORE.SYS below. It
# depends on the same core includes (layout.inc / p256.inc / p256_data.inc all live in core/*.inc).
$(P256_MODULE_BIN): $(P256_MODULE_SRC) $(CORE_INCLUDES) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(CORE_SYS): $(CORE_SRC) $(CORE_INCLUDES) $(CORE_PHASE_INCLUDES) $(P256_MODULE_BIN) $(CORE_SYS_INFO) $(LAYOUT_CHECK) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<
	python3 $(CORE_SYS_INFO) --check $@
	python3 $(LAYOUT_CHECK) $@

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

$(FLOPPY_IMG): $(BOOT_BIN) $(LOADER_BIN) $(CORE_SYS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(TOOLS_SCHEMA) $(IMAGE_BUILDER) | $(BUILD_DIR)
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
	@test $$(wc -c < $(TOOLS_SCHEMA)) -le 384 \
		|| { echo "error: $(TOOLS_SCHEMA) > 384 B (tools-cache tail stores native tool replay history)"; exit 1; }
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_BIN) \
		--loader $(LOADER_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--output $@ \
		$(FAT_FILES)

$(BOOT_360K_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_360K) -f bin -o $@ $<

$(LOADER_360K_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_360K) -f bin -o $@ $<

$(FLOPPY_IMG_360K): $(BOOT_360K_BIN) $(LOADER_360K_BIN) $(CORE_SYS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(TOOLS_SCHEMA) $(IMAGE_BUILDER) | $(BUILD_DIR)
	@LC_ALL=C grep -l '["\\]' $(IDENTITY_PROMPT) $(COMPACT_PROMPT) >/dev/null 2>&1 \
		&& { echo "error: a streamed prompt contains a \" or \\ (breaks JSON / Content-Length)"; exit 1; } || true
	@test $$(wc -c < $(IDENTITY_PROMPT)) -le 512 \
		|| { echo "error: $(IDENTITY_PROMPT) > 512 B (must fit one sector, streamed as <=440 B records)"; exit 1; }
	@test $$(wc -c < $(COMPACT_PROMPT)) -le 512 \
		|| { echo "error: $(COMPACT_PROMPT) > 512 B (contract staging reads one sector into tls_rx_copy)"; exit 1; }
	@test $$(wc -c < $(TOOLS_SCHEMA)) -le 384 \
		|| { echo "error: $(TOOLS_SCHEMA) > 384 B (tools-cache tail stores native tool replay history)"; exit 1; }
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_360K_BIN) \
		--loader $(LOADER_360K_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--total-sectors 720 \
		--media 0xFD \
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
