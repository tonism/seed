.DELETE_ON_ERROR:

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
BASIC_TIMER_IRET := $(shell python3 tools/check-layout.py --emit basic_timer_iret_addr)
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
SEED_SYS := $(BUILD_DIR)/SEED.SYS
SEED_SYS_LST := $(BUILD_DIR)/SEED.SYS.lst
P256_MODULE_BIN := $(BUILD_DIR)/p256_module.bin
TLS13_PACK_BASE_DIR := $(BUILD_DIR)/tls13-pack-base
TLS13_PACK_BASE_SYS := $(TLS13_PACK_BASE_DIR)/SEED.SYS
TLS13_PACK_BASE_LST := $(TLS13_PACK_BASE_DIR)/SEED.SYS.lst
TLS13_PRODUCT_PACK := $(BUILD_DIR)/tls13-k14-product-pack.bin
TLS13_PRODUCT_ABI := $(BUILD_DIR)/tls13-k14-product-abi.inc
TLS13_PRODUCT_PACK_CHECK := tools/check-tls13-product-pack.py
TLS13_PRODUCT_PACK_SOURCE := targets/$(TARGET)/boot/tls13/k14_product_pack.asm
TLS13_CORE_DISPATCH_CHECK := tools/check-tls13-core-dispatch.py
TLS13_PRODUCT_RECONNECT_CHECK := tools/check-tls13-product-reconnect.py
TLS13_APP_CHECK := tools/check-tls13-app.py
TLS13_PUBLIC_VAULT_CHECK := tools/check-tls13-public-vault.py
TLS13_SECURE_WARM_RESTART_CHECK := tools/check-secure-warm-restart.py
TLS13_K14_ABORT_CHECK := tools/crypto-bench/tls13-product/check_k14_abort_capsule.py
TLS13_K14_ABORT_REPORT := $(BUILD_DIR)/k14-abort-capsule-report.json
TLS13_286_BOOTSTRAP_BUILDER := tools/crypto-bench/tls13-product/build_286_product_bootstrap.py
TLS13_286_BOOTSTRAP_SOURCE := targets/$(TARGET)/boot/tls13/tls13_286_bootstrap.asm
TLS13_286_ABI_SOURCE := targets/$(TARGET)/boot/tls13/tls13_286_abi.inc
TLS13_286_BOOTSTRAP := $(BUILD_DIR)/tls13-286-bootstrap.bin
TLS13_286_PRODUCT_ABI := $(BUILD_DIR)/tls13-286-product-abi.inc
TLS13_286_BOOTSTRAP_LST := $(BUILD_DIR)/tls13-286-bootstrap.lst
TLS13_286_BOOTSTRAP_REPORT := $(BUILD_DIR)/tls13-286-bootstrap.json
TLS13_286_BOOTSTRAP_CHECK := tools/crypto-bench/tls13-product/check_286_product_bootstrap.py
TLS13_286_PARENT_TIME_CHECK := tools/crypto-bench/tls13-product/check_286_parent_time.py
TLS13_286_RTC_CHECK := tools/crypto-bench/tls13-product/check_286_rtc.py
TLS13_286_PARENT_TIME_SOURCE := targets/$(TARGET)/boot/phases/tls13_286_parent_time.inc
TLS13_LOW_STATIC_CONSTANTS_SOURCE := targets/$(TARGET)/boot/tls13/low_static_constants.inc
TLS13_286_BOOTSTRAP_GATE := $(BUILD_DIR)/tls13-286-bootstrap.check
TLS13_286_TAIL_BASE_DIR := $(BUILD_DIR)/tls13-286-tail-base
TLS13_286_TAIL_BASE_SYS := $(TLS13_286_TAIL_BASE_DIR)/SEED.SYS
TLS13_286_TAIL_BASE_LST := $(TLS13_286_TAIL_BASE_DIR)/SEED.SYS.lst
TLS13_286_RUNTIME_ABI_BUILDER := tools/crypto-bench/tls13-product/build_286_runtime_abi.py
TLS13_286_RUNTIME_ABI_PROBE := tools/crypto-bench/tls13-product/tls13_286_sym_abi_probe.asm
TLS13_286_RUNTIME_ABI := $(BUILD_DIR)/tls13-286-runtime-abi.inc
TLS13_286_RUNTIME_ABI_REPORT := $(BUILD_DIR)/tls13-286-runtime-abi.json
TLS13_286_TAIL_BUILDER := tools/crypto-bench/tls13-product/build_286_product_tail.py
TLS13_286_TAIL := $(BUILD_DIR)/tls13-286-product-tail.bin
TLS13_286_TAIL_ABI := $(BUILD_DIR)/tls13-286-tail-abi.inc
TLS13_286_TAIL_REPORT := $(BUILD_DIR)/tls13-286-product-tail.json
TLS13_286_TAIL_CHECK := tools/crypto-bench/tls13-product/check_286_product_tail.py
TLS13_286_MLKEM_CHECK := tools/crypto-bench/tls13-product/check_mlkem_product_modules.py
TLS13_286_X25519_CHECK := tools/crypto-bench/tls13-product/check_x25519_product_module.py
TLS13_286_HELLO_CHECK := tools/crypto-bench/tls13-product/check_286_hello_controller.py
TLS13_286_FLIGHT_CHECK := tools/crypto-bench/tls13-product/check_286_flight.py
TLS13_286_SERIALIZED_REPORT_TEST := tools/crypto-bench/tls13-product/test_run_286_tls13_serialized_gate.py
TLS13_FAT_BUDGET_CHECK := tools/check-tls13-fat-budget.py
TLS13_286_TAIL_GATE := $(BUILD_DIR)/tls13-286-product-tail.check
TLS13_PRODUCT_SOURCES := $(wildcard tools/crypto-bench/tls13-poc/*.py) \
	$(wildcard tools/crypto-bench/tls13-poc/*.asm) \
	$(wildcard tools/crypto-bench/tls13-poc/*.inc) \
	$(wildcard tools/crypto-bench/tls13-product/*.py) \
	$(wildcard tools/crypto-bench/tls13-product/*.asm) \
	$(wildcard tools/crypto-bench/tls13-product/*.inc) \
	$(wildcard targets/$(TARGET)/boot/tls13/*.asm) \
	$(wildcard targets/$(TARGET)/boot/tls13/*.inc) \
	tools/check-tls13-k14-state-guard.py
TLS13_286_TAIL_HIDDEN_INPUTS := tools/check-p256.py \
	tools/crypto-bench/tls13-spike/x25519_bench.asm \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_keygen.asm \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_candidate.asm \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_core.inc \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_vectors.inc \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_keygen_check.py \
	tools/crypto-bench/tls13-spike/mlkem768_integrated_check.py \
	tools/crypto-bench/tls13-spike/mlkem768_kernels_check.py \
	tools/crypto-bench/tls13-spike/auth_integrated_bench.asm \
	tools/crypto-bench/tls13-spike/auth_integrated_oracle.py
DRIVER_BUILD_DIR := $(BUILD_DIR)/drivers
NIC_DRIVER_BUILDER := tools/build-nic-driver.py
NIC_DRIVER_NE := $(DRIVER_BUILD_DIR)/NE.DRV
NIC_DRIVER_WD80X3 := $(DRIVER_BUILD_DIR)/WD80X3.DRV
NIC_DRIVER_3C503 := $(DRIVER_BUILD_DIR)/3C503.DRV
NIC_DRIVER_3C501 := $(DRIVER_BUILD_DIR)/3C501.DRV
NIC_DRIVER_PCNET := $(DRIVER_BUILD_DIR)/PCNET.DRV
NIC_DRIVER_TULIP := $(DRIVER_BUILD_DIR)/TULIP.DRV
NIC_DRIVER_RTL8139 := $(DRIVER_BUILD_DIR)/RTL8139.DRV
NIC_DRIVER_EPIC100 := $(DRIVER_BUILD_DIR)/EPIC100.DRV
NIC_DRIVERS := $(NIC_DRIVER_NE) $(NIC_DRIVER_WD80X3) $(NIC_DRIVER_3C503) $(NIC_DRIVER_3C501) $(NIC_DRIVER_PCNET) $(NIC_DRIVER_TULIP) $(NIC_DRIVER_RTL8139) $(NIC_DRIVER_EPIC100)
NIC_DRIVER_TULIP_MASK := 0x01
NIC_DRIVER_NE_MASK := 0x0c
NIC_DRIVER_WD80X3_MASK := 0x60
NIC_DRIVER_3C503_MASK := 0x02
NIC_DRIVER_3C501_MASK := 0x10
NIC_DRIVER_PCNET_MASK := 0x80
NIC_DRIVER_RTL8139_MASK := 0x0100
NIC_DRIVER_EPIC100_MASK := 0x0200
BASIC_BOOT_A_BIN := $(BUILD_DIR)/seed24a-loader.bin
BASIC_BOOT_A_BAS := $(BUILD_DIR)/SEED24A.BAS
BASIC_BOOT_B_BIN := $(BUILD_DIR)/seed24b-loader.bin
BASIC_BOOT_B_BAS := $(BUILD_DIR)/SEED24B.BAS
FLOPPY_IMG := $(BUILD_DIR)/floppy-160k.img
FLOPPY_IMG_360K := $(BUILD_DIR)/floppy-360k.img
FLOPPY_IMG_1440K := $(BUILD_DIR)/floppy-1440k.img
BOOT_360K_BIN := $(BUILD_DIR)/boot-360k.bin
LOADER_360K_BIN := $(BUILD_DIR)/loader-360k.bin
BOOT_1440K_BIN := $(BUILD_DIR)/boot-1440k.bin
LOADER_1440K_BIN := $(BUILD_DIR)/loader-1440k.bin
IMAGE_BUILDER := tools/build-fat12-image.py
BASIC_BOOT_BUILDER := tools/build-basic-bootstrap.py
BASIC_TIMER_QUARANTINE_CHECK := tools/check-basic-timer-quarantine.py
SEED_SYS_INFO := tools/core-sys-info.py
LAYOUT_CHECK := tools/check-layout.py
AGENT_CFG := $(wildcard config/AGENTS.CFG)
USER_CFG := $(wildcard config/USER.CFG)
INCLUDE_USER_CFG ?= 1
INCLUDE_NIC_DRIVERS ?= 1
INCLUDE_NIC_DRIVER_NE ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_WD80X3 ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_3C503 ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_3C501 ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_PCNET ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_TULIP ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_RTL8139 ?= $(INCLUDE_NIC_DRIVERS)
INCLUDE_NIC_DRIVER_EPIC100 ?= $(INCLUDE_NIC_DRIVERS)
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
# single-sided 160K image). Same SEED.SYS + same FAT12 internal layout (data at
# LBA 11); only the physical geometry the AT requires differs. The .asm geometry
# defines default to 160K, so the 160K artifacts stay byte-identical.
NASM_FLAGS_360K := $(NASM_FLAGS) -DFLOPPY_TOTAL_SECTORS=720 -DFLOPPY_SPT=9 -DFLOPPY_HEADS=2 -DFLOPPY_MEDIA=0xfd
# 1.44 MiB 3.5" geometry for later BIOSes that refuse the 5.25" images.
NASM_FLAGS_1440K := $(NASM_FLAGS) -DFLOPPY_TOTAL_SECTORS=2880 -DFLOPPY_SPT=18 -DFLOPPY_HEADS=2 -DFLOPPY_MEDIA=0xf0
FAT_FILES := --file $(SEED_SYS):SEED.SYS

ifneq ($(AGENT_CFG),)
FAT_FILES += --file $(AGENT_CFG):SEED/AGENTS.CFG
endif

ifeq ($(INCLUDE_USER_CFG),1)
ifneq ($(USER_CFG),)
FAT_FILES += --file $(USER_CFG):SEED/USER.CFG
endif
endif

FAT_DRIVER_DEPS :=

FAT_FILES += --file $(IDENTITY_PROMPT):SEED/IDENTITY --file $(COMPACT_PROMPT):SEED/COMPACT --file $(TOOLS_SCHEMA):SEED/TOOLS
ifeq ($(INCLUDE_NIC_DRIVER_NE),1)
FAT_FILES += --file $(NIC_DRIVER_NE):SEED/DRIVERS/NE.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_NE)
endif
ifeq ($(INCLUDE_NIC_DRIVER_WD80X3),1)
FAT_FILES += --file $(NIC_DRIVER_WD80X3):SEED/DRIVERS/WD80X3.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_WD80X3)
endif
ifeq ($(INCLUDE_NIC_DRIVER_3C503),1)
FAT_FILES += --file $(NIC_DRIVER_3C503):SEED/DRIVERS/3C503.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_3C503)
endif
ifeq ($(INCLUDE_NIC_DRIVER_3C501),1)
FAT_FILES += --file $(NIC_DRIVER_3C501):SEED/DRIVERS/3C501.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_3C501)
endif
ifeq ($(INCLUDE_NIC_DRIVER_PCNET),1)
FAT_FILES += --file $(NIC_DRIVER_PCNET):SEED/DRIVERS/PCNET.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_PCNET)
endif
ifeq ($(INCLUDE_NIC_DRIVER_TULIP),1)
FAT_FILES += --file $(NIC_DRIVER_TULIP):SEED/DRIVERS/TULIP.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_TULIP)
endif
ifeq ($(INCLUDE_NIC_DRIVER_RTL8139),1)
FAT_FILES += --file $(NIC_DRIVER_RTL8139):SEED/DRIVERS/RTL8139.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_RTL8139)
endif
ifeq ($(INCLUDE_NIC_DRIVER_EPIC100),1)
FAT_FILES += --file $(NIC_DRIVER_EPIC100):SEED/DRIVERS/EPIC100.DRV
FAT_DRIVER_DEPS += $(NIC_DRIVER_EPIC100)
endif

.PHONY: all clean inspect basic-bootstrap memory-map test FORCE

all: $(FLOPPY_IMG) $(FLOPPY_IMG_360K) $(FLOPPY_IMG_1440K)

FORCE:

$(BUILD_DIR):
	mkdir -p $@

$(DRIVER_BUILD_DIR):
	mkdir -p $@

$(BOOT_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

# Build 12 286 secure tier: the P-256 ECDHE module is assembled as its own flat binary at its run
# address (so p256.inc's absolute self-references resolve), then incbin'd into SEED.SYS below. It
# depends on the same core includes (layout.inc / p256.inc / p256_data.inc all live in core/*.inc).
$(P256_MODULE_BIN): $(P256_MODULE_SRC) $(CORE_INCLUDES) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -f bin -o $@ $<

$(TLS13_PACK_BASE_DIR):
	mkdir -p $@

$(TLS13_286_TAIL_BASE_DIR):
	mkdir -p $@

# The 286 dispatcher enters through one base-independent three-sector image.
# Its generated ABI and binary are prerequisites of both product links, so the
# pack-base and final resident prefixes see the same fixed phase key/geometry.
# The ABI depends on the binary to serialize this two-output builder under -j;
# if either output is removed, the builder republishes the complete pair.
$(TLS13_286_BOOTSTRAP): $(TLS13_286_BOOTSTRAP_BUILDER) $(TLS13_286_BOOTSTRAP_SOURCE) $(TLS13_286_ABI_SOURCE) | $(BUILD_DIR)
	python3 $(TLS13_286_BOOTSTRAP_BUILDER) \
		--bootstrap-out $@ \
		--abi-out $(TLS13_286_PRODUCT_ABI) \
		--listing-out $(TLS13_286_BOOTSTRAP_LST) \
		--report-out $(TLS13_286_BOOTSTRAP_REPORT)

$(TLS13_286_PRODUCT_ABI): $(TLS13_286_BOOTSTRAP) $(TLS13_286_BOOTSTRAP_BUILDER) $(TLS13_286_BOOTSTRAP_SOURCE) $(TLS13_286_ABI_SOURCE) | $(BUILD_DIR)
	@if ! test -s $@; then \
		python3 $(TLS13_286_BOOTSTRAP_BUILDER) \
			--bootstrap-out $(TLS13_286_BOOTSTRAP) \
			--abi-out $@ \
			--listing-out $(TLS13_286_BOOTSTRAP_LST) \
			--report-out $(TLS13_286_BOOTSTRAP_REPORT); \
	fi

$(TLS13_286_BOOTSTRAP_GATE): $(TLS13_286_BOOTSTRAP) $(TLS13_286_PRODUCT_ABI) $(TLS13_286_BOOTSTRAP_CHECK) $(TLS13_286_PARENT_TIME_CHECK) $(TLS13_286_RTC_CHECK) $(TLS13_286_PARENT_TIME_SOURCE) $(TLS13_LOW_STATIC_CONSTANTS_SOURCE) | $(BUILD_DIR)
	python3 $(TLS13_286_PARENT_TIME_CHECK)
	python3 $(TLS13_286_BOOTSTRAP_CHECK)
	@touch $@

# The K14 product phases have fixed sector keys beginning at sector 45.  Build
# a private copy of the current product prefix without the pack, then require
# the state/tamper/equivalence gates to publish one validated flat blob and its
# generated ABI.  The ABI is replaced first and this pack target last, making
# the pack Make's transaction marker for the pair.  Final SEED.SYS incbin's the
# blob; this is build-time source composition, not runtime module loading.
$(TLS13_PACK_BASE_SYS): $(CORE_SRC) Makefile $(CORE_INCLUDES) $(CORE_PHASE_INCLUDES) $(TLS13_LOW_STATIC_CONSTANTS_SOURCE) $(TLS13_286_BOOTSTRAP) $(TLS13_286_PRODUCT_ABI) $(TLS13_286_BOOTSTRAP_GATE) $(SEED_SYS_INFO) $(LAYOUT_CHECK) $(TLS13_PRODUCT_RECONNECT_CHECK) $(TLS13_APP_CHECK) $(TLS13_CORE_DISPATCH_CHECK) $(TLS13_SECURE_WARM_RESTART_CHECK) | $(TLS13_PACK_BASE_DIR)
	python3 $(TLS13_SECURE_WARM_RESTART_CHECK)
	nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -DTLS13_PRODUCT_PACK_BASE=1 -f bin -l $(TLS13_PACK_BASE_LST) -o $@ $<
	python3 $(SEED_SYS_INFO) --check $@
	python3 $(LAYOUT_CHECK) $@
	python3 $(TLS13_PRODUCT_RECONNECT_CHECK) \
		--core $@ \
		--listing $(TLS13_PACK_BASE_LST)
	python3 $(TLS13_APP_CHECK)

# NASM emits the listing beside the checked binary.  If only that side output
# is lost, reconstruct it in quarantine and publish it only when the newly
# assembled binary is byte-identical to the validated transaction marker.
$(TLS13_PACK_BASE_LST): $(TLS13_PACK_BASE_SYS) | $(TLS13_PACK_BASE_DIR)
	@if ! test -s "$@"; then \
		temp_dir=$$(mktemp -d "$(TLS13_PACK_BASE_DIR)/.listing-recovery.XXXXXX"); \
		trap 'rm -f "$$temp_dir/SEED.SYS" "$$temp_dir/SEED.SYS.lst"; rmdir "$$temp_dir" 2>/dev/null || true' EXIT HUP INT TERM; \
		nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -DTLS13_PRODUCT_PACK_BASE=1 -f bin \
			-l "$$temp_dir/SEED.SYS.lst" -o "$$temp_dir/SEED.SYS" $(CORE_SRC); \
		if ! cmp -s "$$temp_dir/SEED.SYS" "$(TLS13_PACK_BASE_SYS)"; then \
			echo "error: recovered pack-base listing does not match validated SEED.SYS"; \
			exit 1; \
		fi; \
		mv "$$temp_dir/SEED.SYS.lst" "$@"; \
	fi

$(TLS13_PRODUCT_PACK): $(TLS13_PRODUCT_PACK_CHECK) $(TLS13_PRODUCT_PACK_SOURCE) $(TLS13_PRODUCT_SOURCES) $(TLS13_PUBLIC_VAULT_CHECK) $(TLS13_K14_ABORT_CHECK) $(TLS13_PACK_BASE_SYS) $(TLS13_PACK_BASE_LST) | $(BUILD_DIR)
	python3 $(TLS13_PUBLIC_VAULT_CHECK)
	python3 $(TLS13_K14_ABORT_CHECK) \
		--product-core $(TLS13_PACK_BASE_SYS) \
		--product-listing $(TLS13_PACK_BASE_LST) \
		--report $(TLS13_K14_ABORT_REPORT)
	python3 $(TLS13_PRODUCT_PACK_CHECK) \
		--product-core $(TLS13_PACK_BASE_SYS) \
		--product-listing $(TLS13_PACK_BASE_LST) \
		--pack-out $@ \
		--abi-out $(TLS13_PRODUCT_ABI)

# The pack is the transaction marker for its generated ABI.  Recover a lost
# ABI through the complete checker, but never overwrite the validated pack:
# the reconstructed pack must compare byte-for-byte first.
$(TLS13_PRODUCT_ABI): $(TLS13_PRODUCT_PACK) $(TLS13_PACK_BASE_LST) $(TLS13_PRODUCT_PACK_CHECK) | $(BUILD_DIR)
	@if ! test -s "$@"; then \
		temp_dir=$$(mktemp -d "$(BUILD_DIR)/.k14-abi-recovery.XXXXXX"); \
		trap 'rm -f "$$temp_dir/product-pack.bin" "$$temp_dir/product-abi.inc"; rmdir "$$temp_dir" 2>/dev/null || true' EXIT HUP INT TERM; \
		python3 $(TLS13_PRODUCT_PACK_CHECK) \
			--product-core $(TLS13_PACK_BASE_SYS) \
			--product-listing $(TLS13_PACK_BASE_LST) \
			--pack-out "$$temp_dir/product-pack.bin" \
			--abi-out "$$temp_dir/product-abi.inc"; \
		if ! cmp -s "$$temp_dir/product-pack.bin" "$(TLS13_PRODUCT_PACK)"; then \
			echo "error: recovered K14 ABI is not bound to the validated product pack"; \
			exit 1; \
		fi; \
		mv "$$temp_dir/product-abi.inc" "$@"; \
	fi

# Bind the 16-bit 286 tail directory to a complete K14 product prefix.  This
# intermediate includes the validated K14 pack and every ordinary phase but
# deliberately omits only the appended 286 tail.  Its header therefore gives
# the exact tail start without creating a second runtime or FAT file.
$(TLS13_286_TAIL_BASE_SYS): $(CORE_SRC) Makefile $(CORE_INCLUDES) $(CORE_PHASE_INCLUDES) $(TLS13_286_BOOTSTRAP) $(TLS13_286_PRODUCT_ABI) $(TLS13_286_BOOTSTRAP_GATE) $(TLS13_PRODUCT_PACK) $(TLS13_PRODUCT_ABI) $(TLS13_PACK_BASE_LST) $(SEED_SYS_INFO) $(LAYOUT_CHECK) $(TLS13_CORE_DISPATCH_CHECK) | $(TLS13_286_TAIL_BASE_DIR)
	nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -DTLS13_PRODUCT_286_TAIL_BASE=1 -f bin -l $(TLS13_286_TAIL_BASE_LST) -o $@ $<
	python3 $(SEED_SYS_INFO) --check $@
	python3 $(LAYOUT_CHECK) $@
	python3 $(TLS13_CORE_DISPATCH_CHECK) \
		--base-core $(TLS13_PACK_BASE_SYS) \
		--base-listing $(TLS13_PACK_BASE_LST) \
		--final-core $@ \
		--final-listing $(TLS13_286_TAIL_BASE_LST)

$(TLS13_286_TAIL_BASE_LST): $(TLS13_286_TAIL_BASE_SYS) | $(TLS13_286_TAIL_BASE_DIR)
	@if ! test -s "$@"; then \
		temp_dir=$$(mktemp -d "$(TLS13_286_TAIL_BASE_DIR)/.listing-recovery.XXXXXX"); \
		trap 'rm -f "$$temp_dir/SEED.SYS" "$$temp_dir/SEED.SYS.lst"; rmdir "$$temp_dir" 2>/dev/null || true' EXIT HUP INT TERM; \
		nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -DTLS13_PRODUCT_286_TAIL_BASE=1 -f bin \
			-l "$$temp_dir/SEED.SYS.lst" -o "$$temp_dir/SEED.SYS" $(CORE_SRC); \
		if ! cmp -s "$$temp_dir/SEED.SYS" "$(TLS13_286_TAIL_BASE_SYS)"; then \
			echo "error: recovered 286 tail-base listing does not match validated SEED.SYS"; \
			exit 1; \
		fi; \
		mv "$$temp_dir/SEED.SYS.lst" "$@"; \
	fi

# Generate the only ABI through which the high-memory 286 route may call the
# exact resident prefix and the exact T13SYM02 image in the validated K14 pack.
# The builder independently reassembles the symmetric phase and requires byte
# identity with the packed image before publishing either output.
$(TLS13_286_RUNTIME_ABI): $(TLS13_286_RUNTIME_ABI_BUILDER) $(TLS13_286_RUNTIME_ABI_PROBE) $(TLS13_286_TAIL_BASE_SYS) $(TLS13_286_TAIL_BASE_LST) $(TLS13_PRODUCT_PACK) | $(BUILD_DIR)
	python3 $(TLS13_286_RUNTIME_ABI_BUILDER) \
		--core $(TLS13_286_TAIL_BASE_SYS) \
		--listing $(TLS13_286_TAIL_BASE_LST) \
		--pack $(TLS13_PRODUCT_PACK) \
		--output $@ \
		--report $(TLS13_286_RUNTIME_ABI_REPORT)
	@touch $(TLS13_286_RUNTIME_ABI_REPORT) $@

$(TLS13_286_RUNTIME_ABI_REPORT): $(TLS13_286_RUNTIME_ABI) $(TLS13_286_RUNTIME_ABI_BUILDER) $(TLS13_286_RUNTIME_ABI_PROBE) $(TLS13_286_TAIL_BASE_SYS) $(TLS13_286_TAIL_BASE_LST) $(TLS13_PRODUCT_PACK) | $(BUILD_DIR)
	@if ! test -s $@; then \
		python3 $(TLS13_286_RUNTIME_ABI_BUILDER) \
			--core $(TLS13_286_TAIL_BASE_SYS) \
			--listing $(TLS13_286_TAIL_BASE_LST) \
			--pack $(TLS13_PRODUCT_PACK) \
			--output $(TLS13_286_RUNTIME_ABI) \
			--report $@; \
	fi

# The tail builder publishes generated metadata first and the exact incbin
# payload last, making this target the transaction marker for all three.
$(TLS13_286_TAIL): $(TLS13_286_TAIL_BUILDER) $(TLS13_PRODUCT_SOURCES) $(TLS13_286_TAIL_HIDDEN_INPUTS) $(TLS13_286_TAIL_BASE_SYS) $(TLS13_286_RUNTIME_ABI) $(TLS13_286_RUNTIME_ABI_REPORT) | $(BUILD_DIR)
	python3 $(TLS13_286_TAIL_BUILDER) \
		--prefix $(TLS13_286_TAIL_BASE_SYS) \
		--tail-out $@ \
		--abi-out $(TLS13_286_TAIL_ABI) \
		--report-out $(TLS13_286_TAIL_REPORT)

$(TLS13_286_TAIL_ABI): $(TLS13_286_TAIL) $(TLS13_286_TAIL_BUILDER) $(TLS13_286_TAIL_BASE_SYS) | $(BUILD_DIR)
	@if ! test -s $@; then \
		python3 $(TLS13_286_TAIL_BUILDER) \
			--prefix $(TLS13_286_TAIL_BASE_SYS) \
			--tail-out $(TLS13_286_TAIL) \
			--abi-out $@ \
			--report-out $(TLS13_286_TAIL_REPORT) \
			--skip-dependency-build; \
	fi

$(TLS13_286_TAIL_REPORT): $(TLS13_286_TAIL_ABI) $(TLS13_286_TAIL) $(TLS13_286_TAIL_BUILDER) $(TLS13_286_TAIL_BASE_SYS) | $(BUILD_DIR)
	@if ! test -s $@; then \
		python3 $(TLS13_286_TAIL_BUILDER) \
			--prefix $(TLS13_286_TAIL_BASE_SYS) \
			--tail-out $(TLS13_286_TAIL) \
			--abi-out $(TLS13_286_TAIL_ABI) \
			--report-out $@ \
			--skip-dependency-build; \
	fi

$(TLS13_286_TAIL_GATE): $(TLS13_286_TAIL) $(TLS13_286_TAIL_ABI) $(TLS13_286_TAIL_REPORT) $(TLS13_286_TAIL_CHECK) $(TLS13_286_MLKEM_CHECK) $(TLS13_286_X25519_CHECK) $(TLS13_286_HELLO_CHECK) $(TLS13_286_FLIGHT_CHECK) $(TLS13_286_SERIALIZED_REPORT_TEST) $(TLS13_286_TAIL_BASE_SYS) | $(BUILD_DIR)
	python3 $(TLS13_286_MLKEM_CHECK)
	python3 $(TLS13_286_X25519_CHECK)
	python3 $(TLS13_286_HELLO_CHECK)
	python3 $(TLS13_286_FLIGHT_CHECK)
	python3 -m unittest $(TLS13_286_SERIALIZED_REPORT_TEST)
	python3 $(TLS13_286_TAIL_CHECK) \
		--prefix $(TLS13_286_TAIL_BASE_SYS) \
		--tail $(TLS13_286_TAIL) \
		--abi $(TLS13_286_TAIL_ABI) \
		--report $(TLS13_286_TAIL_REPORT)
	@touch $@

$(SEED_SYS): $(CORE_SRC) Makefile $(CORE_INCLUDES) $(CORE_PHASE_INCLUDES) $(TLS13_286_BOOTSTRAP) $(TLS13_286_PRODUCT_ABI) $(TLS13_286_BOOTSTRAP_GATE) $(TLS13_PRODUCT_PACK) $(TLS13_PRODUCT_ABI) $(TLS13_PACK_BASE_LST) $(TLS13_286_TAIL_BASE_SYS) $(TLS13_286_TAIL) $(TLS13_286_TAIL_ABI) $(TLS13_286_TAIL_GATE) $(SEED_SYS_INFO) $(LAYOUT_CHECK) $(TLS13_CORE_DISPATCH_CHECK) | $(BUILD_DIR)
	nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -f bin -l $(SEED_SYS_LST) -o $@ $<
	python3 $(SEED_SYS_INFO) --check $@
	python3 $(LAYOUT_CHECK) $@
	python3 $(TLS13_CORE_DISPATCH_CHECK) \
		--base-core $(TLS13_PACK_BASE_SYS) \
		--base-listing $(TLS13_PACK_BASE_LST) \
		--final-core $@ \
		--final-listing $(SEED_SYS_LST)
	python3 $(TLS13_286_TAIL_CHECK) \
		--prefix $(TLS13_286_TAIL_BASE_SYS) \
		--tail $(TLS13_286_TAIL) \
		--abi $(TLS13_286_TAIL_ABI) \
		--report $(TLS13_286_TAIL_REPORT) \
		--final-core $@

$(SEED_SYS_LST): $(SEED_SYS) | $(BUILD_DIR)
	@if ! test -s "$@"; then \
		temp_dir=$$(mktemp -d "$(BUILD_DIR)/.listing-recovery.XXXXXX"); \
		trap 'rm -f "$$temp_dir/SEED.SYS" "$$temp_dir/SEED.SYS.lst"; rmdir "$$temp_dir" 2>/dev/null || true' EXIT HUP INT TERM; \
		nasm $(NASM_FLAGS) -DTLS13_PRODUCT_TLS13=1 -f bin \
			-l "$$temp_dir/SEED.SYS.lst" -o "$$temp_dir/SEED.SYS" $(CORE_SRC); \
		if ! cmp -s "$$temp_dir/SEED.SYS" "$(SEED_SYS)"; then \
			echo "error: recovered final listing does not match validated SEED.SYS"; \
			exit 1; \
		fi; \
		mv "$$temp_dir/SEED.SYS.lst" "$@"; \
	fi

$(NIC_DRIVER_NE): targets/$(TARGET)/boot/drivers/ne.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_NE_MASK)

$(NIC_DRIVER_WD80X3): targets/$(TARGET)/boot/drivers/wd80x3.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_WD80X3_MASK)

$(NIC_DRIVER_3C503): targets/$(TARGET)/boot/drivers/el2_3c503.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_3C503_MASK)

$(NIC_DRIVER_3C501): targets/$(TARGET)/boot/drivers/el1_3c501.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_3C501_MASK)

$(NIC_DRIVER_PCNET): targets/$(TARGET)/boot/drivers/pcnet.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_PCNET_MASK)

$(NIC_DRIVER_TULIP): targets/$(TARGET)/boot/drivers/tulip.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_TULIP_MASK)

$(NIC_DRIVER_RTL8139): targets/$(TARGET)/boot/drivers/rtl8139.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_RTL8139_MASK)

$(NIC_DRIVER_EPIC100): targets/$(TARGET)/boot/drivers/epic100.inc $(SEED_SYS) $(SEED_SYS_LST) $(NIC_DRIVER_BUILDER) $(CORE_INCLUDES) | $(DRIVER_BUILD_DIR)
	python3 $(NIC_DRIVER_BUILDER) --source $< --output $@ --listing $(SEED_SYS_LST) --build-dir $(DRIVER_BUILD_DIR) --family-mask $(NIC_DRIVER_EPIC100_MASK)

$(BASIC_BOOT_A_BIN): $(BASIC_BOOT_SRC) $(SEED_SYS) Makefile | $(BUILD_DIR)
	core_sectors=$$(python3 $(SEED_SYS_INFO) --field resident-sectors $(SEED_SYS)); \
	nasm $(NASM_FLAGS) \
		-DBASIC_BOOTSTRAP_ADDR=$(BASIC_BOOTSTRAP_ADDR) \
		-DSEED_CORE_START_LBA=$(CORE_START_LBA) \
		-DSEED_CORE_SECTORS=$$core_sectors \
		-DSEED_RAM_TOP=$(BASIC_BOOTSTRAP_RAM_TOP) \
		-DSEED_BOOT_DRIVE=$(BASIC_BOOTSTRAP_A_DRIVE) \
		-DBASIC_TIMER_IRET=$(BASIC_TIMER_IRET) \
		-f bin -o $@ $<

$(BASIC_BOOT_B_BIN): $(BASIC_BOOT_SRC) $(SEED_SYS) Makefile | $(BUILD_DIR)
	core_sectors=$$(python3 $(SEED_SYS_INFO) --field resident-sectors $(SEED_SYS)); \
	nasm $(NASM_FLAGS) \
		-DBASIC_BOOTSTRAP_ADDR=$(BASIC_BOOTSTRAP_ADDR) \
		-DSEED_CORE_START_LBA=$(CORE_START_LBA) \
		-DSEED_CORE_SECTORS=$$core_sectors \
		-DSEED_RAM_TOP=$(BASIC_BOOTSTRAP_RAM_TOP) \
		-DSEED_BOOT_DRIVE=$(BASIC_BOOTSTRAP_B_DRIVE) \
		-DBASIC_TIMER_IRET=$(BASIC_TIMER_IRET) \
		-f bin -o $@ $<

$(BASIC_BOOT_A_BAS): $(BASIC_BOOT_A_BIN) $(BASIC_BOOT_BUILDER) | $(BUILD_DIR)
	python3 $(BASIC_BOOT_BUILDER) \
		--input $(BASIC_BOOT_A_BIN) \
		--output $@ \
		--load-addr $(BASIC_BOOTSTRAP_ADDR) \
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP) \
		--max-addr $(BASIC_BOOTSTRAP_MAX_ADDR) \
		--encoding decimal-data

$(BASIC_BOOT_B_BAS): $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_BUILDER) | $(BUILD_DIR)
	python3 $(BASIC_BOOT_BUILDER) \
		--input $(BASIC_BOOT_B_BIN) \
		--output $@ \
		--load-addr $(BASIC_BOOTSTRAP_ADDR) \
		--clear-top $(BASIC_BOOTSTRAP_CLEAR_TOP) \
		--max-addr $(BASIC_BOOTSTRAP_MAX_ADDR) \
		--encoding decimal-data

$(FLOPPY_IMG): FORCE $(BOOT_BIN) $(LOADER_BIN) $(SEED_SYS) $(FAT_DRIVER_DEPS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(TOOLS_SCHEMA) $(IMAGE_BUILDER) $(TLS13_FAT_BUDGET_CHECK) | $(BUILD_DIR)
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
	python3 $(TLS13_FAT_BUDGET_CHECK) \
		--image $@ \
		--tail-report $(TLS13_286_TAIL_REPORT)
	python3 $(TLS13_PRODUCT_RECONNECT_CHECK) \
		--core $(SEED_SYS) \
		--listing $(SEED_SYS_LST) \
		--image $@

$(BOOT_360K_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_360K) -f bin -o $@ $<

$(LOADER_360K_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_360K) -f bin -o $@ $<

$(BOOT_1440K_BIN): $(BOOT_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_1440K) -f bin -o $@ $<

$(LOADER_1440K_BIN): $(LOADER_SRC) | $(BUILD_DIR)
	nasm $(NASM_FLAGS_1440K) -f bin -o $@ $<

$(FLOPPY_IMG_360K): FORCE $(BOOT_360K_BIN) $(LOADER_360K_BIN) $(SEED_SYS) $(FAT_DRIVER_DEPS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(TOOLS_SCHEMA) $(IMAGE_BUILDER) | $(BUILD_DIR)
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

$(FLOPPY_IMG_1440K): FORCE $(BOOT_1440K_BIN) $(LOADER_1440K_BIN) $(SEED_SYS) $(FAT_DRIVER_DEPS) $(AGENT_CFG) $(USER_CFG) $(IDENTITY_PROMPT) $(COMPACT_PROMPT) $(TOOLS_SCHEMA) $(IMAGE_BUILDER) | $(BUILD_DIR)
	@LC_ALL=C grep -l '["\\]' $(IDENTITY_PROMPT) $(COMPACT_PROMPT) >/dev/null 2>&1 \
		&& { echo "error: a streamed prompt contains a \" or \\ (breaks JSON / Content-Length)"; exit 1; } || true
	@test $$(wc -c < $(IDENTITY_PROMPT)) -le 512 \
		|| { echo "error: $(IDENTITY_PROMPT) > 512 B (must fit one sector, streamed as <=440 B records)"; exit 1; }
	@test $$(wc -c < $(COMPACT_PROMPT)) -le 512 \
		|| { echo "error: $(COMPACT_PROMPT) > 512 B (contract staging reads one sector into tls_rx_copy)"; exit 1; }
	@test $$(wc -c < $(TOOLS_SCHEMA)) -le 384 \
		|| { echo "error: $(TOOLS_SCHEMA) > 384 B (tools-cache tail stores native tool replay history)"; exit 1; }
	python3 $(IMAGE_BUILDER) build \
		--boot $(BOOT_1440K_BIN) \
		--loader $(LOADER_1440K_BIN) \
		--loader-sectors $(LOADER_SECTORS) \
		--total-sectors 2880 \
		--media 0xF0 \
		--output $@ \
		$(FAT_FILES)

inspect: $(FLOPPY_IMG) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	python3 $(BASIC_TIMER_QUARANTINE_CHECK) \
		--core $(SEED_SYS) \
		--loader-a $(BASIC_BOOT_A_BIN) --basic-a $(BASIC_BOOT_A_BAS) \
		--loader-b $(BASIC_BOOT_B_BIN) --basic-b $(BASIC_BOOT_B_BAS)
	ls -l $(FLOPPY_IMG) $(BOOT_BIN) $(LOADER_BIN) $(SEED_SYS) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS) $(FAT_DRIVER_DEPS)
	python3 $(SEED_SYS_INFO) \
		--load-addr $(CORE_LOAD_ADDR) \
		--range high-crypto:$(HIGH_CRYPTO_SCRATCH_START):$(HIGH_CRYPTO_SCRATCH_LEN) \
		--range critical:$(CRITICAL_SCRATCH_START):$(CRITICAL_SCRATCH_LEN) \
		--packed-phase K \
		--packed-range high-crypto:$(HIGH_CRYPTO_SCRATCH_LEN) \
		--packed-range critical:$(CRITICAL_SCRATCH_LEN) \
		--budget 24k-basic:$(BASIC_BOOTSTRAP_24K_RAM_TOP):$(BASIC_BOOTSTRAP_24K_STACK_GUARD) \
		--budget 16k-target:$(BASIC_BOOTSTRAP_16K_RAM_TOP):$(BASIC_BOOTSTRAP_16K_STACK_GUARD) \
		$(SEED_SYS)
	xxd -g 1 -l 192 $(FLOPPY_IMG)
	xxd -g 1 -s 512 -l 192 $(FLOPPY_IMG)
	python3 $(IMAGE_BUILDER) list $(FLOPPY_IMG)

basic-bootstrap: $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BAS)
	python3 $(BASIC_TIMER_QUARANTINE_CHECK) \
		--core $(SEED_SYS) \
		--loader-a $(BASIC_BOOT_A_BIN) --basic-a $(BASIC_BOOT_A_BAS) \
		--loader-b $(BASIC_BOOT_B_BIN) --basic-b $(BASIC_BOOT_B_BAS)
	ls -l $(BASIC_BOOT_A_BIN) $(BASIC_BOOT_A_BAS) $(BASIC_BOOT_B_BIN) $(BASIC_BOOT_B_BAS)

memory-map: $(SEED_SYS)
	python3 tools/memory-map.py --update docs/memory.md

test:
	python3 tools/check-p256.py
	python3 tools/check-tls-prf.py
	python3 tools/check-chacha-poly1305.py

clean:
	rm -rf build
