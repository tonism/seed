#!/usr/bin/env python3
"""Gate the TLS 1.3 PoC address contract against the assembled Seed runtime."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PRODUCT_CHECK = ROOT / "tools" / "check-layout.py"
PRODUCT_CORE = ROOT / "build" / "ibm_pc_5150" / "SEED.SYS"
POC_LAYOUT = HERE / "layout.inc"


def load_product_checker():
    spec = importlib.util.spec_from_file_location("seed_product_layout", PRODUCT_CHECK)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PRODUCT_CHECK}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    checker = load_product_checker()
    if not PRODUCT_CORE.exists():
        raise SystemExit(f"missing {PRODUCT_CORE}; run make first")

    product = checker.parse_equates([checker.DEFAULT_LAYOUT, checker.DEFAULT_DATA])
    poc = checker.parse_equates([POC_LAYOUT])
    core = checker.read_core(PRODUCT_CORE)

    expected_equal = {
        "poc_low_scratch_start": product["low_scratch_start"],
        "poc_low_scratch_end": product["low_scratch_end"],
        "poc_resident_start": product["core_load_addr"],
        "poc_nic_driver_slot": product["nic_driver_slot"],
        "poc_k_start": core["k_load"],
        "poc_k_end": core["k_load"] + core["k_sectors"] * checker.SECTOR,
        "poc_high_start": product["high_crypto_scratch_start"],
        "poc_high_end": product["chat_model_cache"],
        "poc_attempt_cache_start": product["chat_model_cache"],
        "poc_attempt_cache_end": product["reconnect_state_start"],
        "poc_reconnect_state_start": product["reconnect_state_start"],
        "poc_esc_handler_start": product["esc_int9_handler"],
        "poc_product_pool_start": product["chat_pool_start"],
        "poc_arena_start": product["chat_arena_start"],
        "poc_context_start": product["chat_context_start"],
        "poc_stack_guard_start": (
            product["basic_sidecar_stack_top_16k"]
            - product["basic_sidecar_stack_guard_len_16k"]
        ),
        "poc_ram_end": product["basic_sidecar_stack_top_16k"],
    }

    failures = []
    for name, expected in expected_equal.items():
        actual = poc.get(name)
        if actual != expected:
            failures.append(
                f"{name}: PoC={actual!r}, product={expected:#06x}"
            )

    exact_sizes = {
        "K bytes": (poc["poc_k_len"], 15 * 512),
        "timed code cap": (
            poc["poc_timed_code_end_max"] - poc["poc_timed_code_start"],
            13 * 512,
        ),
        "candidate work": (poc["poc_k_end"] - poc["poc_timed_code_end_max"], 1024),
        "raw ciphertext": (poc["poc_mlkem_ciphertext_len"], 1088),
        "public key": (poc["poc_mlkem_ek_len"], 1184),
        "candidate cache": (
            poc["poc_candidate_cache_end"] - poc["poc_candidate_cache"],
            96,
        ),
    }
    for label, (actual, expected) in exact_sizes.items():
        if actual != expected:
            failures.append(f"{label}: {actual}, expected {expected}")

    if failures:
        raise SystemExit("TLS13 PoC layout: FAIL\n  " + "\n  ".join(failures))

    print("TLS13 PoC layout: PASS")
    print(
        "  product bands match; K=7680 bytes, timed code<=6656 bytes, "
        "candidate work=1024 bytes"
    )
    print(
        "  arena/context/stack remain "
        f"{poc['poc_arena_start']:#06x}/"
        f"{poc['poc_context_start']:#06x}/"
        f"{poc['poc_stack_guard_start']:#06x}"
    )


if __name__ == "__main__":
    main()
