#!/usr/bin/env python3
"""Build 12 region/lifetime checker — the single, authoritative view of Seed's
memory layout (O4/O7).

It does three things, all at build time:

1. Resolves the layout from one source — ``layout.inc`` + ``data.inc`` equates
   (addresses) plus the assembled ``CORE.SYS`` header (the nucleus + K-window
   extents that depend on assembly position). No constant is duplicated here.
2. Prints a labeled band map — owner + lifetime for each region — the readable
   single source that ``docs/memory.md`` and the inspect budget derive from.
3. Asserts the structural invariants and the intended-alias web. Bands must not
   collide; declared overlays (the lifetime-disjoint reuse the alias web depends
   on) must stay intact. A NEW accidental alias, or a broken intended one, fails
   the build.

Lifetimes are coarse (session-phase granularity): this proves declared overlays
are *declared* and the band geometry holds; it does not prove the code respects a
buffer's lifetime inside a phase (that needs execution analysis). It is the map +
the accidental-overlap guard, not a timing prover. See docs/architecture.md
"Memory Shape" and "One Source of Truth".
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "targets/ibm_pc_5150/boot/core"
DEFAULT_LAYOUT = CORE / "layout.inc"
DEFAULT_DATA = CORE / "data.inc"
# Build 12 NIC HAL: the vtable slots are declared in data.inc; the driver modules carry the headers.
HARDWARE_SETUP = ROOT / "targets/ibm_pc_5150/boot/phases/hardware_setup.inc"
DRIVERS = ROOT / "targets/ibm_pc_5150/boot/drivers"

SECTOR = 512
MAGIC = b"SEEDCORE"
RESIDENT_SECTORS_OFF = 15
PHASE_TABLE_OFF_OFF = 19
PHASE_COUNT_OFF = 21
PHASE_ENTRY = 10


# --- layout.inc / data.inc equate resolution (shared shape with memory-map.py) -------

def _eval(expr: str, consts: dict[str, int]) -> int:
    # NASM integer expressions used in the layout: + - * / ( ), names, hex/dec.
    py = expr.replace("/", "//")
    return int(eval(py, {"__builtins__": {}}, consts))


def parse_equates(paths: list[Path]) -> dict[str, int]:
    """Parse ``name equ <int expr>`` across files, iterating to a fixpoint so
    forward references resolve regardless of order (as NASM allows)."""
    lines: list[str] = []
    for path in paths:
        lines.extend(path.read_text().splitlines())
    consts: dict[str, int] = {}
    while True:
        before = len(consts)
        for raw in lines:
            line = raw.split(";", 1)[0].strip()
            m = re.match(r"^(\w+)\s+equ\s+(.+)$", line)
            if not m or m.group(1) in consts:
                continue
            try:
                consts[m.group(1)] = _eval(m.group(2).strip(), consts)
            except Exception:
                continue
        if len(consts) == before:
            return consts


def read_core(path: Path) -> dict:
    data = path.read_bytes()
    if data[3 : 3 + len(MAGIC)] != MAGIC:
        raise SystemExit(f"{path}: missing SEEDCORE header")

    def u16(off: int) -> int:
        return data[off] | (data[off + 1] << 8)

    resident_sectors = u16(RESIDENT_SECTORS_OFF)
    table_off = u16(PHASE_TABLE_OFF_OFF)
    count = u16(PHASE_COUNT_OFF)
    phases = []
    for i in range(count):
        e = table_off + i * PHASE_ENTRY
        pid = data[e : e + 2].decode("ascii", "replace").rstrip("\x00")
        sectors = u16(e + 4)
        load = u16(e + 6)
        phases.append({"id": pid, "load": load, "sectors": sectors, "end": load + sectors * SECTOR})
    k = next((p for p in phases if p["id"] == "K"), None)
    return {
        "resident_sectors": resident_sectors,
        "resident_bytes": resident_sectors * SECTOR,
        "k_load": k["load"] if k else None,
        "k_sectors": k["sectors"] if k else None,
        "phases": phases,
        "total_bytes": len(data),
    }


# --- the layout model: bands (non-overlapping map) + aliases (intended overlays) -----

LIFETIMES = {
    "external": "BIOS-owned, not Seed",
    "const": "read-only constant, whole session",
    "session": "live the whole session (resident state/code)",
    "resident": "permanently resident code",
    "reconnect": "must survive a mid-session reconnect handshake",
    "handshake": "handshake-only (key schedule / transcript / Finished)",
    "per-turn": "transient scratch for one request/response",
    "persistent": "user-facing, survives everything (context + arena)",
    "reserved": "guard / stack reserve",
}


def build_bands(c: dict[str, int], core: dict) -> list[dict]:
    """The fixed 16 KiB band map, low -> high. Each band is a non-overlapping
    address range; ``end`` is exclusive. The arena/context bands scale up with
    ram_top on bigger machines (shown here at the 16 KiB ceiling)."""
    nucleus_end = c["core_load_addr"] + core["resident_bytes"]
    k_start = core["k_load"]
    k_end = core["k_load"] + core["k_sectors"] * SECTOR
    g16 = c["basic_sidecar_stack_top_16k"] - c["basic_sidecar_stack_guard_len_16k"]
    spec = [
        ("BIOS IVT + BDA", 0x0000, 0x0500, "external", "BIOS"),
        ("SHA-256 K table", c["low_sha256_k"], c["low_sha256_k"] + c["sha256_k_len"], "const", "crypto"),
        ("handoff (capability vector)", c["handoff_addr"], c["handoff_addr"] + c["handoff_size_bytes"], "session", "handoff"),
        ("low runtime state", c["low_runtime_state_start"], c["low_runtime_state_end"], "session", "tls/net/sha state"),
        ("low scratch window (phases + pkt/fs overlay)", c["low_scratch_start"], c["low_scratch_end"], "per-turn", "phase loader"),
        ("resident nucleus (shared)", c["core_load_addr"], c["nic_driver_slot"], "resident", "nucleus"),
        ("active-driver slot", c["nic_driver_slot"], c["nic_driver_slot_end"], "resident", "active NIC driver — loaded at boot; inactive drivers cost 0"),
        ("K crypto window", k_start, k_end, "resident", "crypto code"),
        ("high crypto scratch (session keys)", c["high_crypto_scratch_start"], c["high_crypto_scratch_end"], "handshake", "tls keys (re-derived on reconnect)"),
        ("critical scratch (RX stream + AEAD)", c["critical_scratch_start"], c["critical_scratch_end"], "per-turn", "tls record + handshake scratch"),
        ("per-turn TLS app framing (tls_app_*)", c["critical_scratch_end"], c["chat_model_cache"], "per-turn", "tls_app_* record framing"),
        ("chat config caches (reconnect rebuild)", c["chat_model_cache"], c["reconnect_state_start"], "reconnect", "model + key cache"),
        ("reconnect-safe state", c["reconnect_state_start"], c["reconnect_state_end"], "reconnect", "reconnect/compaction/esc state"),
        ("ESC handler", c["esc_int9_handler"], c["chat_pool_start"], "reconnect", "keyboard escape hook (survives reconnect)"),
        ("user/agent arena", c["chat_arena_start"], c["chat_context_start"], "persistent", "arena"),
        ("conversation window", c["chat_context_start"], c["chat_context_end"], "persistent", "context"),
        ("16K stack guard / stack", g16, c["basic_sidecar_stack_top_16k"], "reserved", "stack"),
    ]
    return [
        {"name": n, "start": s, "end": e, "lifetime": lt, "owner": o}
        for (n, s, e, lt, o) in spec
    ]


# Intended overlays: the lifetime-disjoint reuse the layout depends on. Each is a
# pair of symbols that MUST stay equal (the alias web), with the justification that
# today lives only in data.inc comments. Breaking one, or a future edit silently
# making two live regions equal, fails the build.
ALIASES = [
    ("low_crypto_work", "ne_tx_frame",
     "handshake/PRF crypto work reuses the NIC TX frame; copy-before-crypto (Build 11 fix)"),
    ("low_sha256_saved_state", "low_crypto_work", "SHA save-state shares the low crypto work arena"),
    ("critical_chacha_state", "low_crypto_work", "record ChaCha state reuses the low crypto work arena"),
    ("critical_poly_acc", "critical_chacha_state", "Poly1305 accumulator overlays the ChaCha state slot"),
    ("chacha_state", "critical_chacha_state", "public chacha_state name -> the critical overlay"),
    ("poly_acc", "critical_poly_acc", "public poly_acc name -> the critical overlay"),
    ("tls_premaster_secret", "high_crypto_work", "premaster derives in the high crypto work arena"),
    ("tls_key_block", "high_crypto_work", "key block derives in the high crypto work arena"),
    ("agent_ids", "high_crypto_work", "agent-id scan reuses the high crypto work arena (pre-handshake)"),
    ("poly_rx_save", "tls_master_secret",
     "streaming-receive MAC state parks in the handshake-only master secret"),
    ("tls_app_record_buffer", "api_request_plain", "encrypted app record built over the plaintext request arena"),
    ("tls_server_random", "seed_agent_id", "post-request, seed config arena reused for TLS handshake state"),
    ("api_response_text_buf", "fs_sector_buffer", "response text scanner reuses the fs sector buffer"),
    ("dpi_input_buf", "tls_rx_copy", "DPI prompt input reuses the TLS receive buffer"),
    ("tls_client_hello_buffer", "tls_rx_copy", "ClientHello built in the TLS receive buffer"),
    ("sha256_k", "low_sha256_k", "public sha256_k name -> the low K table"),
    ("tls_rx_copy", "critical_scratch_start", "the TLS receive buffer is the base of critical scratch"),
    ("tls_app_len", "critical_scratch_end", "cross-phase TLS app state begins at the critical scratch tail"),
    ("reconnect_state_start", "chat_cache_end", "reconnect-safe block begins above the chat config caches"),
]


def check_nic_vtable(c: dict[str, int], data_path: Path, drivers_dir: Path) -> tuple[list[str], list[tuple[str, int]], list[str]]:
    """Build 12 NIC HAL guard. The dispatch vector is filled at boot by loading the detected family's
    driver module into the active-driver slot and copying its header — the first nic_vt_slot_count
    words — into the resident nic_vtable. So the invariant is: (1) nic_vtable declares exactly
    nic_vt_slot_count word slots, and (2) every driver module begins with exactly that many `dw`
    header entries (else the boot header copy reads the wrong number of pointers and a card dies).
    Source-parsed — the slots and headers are `dw` data, invisible to the equate model.

    Returns (slots, [(driver, header_dw_count)], issues)."""
    issues: list[str] = []
    slot_count = c.get("nic_vt_slot_count")

    # 1. the nic_vtable slot labels (contiguous `nic_vt_* dw` block under `nic_vtable:`).
    slots: list[str] = []
    in_table = False
    for raw in data_path.read_text().splitlines():
        s = raw.split(";", 1)[0].strip()
        if s == "nic_vtable:":
            in_table = True
            continue
        if in_table:
            m = re.match(r"^(nic_vt_\w+)\s+dw\b", s)
            if m:
                slots.append(m.group(1))
            elif s:  # first non-slot, non-blank line ends the table
                break
    if not slots:
        issues.append("nic_vtable: no slots parsed from data.inc (label renamed/removed?)")
    if slot_count is not None and slots and len(slots) != slot_count:
        issues.append(f"nic_vtable declares {len(slots)} slots but nic_vt_slot_count = {slot_count}")

    # 2. each driver module begins with exactly nic_vt_slot_count `dw` header entries (the run of
    #    leading `dw` lines before the first label / instruction).
    headers: list[tuple[str, int]] = []
    drivers = sorted(drivers_dir.glob("*.inc")) if drivers_dir.is_dir() else []
    if not drivers:
        issues.append(f"no NIC driver modules found in {drivers_dir}")
    for d in drivers:
        n = 0
        for raw in d.read_text().splitlines():
            s = raw.split(";", 1)[0].strip()
            if not s:
                continue
            if re.match(r"^dw\b", s):
                n += 1
                continue
            break
        headers.append((d.name, n))
        if slot_count is not None and n != slot_count:
            issues.append(f"driver {d.name}: header has {n} dw entries, expected nic_vt_slot_count = {slot_count}")
    return slots, headers, issues


def run(core_path: Path, layout: Path, data: Path) -> int:
    c = parse_equates([layout, data])
    core = read_core(core_path)

    missing = [s for pair in ALIASES for s in pair[:2] if s not in c]
    bands = build_bands(c, core)

    # The reconnect-safe line: above it, everything must survive a mid-session
    # reconnect handshake (the conversation context + arena + the caches/state
    # needed to rebuild a request); below it, everything is clobbered or rebuilt by
    # that handshake (the keys are re-derived, the RX/AEAD scratch reused, the
    # per-turn tls_app_* framing rebuilt). The boundary is chat_model_cache: the
    # per-turn tls_app_* block sits just below it, the reconnect-survivor pool
    # (caches -> reconnect state -> keepalive/ESC -> window -> arena) contiguous
    # above. Enforced below.
    line = c["chat_model_cache"]
    print("Seed memory layout — bands (16 KiB ceiling; arena scales with ram_top)\n")
    print(f"  {'range':<15} {'size':>6}  {'lifetime':<11} owner / region")
    drawn = False
    for b in sorted(bands, key=lambda x: x["start"]):
        if not drawn and b["start"] >= line:
            print(f"  {'─' * 13} reconnect-safe line @ {line:#06x} {'─' * 8}")
            drawn = True
        size = b["end"] - b["start"]
        print(
            f"  {b['start']:#06x}..{b['end']:#06x} {size:>6}  "
            f"{b['lifetime']:<11} {b['owner']} — {b['name']}"
        )

    # Phase footprints: each demand-loaded phase below the nucleus must not run
    # into the resident nucleus at core_load_addr (the "phase rounded up a sector
    # and clobbered the nucleus" class). The K window is exempt (loads above it).
    print("\nPhase load footprints (demand-loaded; must end <= nucleus):")
    errors: list[str] = []
    for p in sorted(core["phases"], key=lambda x: (x["load"], x["id"])):
        below = p["load"] < c["core_load_addr"]
        flag = ""
        if below and p["end"] > c["core_load_addr"]:
            flag = "  << OVERRUNS NUCLEUS"
            errors.append(
                f"phase {p['id']} {p['load']:#06x}+{p['sectors']}s ends {p['end']:#06x} "
                f"> nucleus {c['core_load_addr']:#06x}"
            )
        print(f"  {p['id']:<2} {p['load']:#06x}..{p['end']:#06x} ({p['sectors']}s){flag}")

    # 1. Bands must not collide (the address map is a partition, not an overlay).
    ordered = sorted(bands, key=lambda x: x["start"])
    for a, b in zip(ordered, ordered[1:]):
        if b["start"] < a["end"]:
            errors.append(
                f"band overlap: {a['name']} ({a['start']:#06x}..{a['end']:#06x}) "
                f"vs {b['name']} ({b['start']:#06x}..{b['end']:#06x})"
            )

    # 1b. The reconnect-safe-line invariant (the lifetime-band model, enforced):
    #   - the survivor pool ABOVE the line is one CONTIGUOUS block (the arena does
    #     not fragment; nothing per-turn wedges between survivors), and
    #   - no survivor (reconnect/persistent lifetime) is stranded BELOW the line.
    # Two transients (tls_retransmit_seq, chat_effective_cap) live inside the
    # reconnect_state band for headroom — accepted: they are sub-fields rewritten
    # before each use, and 16K has no room below the line to rehome them.
    survivors = [b for b in ordered if b["start"] >= line and b["lifetime"] != "reserved"]
    for a, b in zip(survivors, survivors[1:]):
        if b["start"] != a["end"]:
            errors.append(
                f"reconnect-safe pool not contiguous: {a['name']} ends {a['end']:#06x} "
                f"but {b['name']} starts {b['start']:#06x}"
            )
    for b in ordered:
        if b["start"] < line and b["lifetime"] in ("reconnect", "persistent"):
            errors.append(
                f"survivor band below the reconnect-safe line {line:#06x}: "
                f"{b['name']} ({b['lifetime']})"
            )

    # 2. Structural invariants (mirror the nasm %error guards, in one readable place).
    def need(expr_name: str, cond: bool, detail: str) -> None:
        if not cond:
            errors.append(f"invariant failed [{expr_name}]: {detail}")

    nucleus_end = c["core_load_addr"] + core["resident_bytes"]
    k_end = core["k_load"] + core["k_sectors"] * SECTOR
    need("nucleus<=K", nucleus_end <= core["k_load"],
         f"nucleus ends {nucleus_end:#06x}, K loads {core['k_load']:#06x}")
    need("K<=hi-scratch", k_end <= c["high_crypto_scratch_start"],
         f"K ends {k_end:#06x}, high crypto scratch at {c['high_crypto_scratch_start']:#06x}")
    need("hi==crit", c["high_crypto_scratch_end"] == c["critical_scratch_start"],
         f"high end {c['high_crypto_scratch_end']:#06x} != critical start {c['critical_scratch_start']:#06x}")
    need("crit<=24k-guard",
         c["critical_scratch_end"] <= c["basic_sidecar_stack_top_24k"] - c["basic_sidecar_stack_guard_len_24k"],
         f"critical ends {c['critical_scratch_end']:#06x}")
    need("low-rt<=0x700", c["low_runtime_state_end"] <= c["low_scratch_start"],
         f"low runtime state ends {c['low_runtime_state_end']:#06x}")
    for arena in ("low_file_scratch_end", "low_phase_state_end", "low_static_constants_end", "low_tail_state_end"):
        need(f"{arena}<=0x1000", c[arena] <= c["low_scratch_end"], f"{arena} = {c[arena]:#06x}")
    g16 = c["basic_sidecar_stack_top_16k"] - c["basic_sidecar_stack_guard_len_16k"]
    need("caches<=16k-guard", c["chat_cache_end"] <= g16, f"chat_cache_end = {c['chat_cache_end']:#06x}")
    need("arena-floor", c["chat_arena_start"] + c["chat_arena_floor_min"] <= g16,
         f"arena floor {c['chat_arena_start'] + c['chat_arena_floor_min']:#06x} exceeds guard {g16:#06x}")

    # 2b. The 286-only P-256/RSA secure-crypto module (Build 12 secure tier). It is loaded ONLY on the
    #     286 secure path into a high band that OVERLAYS the 32K loop cache (lifetime-disjoint: the
    #     module runs during the boot handshake; the loop cache preloads after, and a reconnect disables
    #     the cache). So it is NOT part of the 16K partition above. Model it here: print its band and
    #     assert it stays clear of the low crypto/NIC scratch (no 0x0700 / 0x36c2 alias — LANDMINE #4)
    #     and fits the loop cache. A future edit that moves it down into live scratch fails the build.
    if "p256_module_load" in c and "p256_module_end" in c:
        pm_start, pm_end = c["p256_module_load"], c["p256_module_end"]
        print("\n286 secure-crypto module (286-only; overlays the 32K loop cache, 0 RAM on 16K):")
        print(f"  P-256 ECDHE + RSA cert-verify  {pm_start:#06x}..{pm_end:#06x} "
              f"({(pm_end - pm_start) // SECTOR} sectors max)")
        need("module>crit", pm_start >= c["critical_scratch_end"],
             f"module loads {pm_start:#06x}, must be above critical scratch {c['critical_scratch_end']:#06x} (no 0x0700/0x36c2 alias)")
        need("module==loopcache", pm_start == c["loop_cache_start"],
             f"module loads {pm_start:#06x}, expected loop_cache_start {c['loop_cache_start']:#06x} (the overlay band)")
        need("module<=loopcache-end", pm_end <= c["loop_cache_end"],
             f"module ends {pm_end:#06x}, loop cache ends {c['loop_cache_end']:#06x}")

    # 3. Intended aliases must stay intact.
    print("\nIntended overlays (lifetime-disjoint reuse — must stay equal):")
    for sym_a, sym_b, why in ALIASES:
        if sym_a not in c or sym_b not in c:
            print(f"  ?  {sym_a} == {sym_b}  (unresolved symbol)")
            continue
        ok = c[sym_a] == c[sym_b]
        print(f"  {'ok' if ok else 'XX'} {sym_a} == {sym_b} ({c[sym_a]:#06x})  — {why}")
        if not ok:
            errors.append(f"broken alias: {sym_a}({c[sym_a]:#06x}) != {sym_b}({c[sym_b]:#06x})")

    # 4. NIC HAL: the dispatch vector is filled from a driver module's header at boot. Check the
    #    slot count, that every driver's header matches it, and that the slot abuts the K window.
    slots, headers, vt_issues = check_nic_vtable(c, data, DRIVERS)
    print("\nNIC HAL active-driver slot (driver header -> nic_vtable; inactive drivers cost 0 RAM):")
    print(f"  {len(slots)} vtable slots; driver headers: " + ", ".join(f"{n}={h}" for n, h in headers))
    if "nic_driver_slot_end" in c and c["nic_driver_slot_end"] != core["k_load"]:
        vt_issues.append(
            f"active-driver slot end {c['nic_driver_slot_end']:#06x} != K window start {core['k_load']:#06x}"
        )
    errors.extend(vt_issues)

    if missing:
        errors.append(f"unresolved alias symbols: {sorted(set(missing))}")

    print()
    if errors:
        print(f"check-layout: FAIL ({len(errors)} issue(s))")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"check-layout: OK — {len(bands)} bands, {len(ALIASES)} intended overlays intact")
    return 0


# Layout values other tooling needs (the inspect/budget ranges). Derived from
# layout.inc so they cannot drift — replaces the Makefile's hand-synced copies.
EMIT = {
    "high_crypto_scratch_start": lambda c: c["high_crypto_scratch_start"],
    "high_crypto_scratch_len": lambda c: c["high_crypto_scratch_end"] - c["high_crypto_scratch_start"],
    "critical_scratch_start": lambda c: c["critical_scratch_start"],
    "critical_scratch_len": lambda c: c["critical_scratch_len"],
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("core_sys", type=Path, nargs="?", help="assembled CORE.SYS (for nucleus + K-window extents)")
    ap.add_argument("--layout", type=Path, default=DEFAULT_LAYOUT)
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--emit", choices=sorted(EMIT), help="print one layout value (from layout.inc) and exit")
    args = ap.parse_args()
    if args.emit:
        c = parse_equates([args.layout, args.data])
        value = EMIT[args.emit](c)
        # starts as hex (addresses), lengths as decimal — matches inspect-range style.
        print(f"{value:#06x}" if args.emit.endswith("_start") else value)
        return 0
    if args.core_sys is None:
        ap.error("core_sys is required unless --emit is given")
    return run(args.core_sys, args.layout, args.data)


if __name__ == "__main__":
    raise SystemExit(main())
