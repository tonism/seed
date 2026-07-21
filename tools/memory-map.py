#!/usr/bin/env python3
"""Render Seed's memory map at several points along the boot/hydration arc.

Supported stages:

  cold        BIOS-only RAM; Seed has not run yet.
  loaded      SEED.SYS resident nucleus has been read in; no cold phase
              has run, no K LINK window yet.
  readiness   Hydration complete: K window loaded, handoff filled,
              persistent TLS state derived, TLS RX buffer holding the
              encrypted response, agent_response phase has just
              confirmed the proof. This is the densest moment in
              memory — what the cleanup pass is about to act on.
  cleanup     Optional. Available only on branches that include the cleanup
              phase. After cleanup has zeroed every DISCARDED range.

When present, the cleanup-stage map is derived from the actual cleanup table
embedded in SEED.SYS, so it stays in sync with the build. The earlier stages
are reconstructed from layout.inc constants plus the SEED.SYS header
(resident size, K window load address). No stage requires running the binary.

Run with no flags to print all four stages to stdout. Use ``--update
PATH`` to patch the visuals into a markdown file. The script looks for
marker pairs of the form:

    <!-- BEGIN MAP: stage-<name> -->
    <!-- END MAP: stage-<name> -->

and replaces whatever is between them with the freshly-generated block.
"""

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CELL_BYTES = 128
ROW_CELLS = 32
ROW_BYTES = CELL_BYTES * ROW_CELLS
TOTAL_BYTES = 0x4000
ROWS = TOTAL_BYTES // ROW_BYTES
STACK_START = 0x3F00

GLYPH = {
    'bios':         '█',
    'nucleus':      '▓',
    'k_window':     '▒',
    'tls_state':    't',
    'crypto_const': 'c',
    'rx_buffer':    'r',
    'reconnect_scratch': ':',
    'agent_config': 'a',
    'handoff':      'h',
    'wire_state':   'w',
    'context':      'm',
    'arena':        '+',
    'cleaned':      '.',
    'phase_local':  ',',
    'free':         ' ',
    'stack':        '|',
}

PRIORITY = [
    'bios',
    'nucleus',
    'k_window',
    'stack',
    'tls_state',
    'crypto_const',
    'rx_buffer',
    'reconnect_scratch',
    'handoff',
    'wire_state',
    'arena',
    'context',
    'agent_config',
    'cleaned',
    'phase_local',
    'free',
]

STAGES = ['cold', 'nucleus', 'hal', 'net', 'agent-prep', 'tls', 'dpi', 'cleanup']
DEFAULT_STAGES = ['cold', 'nucleus', 'hal', 'net', 'agent-prep', 'tls', 'dpi']
MARKER_BEGIN = '<!-- BEGIN MAP: stage-{stage} -->'
MARKER_END = '<!-- END MAP: stage-{stage} -->'


@dataclass
class Ctx:
    consts: dict
    phases: dict
    resident_sectors: int
    cleanup_ranges: list


def parse_equates(path: Path, consts: dict | None = None) -> dict:
    """Parse ``name equ <int_expr>`` lines from a NASM include file.

    NASM itself accepts forward references between ``equ`` symbols, so
    iterate until convergence rather than requiring source order. Lines
    that don't fit (``dw``, ``db``, macros, ``%if``, etc.) are silently
    skipped — we only need the integer constants below.
    """
    consts = dict(consts) if consts else {}
    lines = path.read_text().splitlines()
    while True:
        added = 0
        for raw in lines:
            line = raw.split(';', 1)[0].strip()
            m = re.match(r'^(\w+)\s+equ\s+(.+)$', line)
            if not m:
                continue
            name, expr = m.group(1), m.group(2).strip()
            try:
                value = _eval(expr, consts)
            except Exception:
                continue
            if name not in consts:
                added += 1
            consts[name] = value
        if added == 0:
            break
    return consts


def parse_listing(path: Path, org_base: int) -> dict:
    """Extract label addresses from a NASM listing file.

    NASM's `-l` listing prints lines as:
        <line_no> <hex_offset> <emitted_bytes>          <source>
    For label declarations that have no emit on the same line, NASM
    omits the offset; the label's address is the offset of the *next*
    line that emits bytes. We walk pending labels until we see an
    emit, then bind them all to that offset (plus the org base).

    The org base must be supplied by the caller (read from the layout
    constants) — Phase 4.5 Step F-3 moved the resident from 0x1000
    down to 0x600, so a hardcoded value would silently mis-render.
    """
    if not path.exists():
        return {}
    consts: dict = {}
    pending: list[str] = []
    line_with_offset = re.compile(r'^\s*\d+\s+([0-9A-Fa-f]{8})\s+')
    inline_label = re.compile(r'^\s*(\w+):\s+(?:times|db|dw|dq|resb)\b')
    label_only = re.compile(r'^\s*(\w+):\s*(?:;.*)?$')
    # NASM listing format: `<line-no> <offset?> <bytes?>   <<level>> <source>`.
    # Match `<N>` reliably and capture everything after it as source.
    level_marker = re.compile(r'<\d+>\s*(.*)$')
    for raw in path.read_text(errors='replace').splitlines():
        lm = level_marker.search(raw)
        if not lm:
            continue
        src = lm.group(1)
        emit = line_with_offset.match(raw)
        if emit:
            addr = int(emit.group(1), 16) + org_base
            for label in pending:
                consts[label] = addr
            pending = []
            inline = inline_label.match(src)
            if inline:
                consts[inline.group(1)] = addr
        else:
            only = label_only.match(src)
            if only and not only.group(1).startswith('%'):
                pending.append(only.group(1))
    return consts


def _eval(expr: str, consts: dict) -> int:
    tokens = re.split(r'(\W+)', expr)
    parts: list[str] = []
    for tok in tokens:
        if re.match(r'^[A-Za-z_]\w*$', tok):
            if tok not in consts:
                raise ValueError(f'unknown identifier: {tok}')
            parts.append(str(consts[tok]))
        else:
            parts.append(tok)
    return int(eval(''.join(parts), {'__builtins__': {}}, {}))


def read_core_sys(path: Path):
    data = path.read_bytes()
    resident_sectors = struct.unpack('<H', data[15:17])[0]
    phase_table_off = struct.unpack('<H', data[19:21])[0]
    phase_count = struct.unpack('<H', data[21:23])[0]
    phases: dict[str, tuple[int, int, int]] = {}
    for i in range(phase_count):
        entry = data[phase_table_off + i * 10:phase_table_off + (i + 1) * 10]
        pid = entry[:2].decode('ascii').rstrip('\x00')
        sector_off, sectors, load_addr = struct.unpack('<HHH', entry[2:8])
        phases[pid] = (sector_off, sectors, load_addr)
    return data, resident_sectors, phases


def extract_cleanup_table(data: bytes, cleanup_sector: int,
                          table_offset: int = 0x1c):
    """Read the cleanup phase's (addr, size) table, or return None.

    The table is a run of little-endian u16 (addr, size) pairs ending
    in (0, 0). Every range targets the 16 KiB low-RAM image, so a valid
    entry has 0 < size and addr + size <= TOTAL_BYTES.

    Callers locate the table by the phase id 'M'. That id was the
    cleanup phase through Build 9, but Build 10 reuses 'M' for the
    `$r/$w/$x` tool phase and ships no cleanup phase at all. Rather than
    trust the id, validate the bytes: if they don't decode to an
    in-range, terminated table, this isn't a cleanup phase — return None
    so the caller drops the cleanup stage instead of mis-rendering (or,
    as before, crashing on the missing terminator)."""
    base = cleanup_sector * 512 + table_offset
    ranges = []
    for i in range(64):
        addr, size = struct.unpack('<HH', data[base + i * 4:base + i * 4 + 4])
        if addr == 0 and size == 0:
            return ranges
        if size == 0 or addr + size > TOTAL_BYTES:
            return None
        ranges.append((addr, size))
    return None


def fill(cells, start, end, kind):
    for a in range(start, end):
        if 0 <= a < TOTAL_BYTES:
            cells[a] = kind


def stage_cold(ctx) -> list[str]:
    cells = ['free'] * TOTAL_BYTES
    fill(cells, 0, 0x0500, 'bios')
    return cells


def stage_nucleus(ctx) -> list[str]:
    """SEED.SYS resident has just been loaded. main.inc has zeroed
    low_runtime_state + high_crypto_scratch + critical_scratch and
    stamped boot drive + RAM top into the handoff block. No cold
    phase has run yet."""
    cells = stage_cold(ctx)
    c = ctx.consts
    fill(cells, c['core_load_addr'],
         c['core_load_addr'] + ctx.resident_sectors * 512, 'nucleus')
    fill(cells, c['handoff_addr'],
         c['handoff_addr'] + c['handoff_size_bytes'], 'handoff')
    fill(cells, STACK_START, TOTAL_BYTES, 'stack')
    return cells


def stage_hal(ctx) -> list[str]:
    """H (hardware_setup) + 2 (driver_load) + I (packet_io_init) have
    run. The handoff block now carries video mode, screen columns, NIC
    family/base/IRQ, MAC. The selected NIC driver is loaded into the
    active-driver slot. Persistent NIC TX/RX page tracking is initialised.
    UI cursor/colour-attribute slots are populated in low_phase_state."""
    cells = stage_nucleus(ctx)
    c = ctx.consts
    # Resident persistent runtime state, packed right up to the cold-phase
    # scratch (0 B free after it): NIC TX/RX page tracking now, plus
    # arp_target_mac + tcp seq/ack from the net stage. NOT the free band the
    # map used to imply between the handoff and low_scratch_start.
    fill(cells, c['low_runtime_state_start'], c['low_runtime_state_end'],
         'wire_state')
    fill(cells, c['low_scratch_start'], c['low_file_scratch_end'],
         'phase_local')
    return cells


def stage_net(ctx) -> list[str]:
    """D (dhcp_setup) + C (tcp_connect) have run.
    Handoff now also carries IP/router/DNS/subnet; low_persistent_state
    has arp_target_mac and tcp_target_ip/seq/ack. DHCP/DNS/ARP
    transient slots in low_phase_state are populated. low_scratch
    holds the last cold-phase image (C tcp_connect on the happy path).

    Cell-level visual is the same as HAL — the new state populates
    the same regions, just denser within them."""
    return stage_hal(ctx)


def stage_agent_prep(ctx) -> list[str]:
    """A + U + Q (if needed) + E + R have run. The agent path has
    consumed SEED/AGENTS.CFG + SEED/USER.CFG, asked the user for any missing
    values, resolved the provider's DNS name, and used seed_* to
    build the HTTP POST into api_request_plain (the first 461 B of
    pre-response scratch).

    The K LINK window is still on the floppy — its 6.6 KiB slot at
    0x1800..0x3200 is conspicuously empty. Same for SHA-256 K and
    low_static_constants: those bytes get filled by the L phase
    that runs as part of the next stage."""
    cells = stage_net(ctx)
    c = ctx.consts

    # api_request_plain only — 461 B at the bottom of pre-response
    # scratch. hmac_prepared and the dedicated tls_random/master/hash
    # slots are still zero at this point.
    api_plain_start = c['critical_scratch_start'] + c['tls_payload_buffer_len']
    fill(cells, api_plain_start, api_plain_start + c['api_request_plain_len'],
         'tls_state')

    seed_start = c['seed_agent_id']
    seed_end = seed_start + c['seed_value_total_len']
    fill(cells, seed_start, seed_end, 'agent_config')

    return cells


def stage_tls(ctx) -> list[str]:
    """L + K + TLS handshake + T have run on top of the agent-prep
    state. This is the densest moment in memory:
      - K LINK window loaded at 0x1800 (6.6 KiB of crypto + TLS + API).
      - SHA-256 K table at 0x0500..0x0600 (copied in by L).
      - low_static_constants at low_phase_state_end (PRF labels +
        ChaCha + Poly + SHA-256 IV — also copied in by L).
      - high_crypto_scratch carries the derived TLS write keys, IVs,
        record sequences, AEAD work slots, finished tags.
      - tls_rx_copy holds the encrypted HTTP response.
      - hmac_prepared inner/outer and the dedicated tls_server_random
        / master_secret / handshake_hash slots fill the rest of
        pre-response scratch.
      - seed_* sits at the top of critical_scratch, just under the
        stack guard floor; the ~681 B gap between pre-response and
        seed_* is what cleanup zeros into a single contiguous arena."""
    cells = stage_agent_prep(ctx)
    c = ctx.consts

    _, k_sectors, k_load_addr = ctx.phases['K']
    fill(cells, k_load_addr, k_load_addr + k_sectors * 512, 'k_window')

    fill(cells, c['low_static_constants_start'],
         c['low_static_constants_end'], 'crypto_const')
    fill(cells, c['low_sha256_k'],
         c['low_sha256_k'] + c['sha256_k_len'], 'crypto_const')

    fill(cells, c['high_crypto_scratch_start'],
         c['critical_scratch_start'], 'tls_state')

    rx_end = c['critical_scratch_start'] + c['tls_payload_buffer_len']
    fill(cells, c['critical_scratch_start'], rx_end, 'rx_buffer')

    pre_response_end = rx_end + 637
    fill(cells, rx_end, pre_response_end, 'tls_state')

    # Build 9 context pool above critical scratch - reconnect-safe, so it is
    # reserved the moment the agent path is up: the caches are already live,
    # the window fills as the chat runs, the arena stays reserved. Painting it
    # here (not just in the chat-loop stage) keeps the densest moment honest -
    # there is no free band waiting below the stack.
    fill(cells, c['critical_scratch_end'], c['chat_pool_start'], 'agent_config')
    fill(cells, c['chat_arena_start'], c['chat_context_start'], 'arena')
    fill(cells, c['chat_context_start'], c['chat_context_end'], 'context')
    return cells


def stage_dpi(ctx) -> list[str]:
    """Chat loop after the first response. The K window, the derived session keys,
    and the receive buffer (now holding the streamed response) stay resident and
    serve every turn. The handshake-only scratch (hmac_prepared, tls_server_random,
    master_secret, handshake_hash) is dead once the session keys exist, so the
    steady-state chat footprint is a little lighter than the handshake peak."""
    cells = stage_tls(ctx)
    c = ctx.consts
    rx_end = c['critical_scratch_start'] + c['tls_payload_buffer_len']
    # The handshake scratch (hmac_prepared, tls_server_random, master_secret,
    # handshake_hash) holds no live data once the session keys exist - but it is
    # NOT free: a reconnect re-runs the handshake and reuses it, and it sits
    # below critical scratch (the reconnect-safe line), so it can never become
    # permanent pool. Paint it reserved, not free, so the map doesn't imply the
    # pool is leaving usable space on the table.
    fill(cells, rx_end, rx_end + 637, 'reconnect_scratch')
    # The context pool (a / m / +) is painted in stage_tls - it is reserved
    # from the first response onward, not new to the chat loop. What changes
    # here is only the handshake scratch: it goes dormant/reserved (above).
    return cells


def stage_cleanup(ctx) -> list[str]:
    if not ctx.cleanup_ranges:
        raise RuntimeError(
            'cleanup stage requires a SEED.SYS with phase M cleanup table'
        )
    cells = stage_tls(ctx)
    for addr, size in ctx.cleanup_ranges:
        fill(cells, addr, addr + size, 'cleaned')

    # Resident nucleus follows the cleanup phase with a final wipe of
    # low_scratch_start..low_file_scratch_end — the cold-phase loading
    # area, which cleanup itself can't zero because it executes from
    # there. (Phase 4.5 Step F moved fs_lba into resident BSS, so
    # main.inc uses low_file_scratch_end as the upper bound instead.)
    fill(cells, ctx.consts['low_scratch_start'],
         ctx.consts['low_file_scratch_end'], 'cleaned')

    # The 128 B "stack guard" at the top of the 16 KiB target is
    # wiped by the resident immediately before halt — Seed performs
    # no more stack ops at that point, so the bytes become arena.
    stack_top = ctx.consts['basic_sidecar_stack_top_16k']
    guard_len = ctx.consts['basic_sidecar_stack_guard_len_16k']
    fill(cells, stack_top - guard_len, stack_top, 'cleaned')

    # Within low_static_constants, cleanup zeros PRF labels + sha256
    # IV; the retained ChaCha20 + Poly1305 constants sit in the gap
    # between those cleanup ranges. Looking inside the bounds avoids
    # confusing the tiny UI-cursor gaps in low_phase_state above.
    static_start = ctx.consts['low_static_constants_start']
    static_end = ctx.consts['low_static_constants_end']
    inside = sorted(
        (a, s) for a, s in ctx.cleanup_ranges
        if static_start <= a < static_end
    )
    for i in range(len(inside) - 1):
        end_i = inside[i][0] + inside[i][1]
        addr_next = inside[i + 1][0]
        if addr_next > end_i:
            fill(cells, end_i, addr_next, 'crypto_const')
            break

    return cells


STAGE_BUILDERS = {
    'cold':       stage_cold,
    'nucleus':    stage_nucleus,
    'hal':        stage_hal,
    'net':        stage_net,
    'agent-prep': stage_agent_prep,
    'tls':        stage_tls,
    'dpi':        stage_dpi,
    'cleanup':    stage_cleanup,
}

def _resident_range(ctx: Ctx) -> str:
    start = ctx.consts['core_load_addr']
    end = start + ctx.resident_sectors * 512
    return f'0x{start:04X}..0x{end:04X}'


def _k_window_range(ctx: Ctx) -> str:
    _, k_sectors, k_load = ctx.phases['K']
    return f'0x{k_load:04X}..0x{k_load + k_sectors * 512:04X}'


def _k_window_kib(ctx: Ctx) -> str:
    _, k_sectors, _ = ctx.phases['K']
    return f'{k_sectors * 512 / 1024:.1f}'


STAGE_FOOTER_BUILDERS = {
    'cold': lambda ctx: (
        "Power-on. BIOS owns 0x0000..0x0500 (interrupt vectors plus the\n"
        "BIOS data area). Everything else is RAM Seed will claim in\n"
        "stages — currently all free."
    ),
    'nucleus': lambda ctx: (
        f"SEED.SYS resident nucleus is at {_resident_range(ctx)}. The phase\n"
        "loader, NIC TX/RX, TCP send/receive, and UI primitives live\n"
        "here. main.inc has cleared the runtime scratch and stamped\n"
        "boot_drive + ram_top into the handoff (the tiny 'h' cell)."
    ),
    'hal': lambda ctx: (
        "H (hardware_setup) + 2 (driver_load) + I (packet_io_init) have\n"
        "run. Handoff now carries video mode, NIC family/base/IRQ, MAC;\n"
        "the selected NIC driver is resident in the active-driver slot;\n"
        "NIC TX/RX page tracking lives in low_runtime_state; UI cursor/\n"
        "colour attrs sit in low_phase_state."
    ),
    'net': lambda ctx: (
        "D (dhcp_setup) + C (tcp_connect) have\n"
        "run. Handoff also carries IP/router/DNS/subnet; the persistent\n"
        "block has arp_target_mac and tcp_target_ip/seq/ack. Visual is\n"
        "identical to the HAL stage — the new bytes populate the same\n"
        "cells, just more densely inside them."
    ),
    'agent-prep': lambda ctx: (
        "A + U + Q + E + R have run. seed_* loaded from SEED/AGENTS.CFG /\n"
        "SEED/USER.CFG, the HTTP POST built into api_request_plain. The K\n"
        f"LINK window is still on the floppy — its {_k_window_kib(ctx)} KiB slot at\n"
        f"{_k_window_range(ctx)} stands empty, the largest visible free band."
    ),
    'tls': lambda ctx: (
        "Densest moment. K LINK window loaded; persistent TLS state\n"
        "derived; receive buffer holding the encrypted response; the rest\n"
        "of pre-response scratch (hmac_prepared + tls_server_random /\n"
        "master_secret / handshake_hash) filled by the handshake. The\n"
        "context pool above critical scratch (caches a, arena +, window m)\n"
        "is already reserved. Nothing is free here - 16 KiB at full pack."
    ),
    'dpi': lambda ctx: (
        "Chat loop after the first response. The K window, session keys, and\n"
        "receive buffer (the streamed response) stay resident and serve every\n"
        "turn. The ':' band is the TLS handshake scratch (HMAC pads, server\n"
        "random, master secret, transcript hash): dormant once the session keys\n"
        "exist, but reserved - a reconnect re-runs the handshake and reuses it,\n"
        "and it sits below critical scratch (the reconnect-safe line), so it can\n"
        "never be permanent pool. The context pool therefore lives ABOVE\n"
        "that line - reconnect-safe caches, user/agent arena (+), and\n"
        "conversation window (m) - so it survives an idle/walk-away reconnect. In\n"
        "the current Build 12 native-tool layout the remaining 16 KiB pool is\n"
        "192 B, split 50/50 by hardware_setup into a 96 B arena and a 96 B\n"
        "window at the far end. The 32 KiB direct tier spends its extra low RAM on the\n"
        "normal-turn loop cache and tools-schema cache, so its seg-0\n"
        "arena/window are 224 B each; larger far-memory tiers keep the 50/50\n"
        "policy until the context window reaches the 1 MiB cap."
    ),
    'cleanup': None,  # generated dynamically below
}


def render(cells: list) -> str:
    indent = '  '
    addr_w = 8
    grid_w = ROW_CELLS
    ruler_in_border = '───────1───────2───────3───────4'

    top = indent + '┌' + '─' * addr_w + '┬' + ruler_in_border + '┐ KiB'
    bottom = indent + '└' + '─' * addr_w + '┴' + '─' * grid_w + '┘'

    lines = [top]
    for row in range(ROWS):
        row_chars = []
        for col in range(ROW_CELLS):
            base = row * ROW_BYTES + col * CELL_BYTES
            kinds = set(cells[base:base + CELL_BYTES])
            for kind in PRIORITY:
                if kind in kinds:
                    row_chars.append(GLYPH[kind])
                    break
            else:
                row_chars.append('?')
        addr_label = f' 0x{row * ROW_BYTES:04X} '
        lines.append(indent + '│' + addr_label + '│' + ''.join(row_chars) + '│')
    lines.append(bottom)
    return '\n'.join(lines)


def generate_block(stage: str, ctx: Ctx) -> str:
    cells = STAGE_BUILDERS[stage](ctx)
    body = render(cells)
    builder = STAGE_FOOTER_BUILDERS.get(stage)
    footer = builder(ctx) if builder else None
    if stage == 'cleanup':
        table_total = sum(size for _, size in ctx.cleanup_ranges)
        cold_wipe_size = (ctx.consts['low_file_scratch_end']
                          - ctx.consts['low_scratch_start'])
        stack_wipe_size = ctx.consts['basic_sidecar_stack_guard_len_16k']
        biggest = max(max(size for _, size in ctx.cleanup_ranges),
                      cold_wipe_size, stack_wipe_size)
        total = table_total + cold_wipe_size + stack_wipe_size
        footer = (
            f"Cleanup zeroed {total} B — "
            f"{table_total} B across {len(ctx.cleanup_ranges)} "
            f"cleanup-table ranges, plus a {cold_wipe_size}-byte post-cleanup "
            f"wipe of the cold-phase loading area, plus a {stack_wipe_size}-byte "
            f"final wipe of the former stack-guard region. "
            f"Largest single freed island: {biggest} B."
        )
    if footer:
        body = body + '\n\n' + footer
    return '```text\n' + body + '\n```'


def update_doc(doc: Path, blocks: dict) -> None:
    text = doc.read_text()
    missing = []
    for stage, block in blocks.items():
        begin = MARKER_BEGIN.format(stage=stage)
        end = MARKER_END.format(stage=stage)
        pattern = re.compile(
            re.escape(begin) + r'.*?' + re.escape(end),
            re.DOTALL,
        )
        if not pattern.search(text):
            missing.append(stage)
            continue
        text = pattern.sub(f'{begin}\n{block}\n{end}', text)
    if missing:
        raise SystemExit(
            f'missing marker pair(s) in {doc}: '
            + ', '.join(f'stage-{s}' for s in missing)
        )
    doc.write_text(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--core-sys', type=Path,
                        default=ROOT / 'build/ibm_pc_5150/SEED.SYS')
    parser.add_argument('--layout', type=Path,
                        default=ROOT / 'targets/ibm_pc_5150/boot/core/layout.inc')
    parser.add_argument('--data', type=Path,
                        default=ROOT / 'targets/ibm_pc_5150/boot/core/data.inc')
    parser.add_argument('--listing', type=Path,
                        default=ROOT / 'build/ibm_pc_5150/SEED.SYS.lst',
                        help='NASM listing file (produced via `make`). Used to '
                             'resolve label addresses that aren\'t plain equates.')
    parser.add_argument('--stage', choices=STAGES, action='append',
                        help='render only these stages (repeatable; default: '
                             'all stages supported by the current SEED.SYS)')
    parser.add_argument('--update', type=Path,
                        help='patch generated blocks into this markdown file')
    args = parser.parse_args()

    if not args.core_sys.exists():
        sys.exit(f'missing {args.core_sys}; run `make` first')

    consts = parse_equates(args.layout)
    consts = parse_equates(args.data, consts)
    # Listing-extracted label addresses come last so they fill in
    # the labels (relocated_tls_keys, relocated_seed_agent_id, etc.)
    # that the `equ` chain above references but can't resolve. Use
    # core_load_addr (from layout.inc) as the org base so labels
    # resolve to runtime addresses regardless of the load address.
    consts.update(parse_listing(args.listing, consts['core_load_addr']))
    # Re-run BOTH layout + data equ passes so chains that depended on
    # those labels (handoff_addr -> relocated_handoff in layout.inc,
    # seed_agent_id -> relocated_seed_agent_id in data.inc, etc.)
    # all resolve.
    consts = parse_equates(args.layout, consts)
    consts = parse_equates(args.data, consts)
    data, resident_sectors, phases = read_core_sys(args.core_sys)
    cleanup_ranges = []
    if 'M' in phases:
        # 'M' is the cleanup phase only on builds that ship one; Build 10
        # reuses the id for the tool phase. extract_cleanup_table returns
        # None when the sector isn't a valid cleanup table, so a reused id
        # simply leaves cleanup_ranges empty (no cleanup stage).
        cleanup_sector = phases['M'][0]
        cleanup_ranges = extract_cleanup_table(data, cleanup_sector) or []
    ctx = Ctx(consts=consts, phases=phases,
              resident_sectors=resident_sectors,
              cleanup_ranges=cleanup_ranges)

    stages = args.stage or (STAGES if cleanup_ranges else DEFAULT_STAGES)
    if 'cleanup' in stages and not cleanup_ranges:
        sys.exit('cleanup stage unavailable: current SEED.SYS has no M phase')
    blocks = {s: generate_block(s, ctx) for s in stages}

    if args.update:
        update_doc(args.update, blocks)
    else:
        for stage in stages:
            print(f'# stage: {stage}\n{blocks[stage]}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
