#!/usr/bin/env python3
"""Static, auditable size ledger for the TLS 1.3 replacement spike.

This script never edits product sources.  It assembles the current runtime and
the isolated spike benches into a temporary directory, reads NASM label
addresses, and reports:

* the exact current K-window include breakdown;
* a conservative, non-overlapping set of code spans that are unambiguously
  TLS-1.2-only in a replacement build;
* the exact implemented HKDF, PSS-decoder, and encrypted-flight benchmark
  glue sizes (kept separate from their harnesses);
* the remaining byte budgets for 15- and 14-sector K;
* current secure-module composition and an assembled generic-RSA-recover
  candidate, without changing ``p256_module.asm``.

The replacement K result is intentionally a ledger, not a fake link result.
ClientHello/ServerHello and encrypted-handshake parsing are not implemented in
the product, so they remain an explicit unknown instead of being assigned an
optimistic estimate.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BOOT = ROOT / "targets" / "ibm_pc_5150" / "boot"
BUILD = ROOT / "build" / "ibm_pc_5150"
SPIKE = ROOT / "tools" / "crypto-bench" / "tls13-spike"

SECTOR = 512
K15 = 15 * SECTOR
K14 = 14 * SECTOR
MODULE24 = 24 * SECTOR


@dataclass(frozen=True)
class Span:
    name: str
    start: str
    end: str
    note: str


# These spans are deliberately conservative.  They exclude generic transcript,
# buffering, sequence-number, nonce, and streaming primitives even where a
# production TLS 1.3 implementation is likely to reshape them.
TLS12_ONLY_K_SPANS = (
    Span(
        "fixed TLS 1.2 Finished Poly1305 wrapper",
        "poly1305_mac_finished",
        "poly1305_load_key",
        "fixed 13-byte AAD and fixed Finished ciphertext",
    ),
    Span(
        "TLS 1.2 top-level handshake",
        "tls_probe_server",
        "tls_prepare_3c501_receive",
        "ServerHello/Certificate/SKE/SHD/CKE/CCS/Finished orchestration",
    ),
    Span(
        "TLS 1.2 ServerHello wait/parser",
        "tls_wait_for_server_hello",
        "tls_save_buffered_server_payload",
        "TLS 1.3 ServerHello and key transition need a new parser",
    ),
    Span(
        "TLS 1.2 Certificate wait",
        "tls_wait_for_server_certificate",
        "tls_load_server_payload",
        "TLS 1.3 certificate arrives inside protected TLSInnerPlaintext",
    ),
    Span(
        "TLS 1.2 Certificate framing parser",
        "tls_parse_server_certificate",
        "tls_wait_for_server_key_exchange_or_done",
        "TLS 1.3 Certificate carries request-context and per-entry extensions",
    ),
    Span(
        "TLS 1.2 SKE/SHD wait",
        "tls_wait_for_server_key_exchange_or_done",
        "tls_prepare_master_secret",
        "TLS 1.3 has EncryptedExtensions/Certificate/CertificateVerify/Finished",
    ),
    Span(
        "TLS 1.2 PRF/master/key-block",
        "tls_prepare_master_secret",
        "tls_prepare_client_key_exchange_transcript",
        "replaced by TLS 1.3 HKDF traffic-secret epochs",
    ),
    Span(
        "TLS 1.2 client second-flight/retry path",
        "tls_prepare_client_key_exchange_transcript",
        "tls_send_application_data_current_seq",
        "CKE + CCS + Finished layout and timing are TLS 1.2-only",
    ),
    Span(
        "TLS 1.2 application-record builder",
        "tls_build_application_data_record",
        "tls_receive_application_data",
        "TLS 1.3 outer type/AAD/inner content-type differ",
    ),
    Span(
        "TLS 1.2 application AAD builders",
        "tls_build_client_app_aad",
        "tls_parse_server_change_cipher_spec",
        "13-byte AAD is replaced by the 5-byte TLSCiphertext header",
    ),
    Span(
        "TLS 1.2 CCS and Finished processing",
        "tls_parse_server_change_cipher_spec",
        "tls_build_client_nonce",
        "TLS 1.3 compatibility CCS is ignored and Finished is transcript-HMAC",
    ),
    Span(
        "TLS 1.2 Finished AAD/cipher/final-flight builder",
        "tls_build_finished_aad",
        "tls_increment_client_record_seq",
        "fixed TLS 1.2 Finished records and CCS construction",
    ),
    Span(
        "TLS 1.2 SKE/SHD/CKE parser-builder tail",
        "tls_parse_server_key_exchange",
        "tls_write_be16",
        "replaced by ServerHello key_share and TLS 1.3 client Finished",
    ),
)


GENERIC_RSA_BLOCK = r"""
; Spike-only candidate ABI.  Input SI is a 256-byte big-endian RSA signature.
; The module performs only RSA-2048/e=65537 recovery and returns SI pointing to
; the recovered big-endian EM in rsa_sig.  That module-owned pointer is valid
; only until the overlay is unloaded.  TLS 1.3 PSS decoding stays in K, while
; the off-race WR1 path uses the strict PKCS#1 validator below.
p256_ep_verify_ske_sig_impl:
    cmp byte [rsa_key_ready], 0
    jne .have_key
    stc
    ret
.have_key:
    mov di, rsa_sig
    call rsa_from_be256
    call rsa_verify
    mov si, rsa_result
    mov di, rsa_sig
    call rsa_to_be256
    mov si, rsa_sig
    clc
    ret

rsa_from_be256:
    push ax
    push bx
    push cx
    push si
    push di
    mov bx, si
    add bx, 255
    mov cx, 128
.next:
    mov al, [bx]
    mov ah, [bx - 1]
    mov [di], ax
    add di, 2
    sub bx, 2
    loop .next
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

rsa_to_be256:
    push ax
    push bx
    push cx
    push si
    push di
    mov bx, si
    add bx, 254
    mov cx, 128
.next:
    mov ax, [bx]
    mov [di], ah
    mov [di + 1], al
    add di, 2
    sub bx, 2
    loop .next
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; SI = recovered 256-byte EM, DI = SHA-256(TBS).
rsa_validate_pkcs1_sha256:
    push di
    cmp byte [si], 0
    jne .prefix_failed
    cmp byte [si + 1], 1
    jne .prefix_failed
    add si, 2
    mov cx, 202
.ff:
    cmp byte [si], 0xff
    jne .prefix_failed
    inc si
    loop .ff
    cmp byte [si], 0
    jne .prefix_failed
    inc si
    mov di, rsa_sha256_digestinfo
    mov cx, 19
    repe cmpsb
    jne .prefix_failed
    pop di
    mov cx, 32
    repe cmpsb
    jne .hash_failed
    clc
    ret
.prefix_failed:
    pop di
.hash_failed:
    stc
    ret

rsa_sha256_digestinfo:
    db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01
    db 0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20

"""


GENERIC_CHAIN_BLOCK = r"""
p256_ep_chain_verify_sig_impl:
    push di
    push si
    call x509_load_wr1
    pop si
    call p256_ep_verify_ske_sig_impl
    jc .recover_reject
    pop di
    call rsa_validate_pkcs1_sha256
    jc .cv_reject
    call ntp_validity_ok
    jc .cv_reject
    clc
    ret
.recover_reject:
    pop di
.cv_reject:
    stc
    ret

"""


def run(command: list[str], *, cwd: Path = ROOT) -> None:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if completed.returncode:
        detail = completed.stderr or completed.stdout
        raise RuntimeError(f"{' '.join(command)} failed:\n{detail}")


def assemble(
    source: Path,
    output: Path,
    listing: Path,
    *,
    extra_include_dirs: tuple[Path, ...] = (),
) -> None:
    include_args = [f"-I{BOOT}/"]
    include_args.extend(f"-I{path}/" for path in extra_include_dirs)
    include_args.extend(
        (f"-I{BUILD}/", f"-I{ROOT / 'tools' / 'crypto-bench'}/")
    )
    run(
        [
            "nasm",
            "-DLOADER_SECTORS=4",
            *include_args,
            "-f",
            "bin",
            "-l",
            str(listing),
            "-o",
            str(output),
            str(source),
        ]
    )


LABEL_RE = re.compile(r"^\s*\d+\s+(?:<\d+>\s+)?([A-Za-z_][A-Za-z0-9_]*):")
INCLUDE_LABEL_RE = re.compile(r"<\d+>\s+([A-Za-z_][A-Za-z0-9_]*):")
INCLUDE_DECL_RE = re.compile(
    r"<\d+>\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:db|dw|dd|dq|times)\b",
    re.IGNORECASE,
)
ADDRESS_RE = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
INCLUDE_ADDRESS_RE = re.compile(
    r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+\S+\s+<\d+>\s+"
)


def listing_labels(path: Path, image_size: int) -> dict[str, int]:
    """Map global labels to offsets by binding label-only lines to next output."""
    labels: dict[str, int] = {}
    pending: list[str] = []
    for line in path.read_text().splitlines():
        label_match = (
            LABEL_RE.match(line)
            or INCLUDE_LABEL_RE.search(line)
            or INCLUDE_DECL_RE.search(line)
        )
        if label_match:
            pending.append(label_match.group(1))
        address_match = ADDRESS_RE.match(line) or INCLUDE_ADDRESS_RE.match(line)
        if address_match:
            address = int(address_match.group(1), 16)
            for label in pending:
                labels[label] = address
            pending.clear()
    # End labels followed only by assertions have no emitted listing line.
    for label in pending:
        labels[label] = image_size
    return labels


def need(labels: dict[str, int], label: str) -> int:
    try:
        return labels[label]
    except KeyError as exc:
        raise RuntimeError(f"required NASM label missing: {label}") from exc


def size(labels: dict[str, int], start: str, end: str) -> int:
    result = need(labels, end) - need(labels, start)
    if result < 0:
        raise RuntimeError(f"negative span {start}..{end}")
    return result


def transform_generic_rsa_module(source: str) -> str:
    hot_start = source.index("p256_ep_verify_ske_sig_impl:")
    hot_end = source.index("; ---- auto-recertify entry points", hot_start)
    source = source[:hot_start] + GENERIC_RSA_BLOCK + source[hot_end:]

    chain_start = source.index("p256_ep_chain_verify_sig_impl:")
    chain_end = source.index("; Task #7 cert-validity gate", chain_start)
    return source[:chain_start] + GENERIC_CHAIN_BLOCK + source[chain_end:]


def report() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-size-") as tmp_name:
        tmp = Path(tmp_name)

        p256_bin = tmp / "p256_module.bin"
        p256_lst = tmp / "p256_module.lst"
        assemble(BOOT / "core" / "p256_module.asm", p256_bin, p256_lst)
        p256_labels = listing_labels(p256_lst, p256_bin.stat().st_size)

        # Assemble core only after producing the exact module it incbins, and
        # search the temp directory before build/.  This prevents a stale or
        # concurrently replaced build/p256_module.bin from affecting the
        # supposedly static report.
        core_bin = tmp / "SEED.SYS"
        core_lst = tmp / "SEED.SYS.lst"
        assemble(
            BOOT / "core.asm",
            core_bin,
            core_lst,
            extra_include_dirs=(tmp,),
        )
        core_labels = listing_labels(core_lst, core_bin.stat().st_size)
        embedded_module = core_bin.read_bytes()[
            need(core_labels, "core_p256_module_start") :
            need(core_labels, "core_p256_module_end")
        ]
        if embedded_module != p256_bin.read_bytes():
            raise RuntimeError(
                "SEED.SYS did not embed the temporary current p256 module"
            )

        candidate_source = tmp / "p256_module_generic_rsa_probe.asm"
        candidate_source.write_text(
            transform_generic_rsa_module(
                (BOOT / "core" / "p256_module.asm").read_text()
            )
        )
        candidate_bin = tmp / "p256_module_generic_rsa_probe.bin"
        candidate_lst = tmp / "p256_module_generic_rsa_probe.lst"
        assemble(candidate_source, candidate_bin, candidate_lst)
        candidate_labels = listing_labels(
            candidate_lst, candidate_bin.stat().st_size
        )

        hkdf_bin = tmp / "hkdf_bench.bin"
        hkdf_lst = tmp / "hkdf_bench.lst"
        assemble(SPIKE / "hkdf_bench.asm", hkdf_bin, hkdf_lst)
        hkdf_labels = listing_labels(hkdf_lst, hkdf_bin.stat().st_size)

        pss_bin = tmp / "pss_decode_bench.bin"
        pss_lst = tmp / "pss_decode_bench.lst"
        assemble(SPIKE / "pss_decode_bench.asm", pss_bin, pss_lst)
        pss_labels = listing_labels(pss_lst, pss_bin.stat().st_size)

        flight_bin = tmp / "flight_bench.bin"
        flight_lst = tmp / "flight_bench.lst"
        assemble(SPIKE / "flight_bench.asm", flight_bin, flight_lst)
        flight_labels = listing_labels(flight_lst, flight_bin.stat().st_size)

        k_breakdown = (
            ("shared SHA-256/HMAC", "core_link_window_start", "chacha20_block"),
            ("shared ChaCha20", "chacha20_block", "poly1305_mac_finished"),
            ("Poly1305 including TLS 1.2 fixed wrapper", "poly1305_mac_finished", "tls_fail_error"),
            ("TLS 1.2/profile logic", "tls_fail_error", "agent_api_exchange"),
            ("agent API exchange glue", "agent_api_exchange", "core_link_window_end"),
        )
        k_items = [
            {
                "name": name,
                "start": start,
                "end": end,
                "bytes": size(core_labels, start, end),
            }
            for name, start, end in k_breakdown
        ]
        k_current = size(
            core_labels, "core_link_window_start", "core_link_window_end"
        )
        if sum(int(item["bytes"]) for item in k_items) != k_current:
            raise RuntimeError("K include breakdown does not sum to K")

        removable_items = [
            {
                "name": span.name,
                "start": span.start,
                "end": span.end,
                "bytes": size(core_labels, span.start, span.end),
                "note": span.note,
            }
            for span in TLS12_ONLY_K_SPANS
        ]
        intervals = sorted(
            (
                need(core_labels, str(item["start"])),
                need(core_labels, str(item["end"])),
                str(item["name"]),
            )
            for item in removable_items
        )
        for previous, current in zip(intervals, intervals[1:]):
            if previous[1] > current[0]:
                raise RuntimeError(
                    "TLS 1.2 deletion spans overlap: "
                    f"{previous[2]} and {current[2]}"
                )
        removable = sum(int(item["bytes"]) for item in removable_items)

        hkdf_bytes = size(
            hkdf_labels, "tls13_hkdf_code_start", "tls13_hkdf_code_end"
        )
        pss_bytes = size(
            pss_labels,
            "pss_verify_sha256_2048_salt32",
            "sha256_init",
        )
        flight_glue = size(flight_labels, "flight_process", "flight_check")

        conservative_subtotal = k_current - removable + hkdf_bytes + pss_bytes
        # Flight glue is deliberately separate: it contains benchmark counters,
        # deterministic RX copying, and fixed geometry.  Counting it wholesale
        # gives a conservative implemented-reference bound, not a link forecast.
        subtotal_with_flight_reference = conservative_subtotal + flight_glue

        module_sections = (
            ("ABI/wrappers/orchestration", "p256_module_entry", "p256_from_be32"),
            (
                "P-256 implementation include (code + internal state)",
                "p256_from_be32",
                "p256_prime",
            ),
            ("P-256 session/constants include", "p256_prime", "rsa_verify"),
            ("RSA exponentiation code", "rsa_verify", "rsa_key_ready"),
            ("RSA workspace", "rsa_key_ready", "x509_parse_leaf"),
            ("strict X.509 parser", "x509_parse_leaf", "rsa_adopt"),
            ("RSA key-adoption code", "rsa_adopt", "wr1_n"),
            ("WR1 modulus", "wr1_n", "capture_leaf_reset"),
            ("leaf-capture code/state", "capture_leaf_reset", "p256_module_image_end"),
        )
        module_items = [
            {
                "name": name,
                "start": start,
                "end": end,
                "bytes": size(p256_labels, start, end),
            }
            for name, start, end in module_sections
        ]
        module_current = p256_bin.stat().st_size
        if sum(int(item["bytes"]) for item in module_items) != module_current:
            raise RuntimeError("secure-module breakdown does not sum to image")

        old_hot_span = size(
            p256_labels, "p256_ep_verify_ske_sig_impl", "p256_ep_parse_leaf_impl"
        )
        candidate_hot_span = size(
            candidate_labels,
            "p256_ep_verify_ske_sig_impl",
            "p256_ep_parse_leaf_impl",
        )
        old_chain_span = size(
            p256_labels, "p256_ep_chain_verify_sig_impl", "ntp_validity_ok"
        )
        candidate_chain_span = size(
            candidate_labels,
            "p256_ep_chain_verify_sig_impl",
            "ntp_validity_ok",
        )
        module_candidate = candidate_bin.stat().st_size

        cold_client_hello = size(
            core_labels,
            "core_tls_client_hello_phase_start",
            "core_tls_client_hello_phase_end",
        )
        tls12_cold_labels = size(
            core_labels,
            "tls_label_master_secret_constant",
            "chacha_constants_constant",
        )
        tls12_client_hello_literals = size(
            core_labels,
            "tls_client_hello_after_random",
            "tls_low_constants_constant",
        )

        result: dict[str, object] = {
            "k": {
                "current_bytes": k_current,
                "current_sectors": (k_current + SECTOR - 1) // SECTOR,
                "k15_limit": K15,
                "k14_limit": K14,
                "k15_slack_current": K15 - k_current,
                "k14_reduction_needed_current": k_current - K14,
                "breakdown": k_items,
                "tls12_only_removable_bytes": removable,
                "tls12_only_spans": removable_items,
                "implemented_hkdf_bytes": hkdf_bytes,
                "implemented_pss_decoder_bytes": pss_bytes,
                "pss_transient_scratch_bytes": 74,
                "pss_recovered_em_bytes": 256,
                "certificate_verify_signature_staging_bytes": 256,
                "certificate_verify_hash_bytes": 32,
                "pss_recovered_em_storage": "module-owned rsa_sig workspace",
                "implemented_flight_reference_glue_bytes": flight_glue,
                "conservative_subtotal_before_unknown_glue": conservative_subtotal,
                "conservative_subtotal_plus_whole_flight_reference": subtotal_with_flight_reference,
                "unknown_budget_for_k15_before_flight_reference": K15
                - conservative_subtotal,
                "unknown_budget_for_k14_before_flight_reference": K14
                - conservative_subtotal,
                "unknown_budget_for_k15_after_whole_flight_reference": K15
                - subtotal_with_flight_reference,
                "unknown_budget_for_k14_after_whole_flight_reference": K14
                - subtotal_with_flight_reference,
                "unknowns": [
                    "TLS 1.3 ClientHello builder and cold-phase literals",
                    "ServerHello/key_share parser and handshake-key transition",
                    "TLSInnerPlaintext encrypted-handshake message parser",
                    "Certificate framing/extensions and CertificateVerify extraction",
                    "server/client Finished transition and application-record send/receive glue",
                    "final liveness-driven key/state overlays and reconnect state",
                ],
            },
            "cold_client_hello_phase": {
                "current_bytes": cold_client_hello,
                "current_sectors": (cold_client_hello + SECTOR - 1) // SECTOR,
                "tls12_prf_label_bytes": tls12_cold_labels,
                "tls12_client_hello_literal_bytes": tls12_client_hello_literals,
                "note": "cold bytes affect SEED.SYS/media, not pinned K or arena",
            },
            "secure_module": {
                "current_bytes": module_current,
                "limit_bytes": MODULE24,
                "current_slack": MODULE24 - module_current,
                "breakdown": module_items,
                "old_tls12_hot_verify_span_bytes": old_hot_span,
                "generic_rsa_candidate_span_bytes": candidate_hot_span,
                "old_chain_wrapper_bytes": old_chain_span,
                "generic_rsa_chain_wrapper_bytes": candidate_chain_span,
                "generic_rsa_candidate_bytes": module_candidate,
                "generic_rsa_candidate_slack": MODULE24 - module_candidate,
                "generic_rsa_candidate_extent_slack": (
                    (module_candidate + SECTOR - 1) // SECTOR
                )
                * SECTOR
                - module_candidate,
                "generic_rsa_candidate_reduction": module_current
                - module_candidate,
                "generic_rsa_candidate_sectors": (
                    module_candidate + SECTOR - 1
                )
                // SECTOR,
                "pss_location": "resident K; not duplicated in secure module",
                "candidate_contract": (
                    "RSA-2048 recovery returns SI -> module-owned 256-byte EM in rsa_sig; "
                    "K performs PSS, off-race WR1 path performs strict PKCS#1 validation"
                ),
            },
        }

        # Hard static invariants: fail loudly if measurements drift.
        assert k_current == 7680
        assert hkdf_bytes == 849
        assert pss_bytes == 272
        assert flight_glue == 438
        assert module_current == 12066
        assert module_candidate <= MODULE24
        span_reduction = (old_hot_span - candidate_hot_span) - (
            candidate_chain_span - old_chain_span
        )
        alignment_padding_reduction = (
            module_current - module_candidate - span_reduction
        )
        if alignment_padding_reduction not in (-1, 0, 1):
            raise RuntimeError(
                "generic RSA module delta is not fully explained by the "
                f"measured spans and word alignment: spans={span_reduction}, "
                f"image={module_current - module_candidate}, "
                f"alignment={alignment_padding_reduction}"
            )
        module_result = result["secure_module"]
        assert isinstance(module_result, dict)
        module_result["generic_rsa_alignment_padding_reduction"] = (
            alignment_padding_reduction
        )
        return result


def print_report(result: dict[str, object]) -> None:
    k = result["k"]
    assert isinstance(k, dict)
    module = result["secure_module"]
    assert isinstance(module, dict)
    cold = result["cold_client_hello_phase"]
    assert isinstance(cold, dict)

    print("TLS 1.3 replacement size ledger: PASS")
    print()
    print(
        f"K current: {k['current_bytes']} B / {k['current_sectors']} sectors; "
        f"K=15 slack {k['k15_slack_current']} B; "
        f"K=14 needs {k['k14_reduction_needed_current']} B"
    )
    for item in k["breakdown"]:
        print(f"  {item['bytes']:4d} B  {item['name']}")
    print()
    print(f"Unambiguously TLS-1.2-only K code: {k['tls12_only_removable_bytes']} B")
    for item in k["tls12_only_spans"]:
        print(
            f"  {item['bytes']:4d} B  {item['start']}..{item['end']} "
            f"({item['name']})"
        )
    print()
    print(
        "Implemented replacement pieces: "
        f"HKDF {k['implemented_hkdf_bytes']} B; "
        f"PSS {k['implemented_pss_decoder_bytes']} B "
        f"(+{k['pss_transient_scratch_bytes']} B scratch, "
        f"+{k['certificate_verify_signature_staging_bytes']} B signature staging, "
        f"+{k['certificate_verify_hash_bytes']} B hash; recovered EM aliases "
        f"{k['pss_recovered_em_storage']}); "
        f"flight reference glue {k['implemented_flight_reference_glue_bytes']} B"
    )
    print(
        "Conservative carry-forward subtotal before unimplemented parser/transition glue: "
        f"{k['conservative_subtotal_before_unknown_glue']} B; "
        f"unknown budget K=15 {k['unknown_budget_for_k15_before_flight_reference']} B, "
        f"K=14 {k['unknown_budget_for_k14_before_flight_reference']} B"
    )
    print(
        "If the whole benchmark flight glue is charged as a conservative reference: "
        f"{k['conservative_subtotal_plus_whole_flight_reference']} B; "
        f"unknown budget K=15 {k['unknown_budget_for_k15_after_whole_flight_reference']} B, "
        f"K=14 {k['unknown_budget_for_k14_after_whole_flight_reference']} B"
    )
    print("Still unknown:")
    for unknown in k["unknowns"]:
        print(f"  - {unknown}")
    print()
    print(
        f"Cold L phase: {cold['current_bytes']} B / {cold['current_sectors']} sectors; "
        f"TLS 1.2 PRF labels {cold['tls12_prf_label_bytes']} B; "
        f"old ClientHello literals {cold['tls12_client_hello_literal_bytes']} B"
    )
    print()
    print(
        f"Secure module current: {module['current_bytes']} B, "
        f"slack {module['current_slack']} B / {module['limit_bytes']} B"
    )
    for item in module["breakdown"]:
        print(f"  {item['bytes']:4d} B  {item['name']}")
    print(
        "Generic RSA-recover candidate: "
        f"{module['generic_rsa_candidate_bytes']} B / "
        f"{module['generic_rsa_candidate_sectors']} sectors, "
        f"slack {module['generic_rsa_candidate_slack']} B below 24-sector limit "
        f"({module['generic_rsa_candidate_extent_slack']} B in its 23-sector extent); "
        f"net reduction {module['generic_rsa_candidate_reduction']} B; "
        f"old hot span {module['old_tls12_hot_verify_span_bytes']} B -> "
        f"candidate span {module['generic_rsa_candidate_span_bytes']} B; "
        f"chain wrapper {module['old_chain_wrapper_bytes']} B -> "
        f"{module['generic_rsa_chain_wrapper_bytes']} B; "
        f"word-alignment padding reduction "
        f"{module['generic_rsa_alignment_padding_reduction']} B"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = report()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
