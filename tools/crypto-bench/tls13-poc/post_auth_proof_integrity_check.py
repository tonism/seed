#!/usr/bin/env python3
"""Hostile gates for the credentialed-live proof boundary.

This checker launches no VM and performs no network I/O.  It uses two public
dummy USER.CFG files to prove that the production manifest, console transcript,
and runner report do not distinguish credential file sizes.  A fake harness
only supplies the already-defined serial success markers after the real builder
and runner have completed all artifact-integrity checks.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import io
import json
import os
import shutil
import subprocess as real_subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECKER = Path(__file__).resolve()
BUILDER_SOURCE = HERE / "build_post_auth_live.py"
RUNNER_SOURCE = HERE / "run_post_auth_live.py"
BASIC_LOADER_SOURCE = ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm"
BASIC_TEXT_BUILDER = ROOT / "tools/build-basic-bootstrap.py"
LIVE_BASE_BUILDER = HERE / "build_live_k15.py"
DEFAULT_OUTPUT = HERE / "post_auth_proof_integrity_results.json"

PUBLIC_CFG_PREFIX = (
    b"agent openai\n"
    b"model gpt-5-mini\n"
    b"key sk-proof-integrity-public-fixture-"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flip_first_byte(path: Path) -> None:
    value = bytearray(path.read_bytes())
    if not value:
        raise AssertionError(f"cannot tamper empty artifact: {path}")
    value[0] ^= 0x01
    path.write_bytes(value)


def import_local(name: str) -> Any:
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    return importlib.import_module(name)


def copy_basic_pair(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    for name in ("live-k15-basic-loader.bin", "LIVEK15.BAS"):
        shutil.copy2(source / name, destination / name)


def isolated_automatic_base(
    builder: Any,
    root: Path,
    supplied_base: Path | None,
) -> tuple[Path, dict[str, Any]]:
    base = root / "automatic-secure-base"
    if supplied_base is None:
        completed = real_subprocess.run(
            [
                sys.executable,
                str(LIVE_BASE_BUILDER),
                "--secure",
                "--build-dir",
                str(base),
            ],
            cwd=ROOT,
            check=True,
            stdout=real_subprocess.PIPE,
            stderr=real_subprocess.STDOUT,
            text=True,
        )
        generated = True
    else:
        if not supplied_base.is_dir():
            raise AssertionError("supplied proof base is not a directory")
        shutil.copytree(supplied_base, base)
        completed = SimpleNamespace(stdout="")
        generated = False

    manifest, core, _phases, manifest_path = builder.validate_base(base)
    entropy = manifest.get("entropy_ceremony")
    mode = entropy.get("operational_mode") if isinstance(entropy, dict) else None
    if (
        not isinstance(mode, dict)
        or mode.get("manual_operator_entry_required") is not False
        or mode.get("unattended_collection") is not True
        or mode.get("collection_before_first_network_transmission") is not True
        or mode.get("automated_security_credit_bits") != 0
        or mode.get("physical_security_credit_pending") is not True
    ):
        raise AssertionError(
            "isolated proof base lacks the automatic-floppy-entropy contract"
        )
    if generated and "VM/network launch=NOT PERFORMED" not in completed.stdout:
        raise AssertionError("isolated base builder crossed its offline boundary")
    return base, {
        "generated_inside_private_gate": generated,
        "supplied_base_copied_before_use": not generated,
        "manual_operator_entry_required": False,
        "unattended_collection": True,
        "collection_before_first_network_transmission": True,
        "automated_security_credit_bits": 0,
        "physical_security_credit_pending": True,
        "network_or_vm_launched": False,
        "core_bytes": len(core),
        "core_sha256": hashlib.sha256(core).hexdigest(),
        "manifest_sha256": sha256_file(manifest_path),
    }


def basic_source_binding_gate(builder: Any, base: Path, root: Path) -> dict[str, Any]:
    for required in (
        base / "live-k15-basic-loader.bin",
        base / "LIVEK15.BAS",
    ):
        if not required.is_file():
            raise AssertionError(f"secure base BASIC artifact is absent: {required}")

    pristine = root / "basic-pristine"
    copy_basic_pair(base, pristine)
    pristine_out = root / "basic-pristine-output"
    pristine_out.mkdir()
    loader, basic, loader_bytes, basic_bytes = (
        builder.build_and_bind_basic_sidecar(pristine_out, pristine)
    )

    hostile_cases: list[str] = []
    for label, target in (
        ("base_loader_byte_flip_rejected", "live-k15-basic-loader.bin"),
        ("base_basic_byte_flip_rejected", "LIVEK15.BAS"),
    ):
        hostile_base = root / label
        copy_basic_pair(base, hostile_base)
        flip_first_byte(hostile_base / target)
        hostile_out = root / f"{label}-output"
        hostile_out.mkdir()
        try:
            builder.build_and_bind_basic_sidecar(hostile_out, hostile_base)
        except AssertionError as exc:
            if "deterministic 16 KiB read-only loader" not in str(exc):
                raise
        else:
            raise AssertionError(f"{label} was accepted")
        hostile_cases.append(label)

    return {
        "deterministic_rebuild_passed": True,
        "loader_bytes": len(loader_bytes),
        "loader_sha256": hashlib.sha256(loader_bytes).hexdigest(),
        "basic_program_bytes": len(basic_bytes),
        "basic_program_sha256": hashlib.sha256(basic_bytes).hexdigest(),
        "rebuilt_loader_path_private_to_gate": loader.is_file(),
        "rebuilt_basic_path_private_to_gate": basic.is_file(),
        "hostile_cases": hostile_cases,
    }


class FakeHarnessProcess:
    """Minimal Popen-compatible object which emits fixed public serial markers."""

    def __init__(
        self,
        command: list[str],
        *,
        tracker: dict[str, Any],
        **_kwargs: Any,
    ) -> None:
        required = {
            "--entry": "basic",
            "--ram-kib": "16",
            "--no-build": None,
            "--no-screenshot": None,
        }
        for option, expected in required.items():
            if option not in command:
                raise AssertionError(f"runner omitted harness option {option}")
            if expected is not None:
                index = command.index(option)
                if index + 1 >= len(command) or command[index + 1] != expected:
                    raise AssertionError(
                        f"runner supplied wrong {option}: {command[index + 1]!r}"
                    )
        for option in ("--basic", "--basic-loader", "--floppy"):
            index = command.index(option)
            if not Path(command[index + 1]).is_file():
                raise AssertionError(f"runner passed absent {option} artifact")
        capture_index = command.index("--com-capture")
        capture = Path(command[capture_index + 1])
        capture.write_bytes(
            b"ENTROPY START 256\r\n"
            b"ENTROPY PASS 256\r\n"
            b"ok\r\nPASS\r\nRESULT\r\n"
        )
        tracker["popen_calls"] = tracker.get("popen_calls", 0) + 1
        self._running = True
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return None if self._running else self.returncode

    def send_signal(self, _signal: int) -> None:
        self._running = False
        self.returncode = 0

    def terminate(self) -> None:
        self.send_signal(0)

    def kill(self) -> None:
        self.send_signal(0)

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self._running = False
        self.returncode = 0
        return 0


def invoke_runner(
    runner: Any,
    *,
    builder_path: Path,
    base: Path,
    build: Path,
    user_cfg: Path,
    extra_environment: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    tracker: dict[str, Any] = {
        "profile_checks": 0,
        "popen_calls": 0,
    }

    def fake_profile(_build: Path) -> Path:
        tracker["profile_checks"] += 1
        profile = build / "fixed-proof-profile"
        profile.mkdir(exist_ok=True)
        return profile

    def fake_popen(command: list[str], **kwargs: Any) -> FakeHarnessProcess:
        return FakeHarnessProcess(command, tracker=tracker, **kwargs)

    facade = SimpleNamespace(
        PIPE=real_subprocess.PIPE,
        STDOUT=real_subprocess.STDOUT,
        TimeoutExpired=real_subprocess.TimeoutExpired,
        run=real_subprocess.run,
        Popen=fake_popen,
    )
    old_builder = runner.BUILDER
    old_subprocess = runner.subprocess
    old_profile = runner.make_exact_runtime_profile
    old_argv = sys.argv
    old_environment = {
        key: os.environ.get(key) for key in (extra_environment or {})
    }
    stream = io.StringIO()
    try:
        runner.BUILDER = builder_path
        runner.subprocess = facade
        runner.make_exact_runtime_profile = fake_profile
        for key, value in (extra_environment or {}).items():
            os.environ[key] = value
        sys.argv = [
            str(RUNNER_SOURCE),
            "--credentialed-live",
            "--automatic-floppy-entropy",
            "--user-cfg",
            str(user_cfg),
            "--base-build",
            str(base),
            "--build-dir",
            str(build),
            "--timeout",
            "60",
            "--start-timeout",
            "30",
        ]
        try:
            with contextlib.redirect_stdout(stream):
                runner.main()
        except SystemExit as exc:
            raise AssertionError(
                "runner exited before the proof boundary "
                f"(code={exc.code!r}):\n{stream.getvalue()}"
            ) from exc
    finally:
        runner.BUILDER = old_builder
        runner.subprocess = old_subprocess
        runner.make_exact_runtime_profile = old_profile
        sys.argv = old_argv
        for key, value in old_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return stream.getvalue(), tracker


def normalized_public_value(value: Any, build: Path) -> Any:
    marker = "<BUILD>"
    if isinstance(value, str):
        return value.replace(str(build), marker)
    if isinstance(value, list):
        return [normalized_public_value(item, build) for item in value]
    if isinstance(value, dict):
        return {
            key: normalized_public_value(item, build)
            for key, item in value.items()
        }
    return value


def assert_no_private_value(
    *,
    label: str,
    values: tuple[str, ...],
    private_path: Path,
    private_bytes: bytes,
) -> None:
    private_strings = (
        str(private_path),
        private_path.name,
        private_bytes.decode("ascii"),
    )
    for value in values:
        for private in private_strings:
            if private and private in value:
                raise AssertionError(f"{label} exposed a private value")


def validate_production_manifest(
    manifest: dict[str, Any],
    build: Path,
) -> None:
    mode = manifest.get("mode")
    output = manifest.get("output")
    phases = manifest.get("post_auth_phases")
    fat = manifest.get("fat_metadata")
    if (
        not isinstance(mode, dict)
        or mode.get("credentialed_live") is not True
        or mode.get("synthetic_fixture") is not False
        or not isinstance(output, dict)
        or output.get("core_sha256") is not None
        or output.get("core_hash_deliberately_omitted") is not True
        or output.get("image_sha256") is not None
        or output.get("image_hash_deliberately_omitted") is not True
        or output.get("basic_sidecar_rebuilt_and_base_compared") is not True
        or not isinstance(phases, list)
        or not isinstance(fat, dict)
        or fat.get("user_cfg_content_hash_recorded") is not False
        or fat.get("user_cfg_path_recorded") is not False
        or fat.get("user_cfg_size_recorded") is not False
        or fat.get("image_hash_recorded") is not False
    ):
        raise AssertionError("production manifest privacy contract drifted")
    user_loader = [
        phase
        for phase in phases
        if phase.get("name") == "post_auth_user_loader"
    ]
    if (
        len(user_loader) != 1
        or user_loader[0].get("sha256") is not None
        or user_loader[0].get("hash_deliberately_omitted") is not True
    ):
        raise AssertionError("credential-dependent UCL1 hash was published")
    callback_pages = [
        phase
        for phase in phases
        if phase.get("name")
        in {
            "post_auth_auth_callbacks",
            "post_auth_request_callbacks",
        }
    ]
    if (
        len(callback_pages) != 2
        or any(
            not isinstance(phase.get("sha256"), str)
            or len(phase["sha256"]) != 64
            or phase.get("hash_deliberately_omitted") is not False
            for phase in callback_pages
        )
    ):
        raise AssertionError("fixed low callback page was not byte-bound")
    for key in (
        "basic_loader",
        "basic_program",
    ):
        path = Path(str(output.get(key, "")))
        if not path.is_file() or build not in path.parents:
            raise AssertionError(f"manifest {key} path is not a built artifact")
    for key, bytes_key, hash_key in (
        ("basic_loader", "basic_loader_bytes", "basic_loader_sha256"),
        ("basic_program", "basic_program_bytes", "basic_program_sha256"),
    ):
        path = Path(output[key])
        if (
            output.get(bytes_key) != path.stat().st_size
            or output.get(hash_key) != sha256_file(path)
        ):
            raise AssertionError(f"manifest did not byte-bind {key}")


def credential_size_non_disclosure_gate(
    runner: Any,
    base: Path,
    root: Path,
) -> dict[str, Any]:
    fixtures = (
        PUBLIC_CFG_PREFIX + b"a" * 19 + b"\n",
        PUBLIC_CFG_PREFIX + b"b" * 347 + b"\n",
    )
    observations: list[dict[str, Any]] = []
    for index, fixture in enumerate(fixtures, start=1):
        private_input = root / f"private-input-{index}.cfg"
        private_input.write_bytes(fixture)
        build = root / f"credentialed-build-{index}"
        build.mkdir()
        transcript, tracker = invoke_runner(
            runner,
            builder_path=BUILDER_SOURCE,
            base=base,
            build=build,
            user_cfg=private_input,
        )
        if tracker != {"profile_checks": 1, "popen_calls": 1}:
            raise AssertionError("runner did not cross each checked boundary once")
        manifest_path = build / "manifest.json"
        report_path = build / "credentialed-live-run.json"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        report_text = report_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        report = json.loads(report_text)
        validate_production_manifest(manifest, build)
        assert_no_private_value(
            label="production transcript/manifest/report",
            values=(transcript, manifest_text, report_text),
            private_path=private_input,
            private_bytes=fixture,
        )
        privacy = report.get("credential_privacy")
        if privacy != {
            "contents_logged": False,
            "path_logged": False,
            "size_logged": False,
            "hash_logged": False,
        }:
            raise AssertionError("runner privacy report drifted")
        observations.append(
            {
                "size": len(fixture),
                "manifest": normalized_public_value(manifest, build),
                "report": normalized_public_value(report, build),
                "transcript": transcript.replace(str(build), "<BUILD>"),
            }
        )

    first, second = observations
    for label in ("manifest", "report", "transcript"):
        if first[label] != second[label]:
            raise AssertionError(
                f"credential sizes are distinguishable through public {label}"
            )
    return {
        "public_fixture_sizes": [item["size"] for item in observations],
        "production_manifest_equal_after_output_path_normalization": True,
        "production_console_equal_after_output_path_normalization": True,
        "runner_report_equal": True,
        "credential_dependent_core_hash_omitted": True,
        "credential_dependent_ucl1_hash_omitted": True,
        "fixed_low_callback_hashes_recorded": True,
        "image_hash_omitted": True,
        "credential_contents_path_size_hash_not_logged": True,
        "real_vm_or_network_launched": False,
    }


def write_stub_builder(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--credentialed-live", action="store_true")
parser.add_argument("--automatic-floppy-entropy", action="store_true")
parser.add_argument("--user-cfg")
parser.add_argument("--base-build")
parser.add_argument("--build-dir", type=Path, required=True)
args = parser.parse_args()
args.build_dir.mkdir(parents=True, exist_ok=True)
image = args.build_dir / "stub.img"
loader = args.build_dir / "stub-loader.bin"
basic = args.build_dir / "STUB.BAS"
image.write_bytes(bytes(512))
image.chmod(0o444)
loader.write_bytes(b"checked loader")
basic.write_bytes(b"10 REM CHECKED BASIC\\r\\n")
loader_hash = hashlib.sha256(loader.read_bytes()).hexdigest()
basic_hash = hashlib.sha256(basic.read_bytes()).hexdigest()
mode = os.environ.get("SEED_PROOF_STUB_MODE", "clean")
if mode == "loader":
    loader.write_bytes(b"tampered loader")
elif mode == "basic":
    basic.write_bytes(b"20 REM TAMPERED BASIC\\r\\n")
manifest = {
    "mode": {
        "credentialed_live": True,
        "automatic_floppy_entropy": True,
        "entropy_values_accepted_by_cli_or_environment": False,
    },
    "output": {
        "image": str(image),
        "basic_loader": str(loader),
        "basic_loader_bytes": len(b"checked loader"),
        "basic_loader_sha256": loader_hash,
        "basic_program": str(basic),
        "basic_program_bytes": len(b"10 REM CHECKED BASIC\\r\\n"),
        "basic_program_sha256": basic_hash,
        "basic_sidecar_rebuilt_and_base_compared": mode != "flag",
    },
}
(args.build_dir / "manifest.json").write_text(
    json.dumps(manifest), encoding="utf-8"
)
""",
        encoding="utf-8",
    )


def runner_sidecar_hostile_gate(
    runner: Any,
    base: Path,
    root: Path,
) -> list[str]:
    stub = root / "stub-builder.py"
    write_stub_builder(stub)
    user_cfg = root / "stub-private.cfg"
    user_cfg.write_bytes(PUBLIC_CFG_PREFIX + b"runner-hostile\n")
    cases = (
        ("runner_rejects_loader_changed_after_hash", "loader"),
        ("runner_rejects_basic_changed_after_hash", "basic"),
        ("runner_rejects_false_rebuild_compare_flag", "flag"),
    )
    passed: list[str] = []
    for label, mode in cases:
        build = root / label
        build.mkdir()
        try:
            invoke_runner(
                runner,
                builder_path=stub,
                base=base,
                build=build,
                user_cfg=user_cfg,
                extra_environment={"SEED_PROOF_STUB_MODE": mode},
            )
        except AssertionError as exc:
            if "BASIC loader/sidecar manifest binding drifted" not in str(exc):
                raise
        else:
            raise AssertionError(f"{label} was accepted")
        if (build / "credentialed-live-run.json").exists():
            raise AssertionError(f"{label} emitted a passing runner report")
        passed.append(label)
    return passed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-build",
        type=Path,
        help=(
            "optional automatic-entropy base to copy into the isolated gate; "
            "by default the gate builds its own deterministic --secure base"
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    builder = import_local("build_post_auth_live")
    runner = import_local("run_post_auth_live")
    temporary_parent = ROOT / "build/crypto-bench"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".post-auth-proof-integrity-",
        dir=temporary_parent,
    ) as temporary_name:
        temporary = Path(temporary_name)
        supplied_base = (
            args.base_build.resolve() if args.base_build is not None else None
        )
        base, base_report = isolated_automatic_base(
            builder,
            temporary,
            supplied_base,
        )
        basic = basic_source_binding_gate(builder, base, temporary)
        non_disclosure = credential_size_non_disclosure_gate(
            runner, base, temporary
        )
        runner_hostiles = runner_sidecar_hostile_gate(
            runner, base, temporary
        )

    hostile_cases = basic["hostile_cases"] + runner_hostiles
    result = {
        "schema": "seed-post-auth-proof-integrity-v1",
        "status": "pass",
        "scope": (
            "offline byte-binding and proof-output privacy gate; public dummy "
            "credentials only; no VM, target entropy, network, or security "
            "credit"
        ),
        "sources": {
            "checker": sha256_file(CHECKER),
            "builder": sha256_file(BUILDER_SOURCE),
            "runner": sha256_file(RUNNER_SOURCE),
            "basic_loader_source": sha256_file(BASIC_LOADER_SOURCE),
            "basic_text_builder": sha256_file(BASIC_TEXT_BUILDER),
            "live_base_builder": sha256_file(LIVE_BASE_BUILDER),
        },
        "isolated_automatic_base": base_report,
        "basic_sidecar_binding": basic,
        "credential_size_non_disclosure": non_disclosure,
        "hostile_cases": {
            "count": len(hostile_cases),
            "all_rejected": True,
            "cases": hostile_cases,
        },
    }
    args.output.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "post-auth proof-integrity gate: PASS "
        f"({len(hostile_cases)} hostile cases)"
    )
    print(f"  results={args.output}")


if __name__ == "__main__":
    main()
