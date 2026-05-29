#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ROOT = ROOT / "targets/ibm_pc_5150/86box"
HARNESS = ROOT / "tools/run-basic-bootstrap-86box.py"


@dataclass
class RunResult:
    profile: str
    iteration: int
    returncode: int
    elapsed_s: float
    verdict: str
    log: str
    oracle_screenshot: str
    stdout_tail: list[str]

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.verdict == "success"


def default_profiles() -> list[str]:
    excluded_suffixes = ("-32k", "-64k", "-8mhz")
    return sorted(
        path.name
        for path in PROFILE_ROOT.iterdir()
        if path.is_dir()
        and path.name.startswith("vm-net-")
        and not path.name.endswith(excluded_suffixes)
    )


def parse_verdict(output: str) -> str:
    for line in reversed(output.splitlines()):
        marker = "screen oracle: "
        if marker not in line:
            continue
        body = line.split(marker, 1)[1].strip()
        if body.startswith("kept"):
            continue
        match = re.search(r"\b(?:verdict=|derived=)?(success|clean-failure|freeze|ambiguous)\b", body)
        if match:
            return match.group(1)
    return "unknown"


def rewrite_temp_identity(config: Path, run_name: str) -> None:
    """Avoid 86Box moved/copied prompts and duplicate NIC MACs for profile copies."""
    text = config.read_text(encoding="utf-8")
    # 86Box compares the stored UUID with UUIDv5(nil, canonical_vm_dir + "/").
    # Match that derivation for throwaway profile copies so they are treated as
    # native temp profiles rather than copied machines.
    vm_dir = str(config.parent.resolve())
    if not vm_dir.endswith("/"):
        vm_dir += "/"
    run_uuid = uuid.uuid5(uuid.UUID(int=0), vm_dir)
    digest = hashlib.blake2s(run_name.encode("ascii"), digest_size=3).digest()
    run_mac = ":".join(f"{byte:02x}" for byte in digest)

    lines: list[str] = []
    replaced_uuid = False
    replaced_mac = False
    for line in text.splitlines():
        if line.startswith("uuid = "):
            lines.append(f"uuid = {run_uuid}")
            replaced_uuid = True
        elif line.startswith("mac = "):
            lines.append(f"mac = {run_mac}")
            replaced_mac = True
        else:
            lines.append(line)
    if not replaced_uuid:
        raise RuntimeError(f"{config} has no 86Box uuid")
    if not replaced_mac:
        raise RuntimeError(f"{config} has no NIC mac")
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")


def matching_86box_pids(vm_path: Path) -> set[int]:
    try:
        result = subprocess.run(
            ["pgrep", "-fl", "86Box"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode not in (0, 1):
        return set()
    pids: set[int] = set()
    vm_path_text = str(vm_path)
    for line in result.stdout.splitlines():
        pid_text, _, command = line.strip().partition(" ")
        if not pid_text.isdigit():
            continue
        if "86Box" in command and "--vmpath" in command and vm_path_text in command:
            pids.add(int(pid_text))
    return pids


def stop_matching_86box_pids(vm_path: Path, timeout: float = 5.0) -> None:
    pids = sorted(matching_86box_pids(vm_path))
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not matching_86box_pids(vm_path):
            return
        time.sleep(0.1)
    for pid in sorted(matching_86box_pids(vm_path)):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_one(
    profile: str,
    iteration: int,
    args: argparse.Namespace,
    artifact_dir: Path,
    harness_args: list[str],
) -> RunResult:
    source_profile = PROFILE_ROOT / profile
    if not source_profile.is_dir():
        raise RuntimeError(f"missing profile: {source_profile}")

    run_name = f"{profile}-{iteration:02d}"
    vm_path = artifact_dir / "profiles" / run_name
    oracle_screenshot = artifact_dir / f"{run_name}-oracle.png"
    full_screenshot = artifact_dir / f"{run_name}-screen.png"
    log_path = artifact_dir / f"{run_name}.log"

    if vm_path.exists():
        shutil.rmtree(vm_path)
    shutil.copytree(source_profile, vm_path)
    rewrite_temp_identity(vm_path / "86box.cfg", run_name)

    cmd = [
        sys.executable,
        str(HARNESS),
        "--profile",
        profile,
        "--vm-path",
        str(vm_path),
        "--no-build",
        "--no-screenshot",
        "--screen-oracle",
        "--fail-on-screen-oracle",
        "--capture-delay",
        str(args.capture_delay),
        "--oracle-screenshot",
        str(oracle_screenshot),
        "--screenshot",
        str(full_screenshot),
    ]
    if args.keep_success_oracle_screenshots:
        cmd.append("--keep-success-oracle-screenshot")
    if args.foreground_launch:
        cmd.append("--foreground-launch")
    cmd.extend(harness_args)

    started = time.monotonic()
    output_parts: list[str] = []
    timed_out = False
    returncode = 99
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("w", encoding="utf-8")
    process: subprocess.Popen[str] | None = None

    def read_stdout() -> None:
        assert process is not None
        assert process.stdout is not None
        for line in process.stdout:
            output_parts.append(line)
            log_file.write(line)
            log_file.flush()

    try:
        process = subprocess.Popen(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()
        timeout = args.run_timeout if args.run_timeout > 0 else None
        while True:
            returncode = process.poll()
            if returncode is not None:
                break
            if timeout is not None and time.monotonic() - started >= timeout:
                timed_out = True
                output_parts.append(
                    f"\nmatrix: child timed out after {timeout:.0f}s\n"
                )
                log_file.write(output_parts[-1])
                log_file.flush()
                process.kill()
                break
            time.sleep(0.2)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=5)
        reader.join(timeout=2)
        if timed_out:
            returncode = 124
    finally:
        log_file.close()
        if timed_out:
            stop_matching_86box_pids(vm_path)
        shutil.rmtree(vm_path, ignore_errors=True)

    elapsed = time.monotonic() - started
    output = "".join(output_parts)
    tail = output.strip().splitlines()[-12:]
    return RunResult(
        profile=profile,
        iteration=iteration,
        returncode=returncode,
        elapsed_s=round(elapsed, 1),
        verdict=parse_verdict(output),
        log=str(log_path),
        oracle_screenshot=str(oracle_screenshot),
        stdout_tail=tail,
    )


def write_summary(results: list[RunResult], artifact_dir: Path) -> None:
    results = sorted(results, key=lambda item: (item.profile, item.iteration))
    overall_passed = sum(1 for item in results if item.ok)
    overall_total = len(results)
    summary = {
        "passed": overall_passed,
        "total": overall_total,
        "pass_rate": (overall_passed / overall_total) if overall_total else 0.0,
        "results": [asdict(item) | {"ok": item.ok} for item in results],
    }
    (artifact_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        f"Seed BASIC bootstrap matrix: {overall_passed}/{overall_total} passed",
        "",
    ]
    for profile in sorted({item.profile for item in results}):
        profile_results = [item for item in results if item.profile == profile]
        passed = sum(1 for item in profile_results if item.ok)
        total = len(profile_results)
        lines.append(f"{profile}: {passed}/{total} passed")
        for item in profile_results:
            status = "PASS" if item.ok else "FAIL"
            lines.append(
                f"  {item.iteration:02d}: {status} rc={item.returncode} "
                f"verdict={item.verdict} {item.elapsed_s:.1f}s"
            )
            lines.append(f"      log: {item.log}")
            if not item.ok:
                lines.append(f"      oracle: {item.oracle_screenshot}")
    (artifact_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Seed ROM BASIC 86Box canaries across profiles with bounded parallelism.",
    )
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=None,
        help="profiles to test (default: every vm-net-* profile)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="runs per profile (default: 1)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="maximum parallel 86Box runs (default: 1)",
    )
    parser.add_argument(
        "--all-at-once",
        action="store_true",
        help="set jobs to the full number of requested runs",
    )
    parser.add_argument(
        "--capture-delay",
        type=float,
        default=100.0,
        help="seconds each harness run waits before oracle classification (default: 100)",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help="where logs and failure oracle screenshots go (default: /tmp/seed-matrix-<timestamp>)",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="skip the one-time make/basic-bootstrap before starting the matrix",
    )
    parser.add_argument(
        "--keep-success-oracle-screenshots",
        action="store_true",
        help="keep oracle screenshots even for successful runs",
    )
    parser.add_argument(
        "--foreground-launch",
        action="store_true",
        help="pass --foreground-launch through to the harness",
    )
    parser.add_argument(
        "--run-timeout",
        type=float,
        default=0.0,
        help="seconds before a child harness run is killed (default: disabled)",
    )
    parser.add_argument(
        "harness_args",
        nargs=argparse.REMAINDER,
        help="extra arguments passed to each harness run after --",
    )
    args = parser.parse_args()

    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")
    profiles = args.profiles or default_profiles()
    if not profiles:
        raise SystemExit("no profiles selected")

    harness_args = list(args.harness_args)
    if harness_args and harness_args[0] == "--":
        harness_args = harness_args[1:]

    total_runs = len(profiles) * args.repeat
    jobs = total_runs if args.all_at_once else args.jobs
    jobs = max(1, min(jobs, total_runs))

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_dir = args.artifact_dir or Path(f"/tmp/seed-matrix-{timestamp}")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "profiles").mkdir(exist_ok=True)

    if not args.no_build:
        subprocess.run(["make"], cwd=ROOT, check=True)
        subprocess.run(["make", "basic-bootstrap"], cwd=ROOT, check=True)

    print(
        f"matrix: {total_runs} run(s), {len(profiles)} profile(s), "
        f"repeat={args.repeat}, jobs={jobs}"
    )
    print(f"matrix: artifacts {artifact_dir}")

    tasks = [
        (profile, iteration)
        for profile in profiles
        for iteration in range(1, args.repeat + 1)
    ]
    results: list[RunResult] = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(run_one, profile, iteration, args, artifact_dir, harness_args): (
                profile,
                iteration,
            )
            for profile, iteration in tasks
        }
        for future in as_completed(future_map):
            profile, iteration = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = RunResult(
                    profile=profile,
                    iteration=iteration,
                    returncode=99,
                    elapsed_s=0.0,
                    verdict="harness-error",
                    log="",
                    oracle_screenshot="",
                    stdout_tail=[repr(exc)],
                )
            results.append(result)
            status = "PASS" if result.ok else "FAIL"
            print(
                f"matrix {profile} #{iteration}: {status} "
                f"rc={result.returncode} verdict={result.verdict} {result.elapsed_s:.1f}s"
            )

    write_summary(results, artifact_dir)

    passed = sum(1 for item in results if item.ok)
    total = len(results)
    print(f"matrix summary: {passed}/{total} passed")
    print(f"matrix summary text: {artifact_dir / 'summary.txt'}")
    print(f"matrix summary json: {artifact_dir / 'summary.json'}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
