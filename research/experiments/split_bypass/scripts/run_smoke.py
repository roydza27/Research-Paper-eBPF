#!/usr/bin/env python3
"""Execute controlled smoke experiment across the 10-fixture corpus.

Runs 1 warmup + 2 measured repetitions per fixture, capturing normalized run
records for routing audit and aggregation without claiming block-level verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
MANIFEST_PATH = ROOT / "research/experiments/split_bypass/manifests/corpus-manifest.json"
POLICY_PATH = ROOT / "research/experiments/split_bypass/policies/policy-c0f0ac4d1a5e.json"
RUNNER_SCRIPT = ROOT / "research/experiments/scripts/split_analyze_bypass.py"
BASELINE_DIR = ROOT / "research/baselines/krakenguard/artifact"
SOCKET_PATH = ROOT / "research/baselines/krakenguard/artifact/socket/krakenguard.sock"
DEFAULT_OUTPUT_DIR = ROOT / "research/experiments/results/split_bypass_smoke/raw"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest_and_fixtures(manifest: dict[str, Any]) -> None:
    expected_policy_hash = manifest.get("policy_source_sha256")
    if not POLICY_PATH.exists():
        raise FileNotFoundError(f"Policy file not found: {POLICY_PATH}")
    actual_policy_hash = sha256_file(POLICY_PATH)
    if expected_policy_hash and actual_policy_hash != expected_policy_hash:
        raise ValueError(
            f"Policy hash mismatch: expected {expected_policy_hash}, got {actual_policy_hash}"
        )

    for prog in manifest.get("programs", []):
        prog_id = prog["program_id"]
        elf_rel = prog.get("elf_path")
        expected_elf_hash = prog.get("elf_sha256")
        elf_path = ROOT / elf_rel
        if not elf_path.exists():
            raise FileNotFoundError(f"Fixture ELF not found for {prog_id}: {elf_path}")
        actual_elf_hash = sha256_file(elf_path)
        if expected_elf_hash and actual_elf_hash != expected_elf_hash:
            raise ValueError(
                f"Fixture ELF hash mismatch for {prog_id}: expected {expected_elf_hash}, got {actual_elf_hash}"
            )


def run_single(
    prog_spec: dict[str, Any],
    repetition: int,
    is_warmup: bool,
    raw_dir: Path,
    abstract_timeout: float,
    symbolic_timeout: float,
) -> dict[str, Any]:
    program_id = prog_spec["program_id"]
    family = prog_spec.get("family", "unknown")
    tag = "warmup" if is_warmup else f"rep{repetition}"
    run_id = f"{program_id}_{tag}"
    out_file = raw_dir / f"{run_id}.json"

    if out_file.exists():
        raise FileExistsError(f"Refusing to overwrite existing result: {out_file}")

    elf_path = ROOT / prog_spec["elf_path"]
    rel_socket = "research/baselines/krakenguard/artifact/socket/krakenguard.sock"

    # Temporary output path for the prototype runner
    proto_out = raw_dir / f".tmp_{run_id}.json"
    if proto_out.exists():
        proto_out.unlink()

    cmd = [
        sys.executable,
        str(RUNNER_SCRIPT),
        "--object",
        str(elf_path),
        "--policy",
        str(POLICY_PATH),
        "--program-id",
        program_id,
        "--baseline-dir",
        str(BASELINE_DIR),
        "--socket-path",
        str(rel_socket),
        "--abstract-timeout-seconds",
        str(abstract_timeout),
        "--symbolic-timeout-seconds",
        str(symbolic_timeout),
        "--output",
        str(proto_out),
    ]

    t0 = time.monotonic_ns()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    e2e_outer_ms = (time.monotonic_ns() - t0) / 1_000_000

    if not proto_out.exists():
        raise RuntimeError(
            f"Runner failed to produce output JSON for {program_id} ({tag}). "
            f"Exit: {proc.returncode}, Stderr: {proc.stderr}"
        )

    proto_payload = json.loads(proto_out.read_text())
    proto_out.unlink()

    unit = proto_payload["units"][0] if proto_payload.get("units") else {}
    metrics = proto_payload.get("metrics", {})

    record = {
        "schema": "split-bypass-smoke-record/v1",
        "run_id": run_id,
        "program_id": program_id,
        "fixture_family": family,
        "policy_id": "c0f0ac4d1a5e",
        "pipeline": "split_bypass",
        "mode": "hybrid",
        "repetition": repetition,
        "is_warmup": is_warmup,
        "abstract_verdict": unit.get("abstract_verdict"),
        "symbolic_verdict": unit.get("symbolic_verdict"),
        "overall_verdict": proto_payload.get("overall_verdict"),
        "routed_to_symbolic": bool(unit.get("symbolic_invoked")),
        "symbolic_invoked": bool(unit.get("symbolic_invoked")),
        "disposition": proto_payload.get("overall_status"),
        "unresolved_reason": (
            unit.get("abstract_error")
            or unit.get("symbolic_error")
            or (
                unit.get("abstract_reason")
                if unit.get("abstract_verdict") == "UNKNOWN"
                and not unit.get("symbolic_verdict")
                else None
            )
        ),
        "fallback_scope": "whole_program",
        "abstract_duration_ms": unit.get("abstract_duration_ms"),
        "symbolic_duration_ms": unit.get("symbolic_duration_ms"),
        "end_to_end_duration_ms": metrics.get("end_to_end_duration_ms", e2e_outer_ms),
        "cfg_block_count": metrics.get("cfg_block_count"),
        "reachable_block_count": metrics.get("reachable_block_count"),
        "prototype_record": proto_payload,
    }

    out_file.write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--abstract-timeout", type=float, default=60.0)
    parser.add_argument("--symbolic-timeout", type=float, default=120.0)
    parser.add_argument(
        "--repetitions",
        type=int,
        default=2,
        help="Number of measured repetitions (in addition to 1 warmup)",
    )
    args = parser.parse_args()

    if not MANIFEST_PATH.exists():
        parser.error(f"Manifest not found: {MANIFEST_PATH}")

    manifest = json.loads(MANIFEST_PATH.read_text())
    print("[1/3] Verifying manifest hashes and fixture ELF integrity...")
    verify_manifest_and_fixtures(manifest)
    print("      All fixture ELF hashes and policy hash verified.")

    raw_dir = args.output_dir
    if raw_dir.exists() and any(raw_dir.glob("*.json")):
        parser.error(f"Output directory exists and contains JSON files: {raw_dir}")
    raw_dir.mkdir(parents=True, exist_ok=True)

    programs = manifest.get("programs", [])
    total_runs = len(programs) * (1 + args.repetitions)
    print(
        f"[2/3] Executing smoke experiment: {len(programs)} fixtures x (1 warmup + {args.repetitions} measured) = {total_runs} runs"
    )

    completed = 0
    start_time = time.time()
    for prog in programs:
        prog_id = prog["program_id"]
        # Warmup run
        rec_w = run_single(
            prog,
            repetition=0,
            is_warmup=True,
            raw_dir=raw_dir,
            abstract_timeout=args.abstract_timeout,
            symbolic_timeout=args.symbolic_timeout,
        )
        completed += 1
        print(
            f"  [{completed}/{total_runs}] {prog_id} (warmup) -> "
            f"disp={rec_w['disposition']}, abs={rec_w['abstract_verdict']}, sym={rec_w['symbolic_verdict']}, "
            f"time={rec_w['end_to_end_duration_ms']:.1f}ms"
        )

        # Measured runs
        for rep in range(1, args.repetitions + 1):
            rec_m = run_single(
                prog,
                repetition=rep,
                is_warmup=False,
                raw_dir=raw_dir,
                abstract_timeout=args.abstract_timeout,
                symbolic_timeout=args.symbolic_timeout,
            )
            completed += 1
            print(
                f"  [{completed}/{total_runs}] {prog_id} (rep {rep}) -> "
                f"disp={rec_m['disposition']}, abs={rec_m['abstract_verdict']}, sym={rec_m['symbolic_verdict']}, "
                f"time={rec_m['end_to_end_duration_ms']:.1f}ms"
            )

    elapsed = time.time() - start_time
    print(
        f"[3/3] Completed {completed} runs in {elapsed:.2f}s. Raw results stored in {raw_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
