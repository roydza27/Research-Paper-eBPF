#!/usr/bin/env python3
"""Tri-mode evaluation and benchmark runner.

Executes controlled evaluation across the 10-fixture corpus in three modes:
- Mode A (symbolic_only): Symbolic-only whole-program verification via KRAKENGUARD.
- Mode B (whole_hybrid): Legacy whole-program abstract analyzer with whole-program symbolic fallback.
- Mode C (region_hybrid): Task 6/8 region-level abstract analyzer with CFG state propagation,
  lattice joins, and whole-program symbolic fallback for unresolved cases.

Supports dry-run demonstration (--dry-run) and full comparative evaluation.
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
DEFAULT_DRY_RUN_OUTPUT_DIR = ROOT / "research/experiments/results/split_bypass_dry_run/raw"
DEFAULT_EVAL_OUTPUT_DIR = ROOT / "research/experiments/results/split_bypass_evaluation/raw"


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


def execute_run(
    prog_spec: dict[str, Any],
    mode: str,
    repetition: int,
    is_warmup: bool,
    raw_dir: Path,
    abstract_timeout: float,
    symbolic_timeout: float,
    overwrite: bool = False,
) -> dict[str, Any]:
    program_id = prog_spec["program_id"]
    family = prog_spec.get("family", "unknown")
    tag = "warmup" if is_warmup else f"rep{repetition}"
    run_id = f"{program_id}_{mode}_{tag}"
    out_file = raw_dir / f"{run_id}.json"

    if out_file.exists():
        if overwrite:
            out_file.unlink()
        else:
            raise FileExistsError(f"Refusing to overwrite existing result: {out_file}")

    elf_path = ROOT / prog_spec["elf_path"]
    rel_socket = "research/baselines/krakenguard/artifact/socket/krakenguard.sock"

    # Extract reference oracle verdict if available
    ref_oracle = prog_spec.get("reference_oracle", {})
    expected_verdict = ref_oracle.get("expected_semantic_verdict")

    source_path = ROOT / prog_spec["source_path"] if "source_path" in prog_spec else None

    cmd = [
        sys.executable,
        str(RUNNER_SCRIPT),
        "--mode",
        mode,
        "--object",
        str(elf_path),
        "--policy",
        str(POLICY_PATH),
        "--program-id",
        program_id,
        "--fixture-family",
        family,
        "--repetition",
        str(repetition),
        "--baseline-dir",
        str(BASELINE_DIR),
        "--socket-path",
        str(rel_socket),
        "--abstract-timeout-seconds",
        str(abstract_timeout),
        "--symbolic-timeout-seconds",
        str(symbolic_timeout),
        "--output",
        str(out_file),
    ]

    if is_warmup:
        cmd.append("--is-warmup")
    if expected_verdict:
        cmd.extend(["--reference-verdict", expected_verdict])
    if source_path and source_path.exists():
        cmd.extend(["--source", str(source_path)])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if not out_file.exists():
        raise RuntimeError(
            f"Runner failed to produce output JSON for {program_id} ({mode}, {tag}). "
            f"Exit: {proc.returncode}, Stderr: {proc.stderr}"
        )

    record = json.loads(out_file.read_text())
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["symbolic_only", "whole_hybrid", "region_hybrid"],
        help="modes to evaluate (symbolic_only, whole_hybrid, region_hybrid)",
    )
    parser.add_argument(
        "--programs",
        nargs="+",
        default=None,
        help="subset of program IDs to run (default: all programs in manifest)",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=3,
        help="number of measured repetitions per mode/fixture (default: 3)",
    )
    parser.add_argument(
        "--warmup",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run 1 warmup iteration per fixture per mode (default: True)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="execute minimal dry-run demonstration across all 3 modes (1 fixture, 1 warmup + 1 measured)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="output directory for raw JSON runs",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow overwriting existing result JSON files",
    )
    parser.add_argument("--abstract-timeout", type=float, default=60.0)
    parser.add_argument("--symbolic-timeout", type=float, default=120.0)

    args = parser.parse_args()

    if not MANIFEST_PATH.exists():
        parser.error(f"Manifest not found: {MANIFEST_PATH}")

    manifest = json.loads(MANIFEST_PATH.read_text())
    print("[1/3] Verifying manifest hashes and fixture ELF integrity...")
    verify_manifest_and_fixtures(manifest)
    print("      All fixture ELF hashes and policy hash verified.")

    # Determine configuration
    all_programs = manifest.get("programs", [])
    if args.dry_run:
        modes = ["symbolic_only", "whole_hybrid", "region_hybrid"]
        repetitions = 1
        include_warmup = True
        programs = [all_programs[0]] if not args.programs else [p for p in all_programs if p["program_id"] in args.programs]
        raw_dir = args.output_dir or DEFAULT_DRY_RUN_OUTPUT_DIR
        print(f"[*] DRY-RUN MODE: Running {len(programs)} fixture(s) across 3 modes with 1 warmup + 1 measured rep.")
    else:
        modes = args.modes
        repetitions = args.repetitions
        include_warmup = args.warmup
        programs = all_programs if not args.programs else [p for p in all_programs if p["program_id"] in args.programs]
        raw_dir = args.output_dir or DEFAULT_EVAL_OUTPUT_DIR

    raw_dir.mkdir(parents=True, exist_ok=True)

    warmup_runs = len(programs) * len(modes) * (1 if include_warmup else 0)
    measured_runs = len(programs) * len(modes) * repetitions
    total_runs = warmup_runs + measured_runs

    print(
        f"[2/3] Executing evaluation: {len(programs)} fixtures x {len(modes)} modes x "
        f"({1 if include_warmup else 0} warmup + {repetitions} measured) = {total_runs} runs"
    )

    completed = 0
    t0 = time.time()
    for prog in programs:
        prog_id = prog["program_id"]
        for mode in modes:
            # Warmup
            if include_warmup:
                rec_w = execute_run(
                    prog_spec=prog,
                    mode=mode,
                    repetition=0,
                    is_warmup=True,
                    raw_dir=raw_dir,
                    abstract_timeout=args.abstract_timeout,
                    symbolic_timeout=args.symbolic_timeout,
                    overwrite=args.overwrite,
                )
                completed += 1
                print(
                    f"  [{completed}/{total_runs}] {prog_id} [{mode}] (warmup) -> "
                    f"disp={rec_w['disposition']}, abs={rec_w['abstract_verdict']}, "
                    f"sym={rec_w['symbolic_verdict']}, fallback={rec_w['fallback_invoked']}, "
                    f"time={rec_w['end_to_end_duration_ms']:.1f}ms"
                )

            # Measured repetitions
            for rep in range(1, repetitions + 1):
                rec_m = execute_run(
                    prog_spec=prog,
                    mode=mode,
                    repetition=rep,
                    is_warmup=False,
                    raw_dir=raw_dir,
                    abstract_timeout=args.abstract_timeout,
                    symbolic_timeout=args.symbolic_timeout,
                    overwrite=args.overwrite,
                )
                completed += 1
                print(
                    f"  [{completed}/{total_runs}] {prog_id} [{mode}] (rep {rep}) -> "
                    f"disp={rec_m['disposition']}, abs={rec_m['abstract_verdict']}, "
                    f"sym={rec_m['symbolic_verdict']}, fallback={rec_m['fallback_invoked']}, "
                    f"agree={rec_m['oracle_agreement']}, time={rec_m['end_to_end_duration_ms']:.1f}ms"
                )

    elapsed = time.time() - t0
    print(f"[3/3] Completed {completed} runs in {elapsed:.2f}s. Raw results stored in {raw_dir}")

    # Generate summary report using analyze_runs
    scripts_dir = ROOT / "research/experiments/split_bypass/scripts"
    sys.path.insert(0, str(scripts_dir))
    from analyze_runs import load_records, summarize

    records = load_records(sorted(raw_dir.glob("*.json")))
    summary = summarize(records)

    print("\n" + "=" * 90)
    print("EVALUATION SUMMARY REPORT")
    print("=" * 90)
    header = f"{'Program':<22} {'Pipeline/Mode':<16} {'Runs':<6} {'E2E Median (ms)':<18} {'Abstract (ms)':<16} {'Sym Inv Rate':<14} {'Oracle Agree':<12}"
    print(header)
    print("-" * 90)
    for row in summary["per_program_pipeline"]:
        e2e = f"{row['end_to_end_ms_median']:.2f}" if row.get("end_to_end_ms_median") is not None else "N/A"
        abs_ms = f"{row['abstract_ms_median']:.2f}" if row.get("abstract_ms_median") is not None else "N/A"
        sym_rate = f"{row['symbolic_invocation_rate'] * 100:.0f}%" if row.get("symbolic_invocation_rate") is not None else "N/A"
        agree = f"{row['oracle_agreement_rate'] * 100:.0f}%" if row.get("oracle_agreement_rate") is not None else "N/A"
        print(f"{row['program_id']:<22} {row['pipeline']:<16} {row['run_count']:<6} {e2e:<18} {abs_ms:<16} {sym_rate:<14} {agree:<12}")
    print("=" * 90)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
