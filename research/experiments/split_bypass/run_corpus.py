#!/usr/bin/env python3
"""Compile and run the isolated source-first split-bypass evaluation corpus.

This harness records actual compiler/analyzer outcomes. It does not assign
reference verdicts and does not claim block-level analysis.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORPUS = Path(__file__).resolve().parent
MANIFEST = CORPUS / "manifest.json"
DEFAULT_POLICY = ROOT / "research/experiments/corpus/phase5/policies/phase5_policy.json"
RUNNER = ROOT / "research/experiments/scripts/split_analyze_bypass.py"
RESULTS_ROOT = ROOT / "research/experiments/results/split-bypass-evaluation"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str]) -> dict:
    started = time.monotonic_ns()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            "command": command,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration_ms": (time.monotonic_ns() - started) / 1_000_000,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "stderr": exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            "duration_ms": (time.monotonic_ns() - started) / 1_000_000,
            "timed_out": True,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--baseline-dir", help="KRAKENGUARD artifact directory; omit to record fallback unavailable")
    parser.add_argument("--socket-path")
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--abstract-timeout-seconds", type=float, default=60)
    parser.add_argument("--symbolic-timeout-seconds", type=float, default=120)
    parser.add_argument("--run-id", help="optional unique output directory name")
    args = parser.parse_args()
    if args.warmups < 0 or args.repetitions < 1:
        parser.error("--warmups must be >= 0 and --repetitions must be >= 1")
    policy = Path(args.policy).resolve()
    if not policy.is_file():
        parser.error(f"policy file does not exist: {policy}")
    if not MANIFEST.is_file():
        parser.error(f"manifest missing: {MANIFEST}")

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS_ROOT / run_id
    if run_dir.exists():
        parser.error(f"refusing to overwrite existing run directory: {run_dir}")
    build_dir = run_dir / "build"
    raw_dir = run_dir / "raw"
    build_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)

    manifest = json.loads(MANIFEST.read_text())
    clang_version = command_output(["clang", "--version"])
    git_head = command_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    rows = []
    compile_records = []

    for spec in manifest["programs"]:
        source = CORPUS / spec["source"]
        object_path = build_dir / f'{spec["program_id"]}.o'
        if not source.is_file():
            compile_records.append({"program_id": spec["program_id"], "status": "source_missing"})
            continue
        compile_command = [
            "clang", "-target", "bpf", "-mcpu=v1", "-D__TARGET_ARCH_x86",
            "-O2", "-g", "-I/usr/include", "-c", str(source), "-o", str(object_path),
        ]
        compiled = command_output(compile_command)
        compile_record = {
            "program_id": spec["program_id"],
            "source": str(source.relative_to(ROOT)),
            "source_sha256": sha256(source),
            **compiled,
            "object_path": str(object_path.relative_to(ROOT)) if object_path.exists() else None,
            "object_sha256": sha256(object_path) if object_path.is_file() else None,
        }
        compile_records.append(compile_record)
        if compiled["returncode"] != 0 or not object_path.is_file():
            rows.append({
                "program_id": spec["program_id"], "phase": "compile",
                "repetition": None, "is_warmup": None, "run_status": "compile_error",
                "overall_verdict": "UNKNOWN", "abstract_verdict": None,
                "symbolic_invoked": None, "symbolic_verdict": None,
                "duration_ms": compiled["duration_ms"], "error": compiled["stderr"][-4000:],
            })
            continue

        total = args.warmups + args.repetitions
        for repetition in range(total):
            is_warmup = repetition < args.warmups
            label = "warmup" if is_warmup else "measured"
            output_path = raw_dir / f'{spec["program_id"]}-{label}-{repetition + 1:02d}.json'
            command = [
                sys.executable, str(RUNNER),
                "--object", str(object_path),
                "--policy", str(policy),
                "--program-id", spec["program_id"],
                "--abstract-timeout-seconds", str(args.abstract_timeout_seconds),
                "--symbolic-timeout-seconds", str(args.symbolic_timeout_seconds),
                "--output", str(output_path),
            ]
            if args.baseline_dir:
                command.extend(["--baseline-dir", str(Path(args.baseline_dir).resolve())])
            if args.socket_path:
                command.extend(["--socket-path", args.socket_path])
            execution = command_output(command)
            payload = {}
            parse_error = None
            if output_path.is_file():
                try:
                    payload = json.loads(output_path.read_text())
                except (OSError, json.JSONDecodeError) as exc:
                    parse_error = f"{type(exc).__name__}: {exc}"
            else:
                parse_error = "runner did not create its result JSON"
            unit = (payload.get("units") or [{}])[0]
            status = payload.get("overall_status", "unresolved")
            rows.append({
                "program_id": spec["program_id"],
                "phase": label,
                "repetition": repetition + 1,
                "is_warmup": is_warmup,
                "run_status": status if parse_error is None else "runner_error",
                "overall_verdict": payload.get("overall_verdict", "UNKNOWN"),
                "abstract_verdict": unit.get("abstract_verdict"),
                "abstract_duration_ms": unit.get("abstract_duration_ms"),
                "symbolic_invoked": unit.get("symbolic_invoked"),
                "symbolic_verdict": unit.get("symbolic_verdict"),
                "symbolic_duration_ms": unit.get("symbolic_duration_ms"),
                "duration_ms": execution["duration_ms"],
                "exit_code": execution["returncode"],
                "output_path": str(output_path.relative_to(ROOT)) if output_path.is_file() else None,
                "error": parse_error or unit.get("symbolic_error") or unit.get("abstract_error") or execution["stderr"][-4000:],
            })

    summary = {
        "schema": "split-bypass-evaluation-run/v1",
        "run_id": run_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit_observed": git_head["stdout"].strip() if git_head["returncode"] == 0 else None,
        "source_commit_command": git_head,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "clang_version_command": clang_version,
        "policy_path": str(policy),
        "policy_sha256": sha256(policy),
        "manifest_path": str(MANIFEST.relative_to(ROOT)),
        "baseline_dir": str(Path(args.baseline_dir).resolve()) if args.baseline_dir else None,
        "socket_path": args.socket_path,
        "warmups_per_program": args.warmups,
        "measured_repetitions_per_program": args.repetitions,
        "timeouts_seconds": {
            "abstract": args.abstract_timeout_seconds,
            "symbolic": args.symbolic_timeout_seconds,
        },
        "scope": "program_level_only; CFG blocks are metadata and do not have independent verdicts",
        "compile_records": compile_records,
        "rows": rows,
        "counts": {
            "programs_in_manifest": len(manifest["programs"]),
            "compile_successes": sum(1 for row in compile_records if row.get("returncode") == 0 and row.get("object_sha256")),
            "compile_failures": sum(1 for row in compile_records if row.get("returncode") not in (0, None)),
            "measured_runs": sum(1 for row in rows if row.get("is_warmup") is False),
            "warmup_runs": sum(1 for row in rows if row.get("is_warmup") is True),
            "unresolved_runs": sum(1 for row in rows if row.get("run_status") == "unresolved"),
            "runner_errors": sum(1 for row in rows if row.get("run_status") == "runner_error"),
        },
        "claim_boundary": "No reference verdicts, correctness agreement, speedup, or block-level verification are inferred by this harness.",
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    columns = [
        "program_id", "phase", "repetition", "is_warmup", "run_status",
        "overall_verdict", "abstract_verdict", "abstract_duration_ms",
        "symbolic_invoked", "symbolic_verdict", "symbolic_duration_ms",
        "duration_ms", "exit_code", "output_path", "error",
    ]
    with (run_dir / "runs.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({
        "run_dir": str(run_dir.relative_to(ROOT)),
        "summary": str((run_dir / "summary.json").relative_to(ROOT)),
        "runs_csv": str((run_dir / "runs.csv").relative_to(ROOT)),
        "counts": summary["counts"],
    }, indent=2))
    return 0 if summary["counts"]["runner_errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
