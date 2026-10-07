#!/usr/bin/env python3
"""Run a controlled comparison of KRAKENGUARD symbolic verification and the hybrid design."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import resource
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
WORK_DIR = ROOT / "work"
RESULTS_DIR = WORK_DIR / "results"
RAW_DIR = RESULTS_DIR / "raw"
CONFIG_PATH = WORK_DIR / "comparison-config.json"
ABSTRACT_WORKER = WORK_DIR / "abstract_worker.py"

BASELINE_DIR = ROOT / "research" / "baselines" / "krakenguard" / "artifact"
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(BASELINE_DIR))

from daemon.krakenguard_client import KrakenGuardClient
from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer


FROZEN_POLICY_SHA = "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"
MODES = ("symbolic_only", "abstract_only", "hybrid")


def load_config() -> Dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def checked(cmd: List[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}: {p.stderr.strip()}")
    return p.stdout.strip()


def load_reference_verdicts(config: Dict[str, Any], programs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Load previously audited reference verdicts without warming the daemon."""
    manifest = ROOT / config["reference"]["validation_csv"]
    policy = ROOT / config["corpus"]["policy_file"]
    if sha256_file(policy) != config["corpus"]["policy_sha256"]:
        raise RuntimeError("policy hash mismatch before loading reference manifest")
    refs: Dict[str, Dict[str, Any]] = {}
    with manifest.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            pid = row["program_id"]
            if pid in refs:
                raise RuntimeError(f"duplicate reference program: {pid}")
            refs[pid] = {
                "reference_verdict": row["reference_verdict"],
                "reference_passed": row["reference_passed"].lower() == "true",
                "reference_source": str(manifest.relative_to(ROOT)),
                "reference_policy_sha256": config["corpus"]["policy_sha256"],
                "krakenguard_commit": row.get("krakenguard_commit", config["krakenguard"]["commit"]),
            }
    expected = {p["program_id"] for p in programs}
    if set(refs) != expected:
        raise RuntimeError("reference manifest IDs do not exactly match corpus IDs")
    for pid, ref in refs.items():
        if ref["krakenguard_commit"] != config["krakenguard"]["commit"]:
            raise RuntimeError(f"reference KRAKENGUARD commit mismatch for {pid}")
        if ref["reference_verdict"] not in ("COMPLIANT", "POLICY VIOLATION"):
            raise RuntimeError(f"invalid reference verdict for {pid}")
    return refs


def load_programs(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = ROOT / config["corpus"]["metadata_csv"]
    programs_dir = ROOT / config["corpus"]["programs_dir"]
    rows: List[Dict[str, Any]] = []
    with metadata.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            object_file = programs_dir / row["object_file"]
            if not object_file.exists():
                raise FileNotFoundError(f"missing object: {object_file}")
            rows.append({
                "program_id": row.get("program_id") or object_file.stem,
                "category": row.get("category", ""),
                "role": row.get("role", ""),
                "target_paths": int(row["target_paths"]) if row.get("target_paths") else None,
                "object_file": object_file,
                "object_sha256": sha256_file(object_file),
                "description": row.get("description", ""),
            })
    if not rows:
        raise RuntimeError("no programs found in metadata")
    return rows


def cpu_model() -> str:
    try:
        text = checked(["lscpu"])
        match = re.search(r"^Model name:\s*(.*)$", text, re.MULTILINE)
        return match.group(1).strip() if match else "unknown"
    except Exception:
        return "unknown"


def preflight(config: Dict[str, Any], programs: List[Dict[str, Any]]) -> Dict[str, Any]:
    policy = ROOT / config["corpus"]["policy_file"]
    socket = ROOT / config["krakenguard"]["socket"]
    artifact = ROOT / config["krakenguard"]["artifact_dir"]

    observed = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repo_branch": checked(["git", "-C", str(ROOT), "branch", "--show-current"]),
        "repo_head": checked(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "repo_tree": checked(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"]),
        "krakenguard_commit": checked(["git", "-C", str(artifact), "rev-parse", "HEAD"]),
        "policy_sha256": sha256_file(policy),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "compiler_version": checked(["clang", "--version"]).splitlines()[0],
        "cpu_model": cpu_model(),
        "program_count": len(programs),
        "measurement_policy": {
            "kernel": "recorded_at_run",
            "compiler": "recorded_at_run",
            "immutable_baseline": True,
            "timing": {
                "symbolic": "client.verify + verdict extraction; archive excluded",
                "abstract": "in-process AbstractPolicyAnalyzer.analyze()",
                "hybrid": "abstract section + symbolic section on UNKNOWN",
                "memory_sampling": "disabled_in_primary_timing"
            }
        },
    }

    if observed["krakenguard_commit"] != config["krakenguard"]["commit"]:
        raise RuntimeError("KRAKENGUARD commit does not match frozen baseline")
    if observed["policy_sha256"] != config["corpus"]["policy_sha256"]:
        raise RuntimeError("policy SHA does not match frozen policy")
    if observed["architecture"] != config["environment"]["architecture"]:
        raise RuntimeError("architecture does not match required environment")
    if not socket.exists():
        raise RuntimeError(f"KRAKENGUARD socket not found: {socket}")

    docker = config["krakenguard"]["container_image"]
    expected_digest = config["krakenguard"]["container_digest"]
    try:
        raw = checked(["docker", "image", "inspect", docker, "--format", "{{json .RepoDigests}}"])
        digests = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"docker frozen-artifact check failed: {exc}") from exc
    if expected_digest not in digests:
        raise RuntimeError("frozen KRAKENGUARD container digest not present")

    observed["controls"] = {
        "container_digest": expected_digest,
        "hook": config["environment"]["hook"],
        "warmups": config["measurement"]["warmups"],
        "repetitions": config["measurement"]["repetitions"],
        "timeout_seconds": config["measurement"]["timeout_seconds"],
        "seed": config["measurement"]["seed"],
    }
    return observed


def extract_kg_result(resp: Any) -> Tuple[str, Dict[str, Any], str, Path]:
    rc = getattr(resp.execution, "return_code", 0)
    if rc != 0:
        raise RuntimeError(f"KRAKENGUARD returned {rc}: {(getattr(resp.output, 'stderr', '') or '')[:500]}")

    out_dir = Path((getattr(resp.output, "directory", "") or "").replace("/data", str(BASELINE_DIR / "data")))
    conditional = out_dir / "conditional_policy.results.txt"
    if not conditional.exists():
        raise RuntimeError(f"missing KRAKENGUARD verdict artifact: {conditional}")

    text = conditional.read_text(encoding="utf-8", errors="replace").strip()
    if "Status: POLICY VIOLATIONS DETECTED" in text:
        verdict = "POLICY VIOLATION"
    elif "Status: NO VIOLATIONS" in text:
        verdict = "COMPLIANT"
    else:
        raise RuntimeError(f"unrecognized KRAKENGUARD verdict: {text[:200]}")

    stats: Dict[str, Any] = {
        "paths_explored": getattr(resp.execution, "paths_explored", None),
        "total_instructions": getattr(resp.execution, "total_instructions", None),
        "completed_paths": None,
        "total_queries": None,
    }
    info = out_dir / "info"
    if info.exists():
        completed_re = re.compile(r"^\\s*completed paths = (\\d+)\\s*$")
        queries_re = re.compile(r"^\\s*total queries = (\\d+)\\s*$")
        explored_re = re.compile(r"^\\s*explored paths = (\\d+)\\s*$")
        for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
            if match := completed_re.match(line):
                stats["completed_paths"] = int(match.group(1))
            elif match := queries_re.match(line):
                stats["total_queries"] = int(match.group(1))
            elif match := explored_re.match(line):
                if stats["paths_explored"] in (None, 0):
                    stats["paths_explored"] = int(match.group(1))

    return verdict, stats, text, out_dir


def invoke_symbolic(
    client: KrakenGuardClient,
    program: Dict[str, Any],
    policy: Path,
    timeout: int,
) -> Dict[str, Any]:
    """Time only verifier execution plus verdict extraction.

    Evidence archival is outside the timed interval so filesystem copying and
    serialization cannot inflate the verification-time endpoint.
    """
    response = None
    start = time.perf_counter_ns()
    try:
        response = client.verify(
            object_file=str(program["object_file"].resolve()),
            constraints_file=str(policy.resolve()),
            timeout=timeout,
        )
        verdict, stats, conditional, out_dir = extract_kg_result(response)
        status, error = "ok", None
    except Exception as exc:
        verdict, stats, conditional, out_dir = "TIMEOUT_OR_ERROR", {}, "", None
        status, error = "error", f"{type(exc).__name__}: {exc}"
    elapsed_us = (time.perf_counter_ns() - start) // 1000

    return {
        "status": status,
        "verdict": verdict,
        "wall_time_us": elapsed_us,
        "wall_time_ms": round(elapsed_us / 1000.0, 6),
        "klee": stats,
        "error": error,
        "response": response,
        "conditional": conditional,
        "out_dir": out_dir,
    }


def measure_symbolic(
    client: KrakenGuardClient,
    program: Dict[str, Any],
    policy: Path,
    timeout: int,
    run_id: str,
) -> Dict[str, Any]:
    """Run KRAKENGUARD and archive artifacts outside the timed interval."""
    raw = RAW_DIR / run_id
    raw.mkdir(parents=True, exist_ok=True)
    result = invoke_symbolic(client, program, policy, timeout)

    response = result.pop("response")
    conditional = result.pop("conditional")
    out_dir = result.pop("out_dir")

    if result["status"] == "ok" and response is not None:
        (raw / "response.json").write_text(
            json.dumps(response.to_dict(), indent=2), encoding="utf-8"
        )
        (raw / "conditional_policy.results.txt").write_text(
            conditional, encoding="utf-8"
        )
        (raw / "request.json").write_text(json.dumps({
            "request_id": getattr(response, "request_id", None),
            "program_id": program["program_id"],
            "object_sha256": program["object_sha256"],
            "policy_sha256": FROZEN_POLICY_SHA,
        }, indent=2), encoding="utf-8")
        for name in ("info", "messages.txt", "warnings.txt"):
            src = out_dir / name
            if src.exists():
                (raw / name).write_bytes(src.read_bytes())
    elif result["error"]:
        (raw / "error.txt").write_text(result["error"], encoding="utf-8")

    return result


def measure_abstract(program: Dict[str, Any], policy: Path, run_id: str) -> Dict[str, Any]:
    """Measure the analyzer in-process.

    The analyzer is the component being evaluated, so subprocess startup and
    JSON IPC overhead are excluded from the primary endpoint. The historical
    abstract_worker.py remains available as an auxiliary isolated-process probe.
    """
    raw = RAW_DIR / run_id
    raw.mkdir(parents=True, exist_ok=True)

    start_wall = time.perf_counter_ns()
    start_cpu = time.process_time_ns()
    child_cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        result = AbstractPolicyAnalyzer(
            str(program["object_file"]), str(policy)
        ).analyze()
        status = "ok"
        error = None
    except Exception as exc:
        result = {
            "verdict": "UNKNOWN",
            "discharged": False,
            "metrics": {},
            "proof": "",
        }
        status = "error"
        error = f"{type(exc).__name__}: {exc}"

    wall_us = (time.perf_counter_ns() - start_wall) // 1000
    parent_cpu_us = (time.process_time_ns() - start_cpu) // 1000
    child_cpu_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    child_cpu_us = int(
        (
            (child_cpu_end.ru_utime - child_cpu_start.ru_utime)
            + (child_cpu_end.ru_stime - child_cpu_start.ru_stime)
        )
        * 1_000_000
    )
    cpu_us = parent_cpu_us + child_cpu_us

    payload = {
        "status": status,
        "error": error,
        "verdict": result.get("verdict", "UNKNOWN"),
        "discharged": bool(result.get("discharged", False)),
        "proof": result.get("proof", ""),
        "metrics": result.get("metrics", {}),
        "wall_time_us": wall_us,
        "cpu_time_us": cpu_us,
        "parent_cpu_time_us": parent_cpu_us,
        "child_process_cpu_time_us": child_cpu_us,
    }
    (raw / "analysis.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    return {
        "status": status,
        "verdict": payload["verdict"],
        "discharged": payload["discharged"],
        "wall_time_us": wall_us,
        "analysis_wall_time_us": wall_us,
        "process_total_wall_time_us": wall_us,
        "cpu_time_us": cpu_us,
        "peak_abstract_rss_bytes": None,
        "metrics": payload["metrics"],
        "proof": payload["proof"],
        "error": error,
    }


def normalize(verdict: str) -> str:
    return {"SAFE": "COMPLIANT", "VIOLATION": "POLICY VIOLATION", "UNKNOWN": "UNKNOWN"}.get(verdict, "UNKNOWN")


def run_one(
    mode: str,
    program: Dict[str, Any],
    policy: Path,
    client: KrakenGuardClient,
    oracle: Dict[str, Dict[str, Any]],
    timeout: int,
    run_id: str,
) -> Dict[str, Any]:
    raw_run_dir = RAW_DIR / run_id
    raw_run_dir.mkdir(parents=True, exist_ok=True)
    abstract = None
    symbolic = None
    start = time.perf_counter_ns()

    if mode == "symbolic_only":
        symbolic = measure_symbolic(client, program, policy, timeout, run_id)
        final = symbolic["verdict"]
        route = "SYMBOLIC_ONLY"
        discharged = False
    elif mode == "abstract_only":
        abstract = measure_abstract(program, policy, run_id)
        final = normalize(abstract["verdict"])
        route = "ABSTRACT_ONLY"
        discharged = abstract["discharged"]
    else:
        abstract = measure_abstract(program, policy, run_id + "-abstract")
        if abstract["verdict"] == "SAFE":
            final, route, discharged = "COMPLIANT", "FAST_PATH_SAFE", True
        elif abstract["verdict"] == "VIOLATION":
            final, route, discharged = "POLICY VIOLATION", "FAST_PATH_VIOLATION", True
        else:
            route, discharged = "FALLBACK_SYMBOLIC", False
            symbolic = measure_symbolic(client, program, policy, timeout, run_id + "-symbolic")
            final = symbolic["verdict"]

    # Primary timing is the sum of measured verification sections. Raw evidence
    # archival happens after those sections and is intentionally excluded.
    if mode == "symbolic_only":
        total_elapsed = symbolic["wall_time_us"]
    elif mode == "abstract_only":
        total_elapsed = abstract["wall_time_us"]
    else:
        total_elapsed = abstract["wall_time_us"]
        if symbolic is not None:
            total_elapsed += symbolic["wall_time_us"]

    ref = oracle[program["program_id"]]["reference_verdict"]
    correctness = None if final == "UNKNOWN" else (final == ref)
    metrics: Dict[str, Any] = {}
    if abstract:
        metrics.update({f"abstract_{k}": v for k, v in abstract.get("metrics", {}).items()})
        metrics["abstract_analysis_wall_time_us"] = abstract.get("analysis_wall_time_us")
        metrics["abstract_process_total_wall_time_us"] = abstract.get("process_total_wall_time_us")
    if symbolic:
        metrics.update({f"klee_{k}": v for k, v in symbolic.get("klee", {}).items()})

    record = {
        "run_id": run_id,
        "mode": mode,
        "program_id": program["program_id"],
        "category": program["category"],
        "role": program["role"],
        "target_paths": program["target_paths"],
        "route": route,
        "discharged": discharged,
        "abstract_verdict": abstract["verdict"] if abstract else None,
        "final_verdict": final,
        "reference_verdict": ref,
        "verdict_correct": correctness,
        "fallback_invoked": route == "FALLBACK_SYMBOLIC",
        "status": (
            "ok"
            if final in ("COMPLIANT", "POLICY VIOLATION", "UNKNOWN")
            else "error"
        ),
        "wall_time_us": total_elapsed,
        "wall_time_ms": round(total_elapsed / 1000.0, 6),
        "abstract_wall_time_us": abstract.get("wall_time_us") if abstract else None,
        "abstract_analysis_wall_time_us": abstract.get("analysis_wall_time_us") if abstract else None,
        "abstract_cpu_time_us": abstract.get("cpu_time_us") if abstract else None,
        "peak_abstract_rss_bytes": abstract.get("peak_abstract_rss_bytes") if abstract else None,
        "symbolic_wall_time_us": symbolic.get("wall_time_us") if symbolic else None,
        "reference_manifest": oracle[program["program_id"]].get("reference_source"),
        "error": (symbolic or abstract or {}).get("error"),
        "object_sha256": program["object_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA,
        "krakenguard_commit": oracle[program["program_id"]]["krakenguard_commit"],
        "metrics": metrics,
    }
    (raw_run_dir / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def run_measurements(
    modes: List[str],
    programs: List[Dict[str, Any]],
    policy: Path,
    client: KrakenGuardClient,
    oracle: Dict[str, Dict[str, Any]],
    config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    warmups = int(config["measurement"]["warmups"])
    repetitions = int(config["measurement"]["repetitions"])
    timeout = int(config["measurement"]["timeout_seconds"])
    seed = int(config["measurement"]["seed"])
    rng = random.Random(seed)
    records: List[Dict[str, Any]] = []

    # Warmups are executed for every requested condition and are excluded from analysis.
    for w in range(1, warmups + 1):
        for mode in modes:
            jobs = [(mode, p) for p in programs]
            rng.shuffle(jobs)
            for mode_name, program in jobs:
                run_id = f"{mode_name}-{program['program_id']}-w{w:02d}"
                result = run_one(mode_name, program, policy, client, oracle, timeout, run_id)
                result.update({"repetition_type": "warmup", "repetition": w})
                records.append(result)

    # Fully randomized program/condition order for each measured repetition.
    for rep in range(1, repetitions + 1):
        jobs = [(mode, p) for mode in modes for p in programs]
        rng.shuffle(jobs)
        for mode_name, program in jobs:
            run_id = f"{mode_name}-{program['program_id']}-m{rep:02d}"
            result = run_one(mode_name, program, policy, client, oracle, timeout, run_id)
            result.update({"repetition_type": "measured", "repetition": rep})
            records.append(result)

    return records


def write_results(records: List[Dict[str, Any]], oracle: Dict[str, Dict[str, Any]], provenance: Dict[str, Any]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    (RESULTS_DIR / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    (RESULTS_DIR / "reference-verdicts.json").write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    (RESULTS_DIR / "runs.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8"
    )

    fields = [
        "run_id","mode","program_id","category","role","target_paths",
        "repetition_type","repetition","route","discharged",
        "abstract_verdict","final_verdict","reference_verdict","verdict_correct",
        "fallback_invoked","status","wall_time_us","wall_time_ms",
        "abstract_wall_time_us","abstract_analysis_wall_time_us","abstract_cpu_time_us",
        "peak_abstract_rss_bytes","symbolic_wall_time_us",
        "reference_manifest","error",
        "object_sha256","policy_sha256","krakenguard_commit","metrics"
    ]
    with (RESULTS_DIR / "runs.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["metrics"] = json.dumps(row.get("metrics", {}), sort_keys=True)
            writer.writerow({k: row.get(k) for k in fields})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    config = load_config()
    if args.warmups is not None:
        config["measurement"]["warmups"] = args.warmups
    if args.repetitions is not None:
        config["measurement"]["repetitions"] = args.repetitions
    if args.seed is not None:
        config["measurement"]["seed"] = args.seed

    programs = load_programs(config)
    provenance = preflight(config, programs)
    policy = ROOT / config["corpus"]["policy_file"]

    client = KrakenGuardClient(os.path.relpath(BASELINE_DIR / "socket" / "krakenguard.sock", Path.cwd()))
    health = client.health()
    if getattr(health, "status", None) != "success":
        raise RuntimeError(f"KRAKENGUARD health check failed: {health.to_dict()}")

    oracle = load_reference_verdicts(config, programs)

    modes = list(MODES) if args.mode == "all" else [args.mode]
    records = run_measurements(modes, programs, policy, client, oracle, config)
    write_results(records, oracle, provenance)

    measured_ok = sum(r["repetition_type"] == "measured" and r["status"] == "ok" for r in records)
    print(json.dumps({
        "status": "completed",
        "branch": provenance["repo_branch"],
        "modes": modes,
        "programs": len(programs),
        "warmups_per_mode": config["measurement"]["warmups"],
        "measured_repetitions_per_mode": config["measurement"]["repetitions"],
        "measured_runs": len(programs) * int(config["measurement"]["repetitions"]) * len(modes),
        "successful_measured_runs": measured_ok,
        "output": "work/results/runs.csv",
    }, indent=2))


if __name__ == "__main__":
    main()
