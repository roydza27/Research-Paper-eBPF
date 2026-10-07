#!/usr/bin/env python3
"""Comparative benchmark for symbolic-only, abstract-only, and hybrid verification.

This workbench deliberately lives outside the authoritative Phase 5 result tree.
It creates fresh evidence under work/results/ only.
"""

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
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "work" / "comparison-config.json"
WORK_DIR = ROOT / "work"
RESULTS_DIR = WORK_DIR / "results"
RAW_DIR = RESULTS_DIR / "raw"
ABSTRACT_WORKER = WORK_DIR / "abstract_worker.py"

sys.path.insert(0, str(ROOT / "research"))
BASELINE_DIR = ROOT / "research" / "baselines" / "krakenguard" / "artifact"
sys.path.insert(0, str(BASELINE_DIR))

from daemon.krakenguard_client import KrakenGuardClient


MODES = ("symbolic_only", "abstract_only", "hybrid")


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(cmd: List[str], cwd: Optional[Path] = None) -> str:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def parse_cpu_model() -> str:
    try:
        return run_checked(["lscpu"]).split("Model name:", 1)[1].splitlines()[0].strip()
    except Exception:
        return platform.processor() or "unknown"


def load_programs(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = ROOT / config["corpus"]["metadata_csv"]
    programs_dir = ROOT / config["corpus"]["programs_dir"]
    rows: List[Dict[str, Any]] = []
    with metadata.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            program_id = row.get("program_id") or Path(row["object_file"]).stem
            object_file = programs_dir / row["object_file"]
            if not object_file.exists():
                raise FileNotFoundError(f"missing object for {program_id}: {object_file}")
            rows.append({
                "program_id": program_id,
                "category": row.get("category", ""),
                "role": row.get("role", ""),
                "target_paths": int(row["target_paths"]) if row.get("target_paths") else None,
                "object_file": object_file,
                "object_sha256": sha256_file(object_file),
                "description": row.get("description") or row.get("desc") or "",
            })
    if not rows:
        raise RuntimeError("metadata.csv produced no programs")
    return rows


def preflight(config: Dict[str, Any], programs: List[Dict[str, Any]]) -> Dict[str, Any]:
    policy = ROOT / config["corpus"]["policy_file"]
    artifact = ROOT / config["krakenguard"]["artifact_dir"]
    socket = ROOT / config["krakenguard"]["socket"]

    observed = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repo_head": run_checked(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "repo_tree": run_checked(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"]),
        "repo_branch": run_checked(["git", "-C", str(ROOT), "branch", "--show-current"]),
        "krakenguard_commit": run_checked(["git", "-C", str(artifact), "rev-parse", "HEAD"]),
        "policy_sha256": sha256_file(policy),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu_model": parse_cpu_model(),
        "compiler_version": run_checked(["clang", "--version"]).splitlines()[0],
    }

    expected = config["krakenguard"]["commit"]
    if observed["krakenguard_commit"] != expected:
        raise RuntimeError(f"KRAKENGUARD commit mismatch: {observed['krakenguard_commit']} != {expected}")
    if observed["policy_sha256"] != config["krakenguard"]["commit"] and False:
        raise AssertionError("unreachable")
    if observed["policy_sha256"] != "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603":
        raise RuntimeError("policy SHA does not match frozen Phase 5/E1 policy")
    env_cfg = config["environment"]
    if observed["architecture"] != env_cfg["architecture"]:
        raise RuntimeError(f"architecture mismatch: {observed['architecture']} != {env_cfg['architecture']}")
    if observed["kernel"] != env_cfg["kernel"]:
        raise RuntimeError(f"kernel mismatch: {observed['kernel']} != {env_cfg['kernel']}")
    if env_cfg["compiler_version"] not in observed["compiler_version"]:
        raise RuntimeError(f"compiler mismatch: {observed['compiler_version']}")

    if not socket.exists():
        raise RuntimeError(f"KRAKENGUARD socket not found: {socket}")

    digest_text = ""
    try:
        digest_text = run_checked([
            "docker", "image", "inspect",
            config["krakenguard"]["container_image"],
            "--format", "{{json .RepoDigests}}"
        ])
        digests = json.loads(digest_text)
        if config["krakenguard"]["container_digest"] not in digests:
            raise RuntimeError(f"container digest not found in docker inspect: {digests}")
    except FileNotFoundError:
        raise RuntimeError("docker is required for frozen KRAKENGUARD resource measurement")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"docker preflight failed: {exc}") from exc

    observed["program_count"] = len(programs)
    observed["frozen_controls"] = {
        "container_digest": config["krakenguard"]["container_digest"],
        "hook": config["environment"]["hook"],
        "seed": config["measurement"]["seed"],
        "warmups": config["measurement"]["warmups"],
        "repetitions": config["measurement"]["repetitions"],
        "timeout_seconds": config["measurement"]["timeout_seconds"],
    }
    return observed


def extract_reference(resp: Any, artifact_dir: Path) -> Tuple[str, Dict[str, Any], str]:
    if getattr(resp.execution, "return_code", 0) != 0:
        stderr = getattr(resp.output, "stderr", "") or ""
        raise RuntimeError(f"KRAKENGUARD return code {resp.execution.return_code}: {stderr[:500]}")

    out_dir = getattr(resp.output, "directory", "") or ""
    host_out = Path(out_dir.replace("/data", str(artifact_dir / "data")))
    conditional = host_out / "conditional_policy.results.txt"
    if not conditional.exists():
        raise RuntimeError(f"missing mandatory verdict artifact: {conditional}")
    text = conditional.read_text(encoding="utf-8", errors="replace").strip()
    if "Status: POLICY VIOLATIONS DETECTED" in text:
        verdict = "POLICY VIOLATION"
    elif "Status: NO VIOLATIONS" in text:
        verdict = "COMPLIANT"
    else:
        raise RuntimeError(f"unrecognized KRAKENGUARD status: {text[:200]}")

    info = host_out / "info"
    stats = {
        "paths_explored": getattr(resp.execution, "paths_explored", None),
        "total_instructions": getattr(resp.execution, "total_instructions", None),
        "completed_paths": None,
        "total_queries": None,
    }
    if info.exists():
        for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
            if "completed paths =" in line:
                stats["completed_paths"] = int(line.split("=", 1)[1].strip())
            elif "total queries =" in line:
                stats["total_queries"] = int(line.split("=", 1)[1].strip())
            elif "explored paths =" in line and stats["paths_explored"] in (None, 0):
                stats["paths_explored"] = int(line.split("=", 1)[1].strip())

    return verdict, stats, text


def docker_container_ids() -> List[str]:
    try:
        raw = run_checked(
            ["docker", "compose", "ps", "-q"],
            cwd=BASELINE_DIR
        )
    except Exception:
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]


def docker_stats(container_ids: List[str]) -> List[Dict[str, Any]]:
    if not container_ids:
        return []
    proc = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.ID}}|{{.Name}}|{{.MemUsage}}", *container_ids],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        return []
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        rows.append({
            "container_id": parts[0],
            "container_name": parts[1],
            "memory": parts[2]
        })
    return rows


_UNIT_FACTORS = {
    "b": 1,
    "kb": 1000,
    "kib": 1024,
    "mb": 1000**2,
    "mib": 1024**2,
    "gb": 1000**3,
    "gib": 1024**3,
}


def parse_memory_usage(text: str) -> Optional[int]:
    left = text.split("/", 1)[0].strip()
    match = re.match(r"^([0-9.]+)\s*([A-Za-z]+)$", left)
    if not match:
        return None
    number = float(match.group(1))
    factor = _UNIT_FACTORS.get(match.group(2).lower())
    return int(number * factor) if factor else None


def measure_abstract(object_file: Path, policy_file: Path, run_id: str) -> Dict[str, Any]:
    raw_run = RAW_DIR / run_id
    raw_run.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter_ns()
    proc = subprocess.run(
        [sys.executable, str(ABSTRACT_WORKER), "--object", str(object_file), "--policy", str(policy_file)],
        capture_output=True, text=True
    )
    end = time.perf_counter_ns()

    (raw_run / "abstract.stdout").write_text(proc.stdout, encoding="utf-8")
    (raw_run / "abstract.stderr").write_text(proc.stderr, encoding="utf-8")

    if proc.returncode != 0:
        return {
            "status": "worker_failed",
            "verdict": "UNKNOWN",
            "discharged": False,
            "wall_time_us": (end - start) // 1000,
            "cpu_time_us": None,
            "peak_rss_bytes": None,
            "error": f"worker exit {proc.returncode}",
            "metrics": {},
        }

    try:
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        return {
            "status": "worker_invalid_output",
            "verdict": "UNKNOWN",
            "discharged": False,
            "wall_time_us": (end - start) // 1000,
            "cpu_time_us": None,
            "peak_rss_bytes": None,
            "error": f"invalid worker JSON: {exc}",
            "metrics": {},
        }

    return {
        "status": payload.get("status", "unknown"),
        "verdict": payload.get("verdict", "UNKNOWN"),
        "discharged": bool(payload.get("discharged", False)),
        "wall_time_us": int(payload.get("wall_time_us", (end - start) // 1000)),
        "process_total_wall_time_us": (end - start) // 1000,
        "cpu_time_us": payload.get("cpu_time_us"),
        "peak_rss_bytes": payload.get("peak_rss_bytes"),
        "error": payload.get("error"),
        "metrics": payload.get("metrics", {}),
        "proof": payload.get("proof", ""),
    }


def measure_symbolic(
    client: KrakenGuardClient,
    object_file: Path,
    policy_file: Path,
    artifact_dir: Path,
    run_id: str,
    timeout_seconds: int,
) -> Dict[str, Any]:
    raw_run = RAW_DIR / run_id
    raw_run.mkdir(parents=True, exist_ok=True)

    container_ids = docker_container_ids()
    peak_memory = None
    samples = []
    start = time.perf_counter_ns()
    try:
        resp = client.verify(
            object_file=str(object_file.resolve()),
            constraints_file=str(policy_file.resolve()),
            timeout=timeout_seconds,
        )
        verdict, stats, conditional_text = extract_reference(resp, artifact_dir)
        status = "ok"
        error = None
        response_payload = resp.to_dict()
        request_id = getattr(resp, "request_id", None)
        (raw_run / "response.json").write_text(json.dumps(response_payload, indent=2), encoding="utf-8")
        (raw_run / "conditional_policy.results.txt").write_text(conditional_text, encoding="utf-8")
        for filename in ("info", "messages.txt", "warnings.txt"):
            out_dir = Path((getattr(resp.output, "directory", "") or "").replace("/data", str(artifact_dir / "data")))
            source = out_dir / filename
            if source.exists():
                (raw_run / filename).write_bytes(source.read_bytes())
    except Exception as exc:
        verdict = "TIMEOUT_OR_ERROR"
        stats = {}
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
        response_payload = None
        request_id = None
    finally:
        end = time.perf_counter_ns()
        try:
            for sample in docker_stats(container_ids):
                mem = parse_memory_usage(sample["memory"])
                if mem is not None:
                    samples.append(mem)
            if samples:
                peak_memory = max(samples)
        except Exception:
            pass

    (raw_run / "request.json").write_text(json.dumps({
        "program_object": str(object_file),
        "policy_file": str(policy_file),
        "request_id": request_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")

    return {
        "status": status,
        "verdict": verdict,
        "request_id": request_id,
        "wall_time_us": (end - start) // 1000,
        "cpu_time_us": None,
        "peak_rss_bytes": None,
        "peak_kg_container_memory_bytes": peak_memory,
        "klee": stats,
        "error": error,
    }


def run_oracle(client: KrakenGuardClient, programs: List[Dict[str, Any]], policy_file: Path, artifact_dir: Path, timeout: int) -> Dict[str, Dict[str, Any]]:
    oracle = {}
    oracle_dir = RESULTS_DIR / "oracle"
    oracle_dir.mkdir(parents=True, exist_ok=True)

    for program in programs:
        start = time.perf_counter_ns()
        resp = client.verify(
            object_file=str(program["object_file"].resolve()),
            constraints_file=str(policy_file.resolve()),
            timeout=timeout,
        )
        elapsed = (time.perf_counter_ns() - start) // 1000
        verdict, stats, conditional_text = extract_reference(resp, artifact_dir)
        entry = {
            "program_id": program["program_id"],
            "reference_verdict": verdict,
            "reference_duration_us": elapsed,
            "klee": stats,
            "request_id": getattr(resp, "request_id", None),
        }
        oracle[program["program_id"]] = entry
        (oracle_dir / f'{program["program_id"]}.json').write_text(json.dumps({
            **entry, "conditional_policy_results": conditional_text
        }, indent=2), encoding="utf-8")
    return oracle


def normalize_abstract(verdict: str) -> str:
    return {
        "SAFE": "COMPLIANT",
        "VIOLATION": "POLICY VIOLATION",
        "UNKNOWN": "UNKNOWN",
    }.get(verdict, "UNKNOWN")


def run_mode(
    mode: str,
    programs: List[Dict[str, Any]],
    oracle: Dict[str, Dict[str, Any]],
    client: KrakenGuardClient,
    policy_file: Path,
    artifact_dir: Path,
    warmups: int,
    repetitions: int,
    timeout: int,
    seed: int,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    order_rng = random.Random(seed)
    sequence = 0

    for repetition_type, rep in [("warmup", i) for i in range(1, warmups + 1)] + [("measured", i) for i in range(1, repetitions + 1)]:
        pairs = []
        for program in programs:
            modes = [mode]
            pairs.append((program, modes))
        order_rng.shuffle(pairs)

        for program, _ in pairs:
            sequence += 1
            pid = program["program_id"]
            run_id = f"{mode}-{pid}-{'w' if repetition_type == 'warmup' else 'm'}{rep:02d}"
            abstract = None
            symbolic = None
            route = mode

            if mode == "symbolic_only":
                symbolic = measure_symbolic(client, program["object_file"], policy_file, artifact_dir, run_id, timeout)
                final_verdict = symbolic["verdict"]
                discharged = False
                wall_us = symbolic["wall_time_us"]
                cpu_us = None
                peak_rss = None
                peak_kg = symbolic.get("peak_kg_container_memory_bytes")
                status = symbolic["status"]
                error = symbolic.get("error")
                metrics = symbolic.get("klee", {})
            elif mode == "abstract_only":
                abstract = measure_abstract(program["object_file"], policy_file, run_id)
                final_verdict = normalize_abstract(abstract["verdict"])
                discharged = bool(abstract["discharged"])
                wall_us = abstract["wall_time_us"]
                cpu_us = abstract.get("cpu_time_us")
                peak_rss = abstract.get("peak_rss_bytes")
                peak_kg = None
                status = abstract["status"]
                error = abstract.get("error")
                metrics = abstract.get("metrics", {})
            else:
                start = time.perf_counter_ns()
                abstract = measure_abstract(program["object_file"], policy_file, f"{run_id}-abstract")
                if abstract["verdict"] == "SAFE":
                    route = "FAST_PATH_SAFE"
                    final_verdict = "COMPLIANT"
                    discharged = True
                    symbolic = None
                elif abstract["verdict"] == "VIOLATION":
                    route = "FAST_PATH_VIOLATION"
                    final_verdict = "POLICY VIOLATION"
                    discharged = True
                    symbolic = None
                else:
                    route = "FALLBACK_SYMBOLIC"
                    symbolic = measure_symbolic(
                        client, program["object_file"], policy_file, artifact_dir, f"{run_id}-symbolic", timeout
                    )
                    final_verdict = symbolic["verdict"]
                    discharged = False
                wall_us = (time.perf_counter_ns() - start) // 1000
                cpu_us = abstract.get("cpu_time_us")
                peak_rss = abstract.get("peak_rss_bytes")
                peak_kg = symbolic.get("peak_kg_container_memory_bytes") if symbolic else None
                status = "ok" if final_verdict in ("COMPLIANT", "POLICY VIOLATION") else "error"
                error = None if status == "ok" else (symbolic or abstract).get("error")
                metrics = {}
                metrics.update(abstract.get("metrics", {}))
                if symbolic:
                    metrics.update({f"klee_{k}": v for k, v in symbolic.get("klee", {}).items()})

            reference = oracle[pid]
            expected = reference["reference_verdict"]
            verdict_check = final_verdict == expected
            if mode == "abstract_only" and final_verdict == "UNKNOWN":
                verdict_check = None

            raw_record = {
                "run_id": run_id,
                "sequence": sequence,
                "mode": mode,
                "program_id": pid,
                "category": program["category"],
                "role": program["role"],
                "target_paths": program["target_paths"],
                "repetition_type": repetition_type,
                "repetition": rep,
                "wall_time_us": wall_us,
                "wall_time_ms": round(wall_us / 1000.0, 6),
                "cpu_time_us": cpu_us,
                "peak_abstract_rss_bytes": peak_rss,
                "peak_krakenguard_container_memory_bytes": peak_kg,
                "abstract_verdict": abstract["verdict"] if abstract else None,
                "abstract_discharged": discharged if abstract else None,
                "route": route,
                "final_verdict": final_verdict,
                "reference_verdict": expected,
                "verdict_correct": verdict_check,
                "fallback_invoked": route == "FALLBACK_SYMBOLIC",
                "status": status,
                "error": error,
                "metrics": metrics,
                "object_sha256": program["object_sha256"],
                "policy_sha256": "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603",
                "krakenguard_commit": oracle[pid].get("krakenguard_commit"),
            }
            results.append(raw_record)
            (RAW_DIR / run_id / "run.json").write_text(json.dumps(raw_record, indent=2), encoding="utf-8")

    return results


def start_client() -> KrakenGuardClient:
    socket = BASELINE_DIR / "socket" / "krakenguard.sock"
    client = KrakenGuardClient(os.path.relpath(socket, Path.cwd()))
    health = client.health()
    if getattr(health, "status", None) != "success":
        raise RuntimeError(f"KRAKENGUARD health check failed: {health.to_dict()}")
    return client


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["symbolic_only", "abstract_only", "hybrid", "all"], default="all")
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    config = load_config()
    policy_file = ROOT / config["corpus"]["policy_file"]
    programs = load_programs(config)
    env = preflight(config, programs)

    warmups = args.warmups if args.warmups is not None else config["measurement"]["warmups"]
    repetitions = args.repetitions if args.repetitions is not None else config["measurement"]["repetitions"]
    seed = args.seed if args.seed is not None else config["measurement"]["seed"]
    timeout = int(config["measurement"]["timeout_seconds"])

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "provenance.json").write_text(json.dumps(env, indent=2), encoding="utf-8")

    client = start_client()
    oracle = run_oracle(client, programs, policy_file, BASELINE_DIR, timeout)

    requested = list(MODES) if args.mode == "all" else [args.mode]
    all_results: List[Dict[str, Any]] = []
    for mode in requested:
        all_results.extend(run_mode(
            mode, programs, oracle, client, policy_file, BASELINE_DIR,
            warmups, repetitions, timeout, seed
        ))

    out_csv = RESULTS_DIR / "runs.csv"
    fields = [
        "run_id","sequence","mode","program_id","category","role","target_paths",
        "repetition_type","repetition","wall_time_us","wall_time_ms","cpu_time_us",
        "peak_abstract_rss_bytes","peak_krakenguard_container_memory_bytes",
        "abstract_verdict","abstract_discharged","route","final_verdict",
        "reference_verdict","verdict_correct","fallback_invoked","status","error",
        "object_sha256","policy_sha256","krakenguard_commit","metrics"
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in all_results:
            row = dict(row)
            row["metrics"] = json.dumps(row["metrics"], sort_keys=True)
            writer.writerow({key: row.get(key) for key in fields})

    (RESULTS_DIR / "oracle.json").write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    (RESULTS_DIR / "runs.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in all_results),
        encoding="utf-8"
    )

    print(json.dumps({
        "status": "completed",
        "modes": requested,
        "programs": len(programs),
        "warmups_per_mode": warmups,
        "measured_repetitions_per_mode": repetitions,
        "measured_runs": len(programs) * repetitions * len(requested),
        "results_csv": str(out_csv.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
