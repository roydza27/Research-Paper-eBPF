#!/usr/bin/env python3
"""Execute the controlled time-scaling campaign for the generated corpus."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work"
RUNTIME = WORK / "scaling" / "runtime"
CORPUS = RUNTIME / "corpus"
RESULTS = RUNTIME / "time-results"
RAW = RESULTS / "raw"
CONFIG = WORK / "comparison-config.json"

import sys
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(ROOT / "research" / "baselines" / "krakenguard" / "artifact"))

from daemon.krakenguard_client import KrakenGuardClient
from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer

FROZEN_POLICY_SHA = "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"
FROZEN_KG_COMMIT = "e7bd84005b304c5a10efcdb04914d1882b3cccf7"
FROZEN_DIGEST = "kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4"
POLICY = ROOT / "research" / "experiments" / "corpus" / "phase5" / "policies" / "phase5_policy.json"
SOCKET = ROOT / "research" / "baselines" / "krakenguard" / "artifact" / "socket" / "krakenguard.sock"
KG_IMAGE = "kg-artifact-krakenguard:latest"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def checked(cmd: List[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"command failed: {' '.join(cmd)}: {p.stderr.strip()}")
    return p.stdout.strip()


def preflight() -> Dict[str, Any]:
    if sha256(POLICY) != FROZEN_POLICY_SHA:
        raise RuntimeError("frozen policy SHA mismatch")
    if platform.machine() != "x86_64":
        raise RuntimeError("scaling experiment requires x86_64")
    if not SOCKET.exists():
        raise RuntimeError(f"KRAKENGUARD socket missing: {SOCKET}")
    kg_commit = checked(["git", "-C", str(ROOT / "research" / "baselines" / "krakenguard" / "artifact"), "rev-parse", "HEAD"])
    if kg_commit != FROZEN_KG_COMMIT:
        raise RuntimeError("KRAKENGUARD commit mismatch")
    digests = json.loads(checked(["docker","image","inspect",KG_IMAGE,"--format","{{json .RepoDigests}}"]))
    if FROZEN_DIGEST not in digests:
        raise RuntimeError("frozen KRAKENGUARD container digest missing")
    if not (CORPUS / "manifest.json").exists():
        raise RuntimeError("generated corpus missing; run generate_scaling_corpus.py first")
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repo_branch": checked(["git","-C",str(ROOT),"branch","--show-current"]),
        "repo_head": checked(["git","-C",str(ROOT),"rev-parse","HEAD"]),
        "repo_tree": checked(["git","-C",str(ROOT),"rev-parse","HEAD^{tree}"]),
        "krakenguard_commit": kg_commit,
        "container_digest": FROZEN_DIGEST,
        "policy_sha256": FROZEN_POLICY_SHA,
        "kernel": platform.release(),
        "compiler": checked(["clang","--version"]).splitlines()[0],
        "architecture": platform.machine(),
        "cpu_model": next((x.split(":",1)[1].strip() for x in checked(["lscpu"]).splitlines() if x.startswith("Model name:")), "unknown"),
    }


def load_rows() -> List[Dict[str, Any]]:
    with (CORPUS / "metadata.csv").open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise RuntimeError("empty scaling corpus")
    for row in rows:
        row["scale"] = int(row["scale"])
        row["target_paths"] = int(row["target_paths"])
        row["instructions"] = int(row["instructions"])
        row["branches"] = int(row["branches"])
    return rows


def kg_invoke(client: KrakenGuardClient, obj: Path, timeout: int, run_dir: Path) -> Dict[str, Any]:
    start = time.perf_counter_ns()
    try:
        resp = client.verify(object_file=str(obj.resolve()), constraints_file=str(POLICY.resolve()), timeout=timeout)
        out_dir = Path((getattr(resp.output, "directory", "") or "").replace(
            "/data", str(ROOT / "research" / "baselines" / "krakenguard" / "artifact" / "data")
        ))
        cond = out_dir / "conditional_policy.results.txt"
        text = cond.read_text(encoding="utf-8", errors="replace") if cond.exists() else ""
        if "Status: POLICY VIOLATIONS DETECTED" in text:
            verdict = "POLICY VIOLATION"
        elif "Status: NO VIOLATIONS" in text:
            verdict = "COMPLIANT"
        else:
            verdict = "UNKNOWN"
        info = {}
        infof = out_dir / "info"
        if infof.exists():
            for line in infof.read_text(errors="replace").splitlines():
                for key, pat in [
                    ("completed_paths", r"^\s*KLEE:\s*done:\s*completed paths = (\d+)\s*$"),
                    ("total_queries", r"^\s*KLEE:\s*done:\s*total queries = (\d+)\s*$"),
                    ("explored_paths", r"^\s*KLEE:\s*done:\s*explored paths = (\d+)\s*$"),
                ]:
                    m = re.match(pat, line)
                    if m:
                        info[key] = int(m.group(1))
        status = "ok"
        error = None
    except Exception as exc:
        verdict, info, status = "ERROR", {}, "error"
        error = f"{type(exc).__name__}: {exc}"
    elapsed = (time.perf_counter_ns() - start) // 1000

    # Evidence archival is intentionally outside the timed section.
    try:
        if status == "ok":
            if cond.exists():
                shutil.copyfile(cond, run_dir / "conditional_policy.results.txt")
            if infof.exists():
                shutil.copyfile(infof, run_dir / "info")
    except Exception as exc:
        status = "error"
        error = f"archive failure: {type(exc).__name__}: {exc}"

    return {"status": status, "verdict": verdict, "wall_time_us": elapsed, "klee": info, "error": error}


def abstract_invoke(obj: Path, run_dir: Path) -> Dict[str, Any]:
    start = time.perf_counter_ns()
    try:
        res = AbstractPolicyAnalyzer(str(obj), str(POLICY)).analyze()
        status, error = "ok", None
    except Exception as exc:
        res = {"verdict":"UNKNOWN","discharged":False,"metrics":{}}
        status, error = "error", f"{type(exc).__name__}: {exc}"
    elapsed = (time.perf_counter_ns() - start) // 1000
    (run_dir / "analysis.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return {
        "status": status,
        "verdict": res.get("verdict","UNKNOWN"),
        "discharged": bool(res.get("discharged",False)),
        "wall_time_us": elapsed,
        "metrics": res.get("metrics", {}),
        "error": error
    }


def run_one(mode: str, row: Dict[str, Any], client: KrakenGuardClient, timeout: int, run_id: str) -> Dict[str, Any]:
    run_dir = RAW / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    obj = ROOT / row["object_file"]
    expected = row["expected_verdict"]

    abstract = None
    symbolic = None

    if mode == "symbolic_only":
        symbolic = kg_invoke(client, obj, timeout, run_dir)
        final = symbolic["verdict"]
        route = "SYMBOLIC_ONLY"
    elif mode == "abstract_only":
        abstract = abstract_invoke(obj, run_dir)
        final = {"SAFE":"COMPLIANT","VIOLATION":"POLICY VIOLATION","UNKNOWN":"UNKNOWN"}.get(abstract["verdict"],"UNKNOWN")
        route = "ABSTRACT_ONLY"
    else:
        abstract = abstract_invoke(obj, run_dir / Path("abstract") if False else run_dir)
        if abstract["verdict"] == "UNKNOWN":
            symbolic = kg_invoke(client, obj, timeout, run_dir / Path("symbolic") if False else run_dir)
            final = symbolic["verdict"]
            route = "FALLBACK_SYMBOLIC"
        elif abstract["verdict"] == "SAFE":
            final, route = "COMPLIANT", "FAST_PATH_SAFE"
        else:
            final, route = "POLICY VIOLATION", "FAST_PATH_VIOLATION"

    total_us = (abstract["wall_time_us"] if abstract else 0) + (symbolic["wall_time_us"] if symbolic else 0)
    return {
        "run_id": run_id,
        "mode": mode,
        "program_id": row["program_id"],
        "family": row["family"],
        "scale": row["scale"],
        "target_paths": row["target_paths"],
        "instructions": row["instructions"],
        "branches": row["branches"],
        "helpers": row["helpers"],
        "expected_verdict": expected,
        "abstract_verdict": abstract["verdict"] if abstract else "",
        "final_verdict": final,
        "route": route,
        "fallback_invoked": route == "FALLBACK_SYMBOLIC",
        "status": "ok" if final in ("COMPLIANT","POLICY VIOLATION","UNKNOWN") else "error",
        "wall_time_us": total_us,
        "wall_time_ms": total_us / 1000.0,
        "symbolic_wall_time_us": symbolic["wall_time_us"] if symbolic else None,
        "abstract_wall_time_us": abstract["wall_time_us"] if abstract else None,
        "klee_paths_explored": (symbolic or {}).get("klee",{}).get("paths_explored"),
        "klee_completed_paths": (symbolic or {}).get("klee",{}).get("completed_paths"),
        "klee_total_queries": (symbolic or {}).get("klee",{}).get("total_queries"),
        "verdict_correct": final == expected if final != "UNKNOWN" else None,
        "object_sha256": row["object_sha256"],
        "source_sha256": row["source_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA,
        "krakenguard_commit": FROZEN_KG_COMMIT,
        "error": (symbolic or abstract or {}).get("error"),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--warmups", type=int, default=2)
    p.add_argument("--repetitions", type=int, default=7)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--mode", choices=["all","symbolic_only","abstract_only","hybrid"], default="all")
    args = p.parse_args()

    prov = preflight()
    rows = load_rows()
    RESULTS.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    client = KrakenGuardClient(os.path.relpath(SOCKET, Path.cwd()))

    modes = ["symbolic_only","abstract_only","hybrid"] if args.mode == "all" else [args.mode]
    rng = random.Random(args.seed)
    records: List[Dict[str, Any]] = []

    jobs = [(m,r) for m in modes for r in rows]
    # Warmups: randomized jobs per round and excluded from statistics.
    for w in range(1, args.warmups+1):
        jobs = [(m,r) for m in modes for r in rows]
        rng.shuffle(jobs)
        for m,r in jobs:
            rec = run_one(m,r,client,args.timeout,f"{m}-{r['program_id']}-w{w:02d}")
            rec.update({"repetition_type":"warmup","repetition":w})
            records.append(rec)

    for rep in range(1, args.repetitions+1):
        jobs = [(m,r) for m in modes for r in rows]
        rng.shuffle(jobs)
        for m,r in jobs:
            rec = run_one(m,r,client,args.timeout,f"{m}-{r['program_id']}-m{rep:02d}")
            rec.update({"repetition_type":"measured","repetition":rep})
            records.append(rec)

    (RESULTS / "provenance.json").write_text(json.dumps({
        **prov, "seed": args.seed, "warmups": args.warmups,
        "repetitions": args.repetitions, "timeout": args.timeout,
        "program_count": len(rows), "measured_runs": len(rows)*len(modes)*args.repetitions
    }, indent=2), encoding="utf-8")

    fields = list(records[0].keys())
    with (RESULTS / "runs.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader(); w.writerows(records)
    (RESULTS / "runs.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in records), encoding="utf-8"
    )
    print(json.dumps({
        "status":"completed",
        "programs":len(rows),
        "modes":modes,
        "total_runs":len(records),
        "measured_runs":len(rows)*len(modes)*args.repetitions,
        "results":str((RESULTS / "runs.csv").relative_to(ROOT))
    }, indent=2))


if __name__ == "__main__":
    main()
