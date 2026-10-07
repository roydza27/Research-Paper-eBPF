#!/usr/bin/env python3
"""Measure peak memory for the scaling corpus in a separate campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work"
RUNTIME = WORK / "scaling" / "runtime"
CORPUS = RUNTIME / "corpus"
RESULTS = RUNTIME / "space-results"
RAW = RESULTS / "raw"
POLICY = ROOT / "research" / "experiments" / "corpus" / "phase5" / "policies" / "phase5_policy.json"
KG_ARTIFACT = ROOT / "research" / "baselines" / "krakenguard" / "artifact"
SOCKET = KG_ARTIFACT / "socket" / "krakenguard.sock"
KG_IMAGE = "kg-artifact-krakenguard:latest"

FROZEN_POLICY_SHA = "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"
FROZEN_KG_COMMIT = "e7bd84005b304c5a10efcdb04914d1882b3cccf7"
FROZEN_DIGEST = "kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4"

import sys
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(KG_ARTIFACT))

from daemon.krakenguard_client import KrakenGuardClient


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


def kg_container_cgroup() -> Path:
    pid = int(checked(["docker", "inspect", KG_IMAGE, "--format", "{{.State.Pid}}"]))
    if pid <= 0:
        raise RuntimeError("KRAKENGUARD container does not have a running PID")
    text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    line = next((x for x in text.splitlines() if x.startswith("0::")), None)
    if not line:
        raise RuntimeError("host is not exposing a unified cgroup-v2 path for KRAKENGUARD")
    rel = line.split("0::", 1)[1].lstrip("/")
    cg = Path("/sys/fs/cgroup") / rel
    peak = cg / "memory.peak"
    current = cg / "memory.current"
    if not peak.exists() or not current.exists():
        raise RuntimeError(f"memory.peak/current unavailable in {cg}")
    return cg


def reset_peak(cg: Path) -> Tuple[int, str]:
    current = int((cg / "memory.current").read_text().strip())
    # cgroup-v2 memory.peak is reset by writing any non-empty value.
    with (cg / "memory.peak").open("w") as fh:
        fh.write("0")
    after = int((cg / "memory.peak").read_text().strip())
    return current, "reset_ok" if after <= current else "reset_unverified"


def peak(cg: Path) -> int:
    return int((cg / "memory.peak").read_text().strip())


def worker_abstract(obj: Path, run_dir: Path) -> Dict[str, Any]:
    cmd = [
        sys.executable, str(WORK / "abstract_worker.py"),
        "--object", str(obj.resolve()),
        "--policy", str(POLICY.resolve()),
    ]
    p = subprocess.run(cmd, text=True, capture_output=True)
    (run_dir / "abstract.stdout").write_text(p.stdout, encoding="utf-8")
    (run_dir / "abstract.stderr").write_text(p.stderr, encoding="utf-8")
    if p.returncode:
        raise RuntimeError(f"abstract worker failed: {p.stderr.strip()}")
    payload = json.loads(p.stdout.strip().splitlines()[-1])
    return payload


def kg_once(client: KrakenGuardClient, obj: Path, timeout: int, cg: Path, run_dir: Path) -> Dict[str, Any]:
    baseline, reset_status = reset_peak(cg)
    start = time.perf_counter_ns()
    try:
        resp = client.verify(
            object_file=str(obj.resolve()),
            constraints_file=str(POLICY.resolve()),
            timeout=timeout,
        )
        out_dir = Path((getattr(resp.output, "directory", "") or "").replace(
            "/data", str(KG_ARTIFACT / "data")
        ))
        cond = out_dir / "conditional_policy.results.txt"
        verdict_text = cond.read_text(encoding="utf-8", errors="replace") if cond.exists() else ""
        if "Status: POLICY VIOLATIONS DETECTED" in verdict_text:
            verdict = "POLICY VIOLATION"
        elif "Status: NO VIOLATIONS" in verdict_text:
            verdict = "COMPLIANT"
        else:
            verdict = "UNKNOWN"
        status = "ok"
        error = None
    except Exception as exc:
        verdict = "ERROR"
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
    elapsed_us = (time.perf_counter_ns() - start) // 1000
    peak_bytes = peak(cg)
    (run_dir / "memory.json").write_text(json.dumps({
        "cgroup": str(cg),
        "baseline_memory_current_bytes": baseline,
        "peak_memory_bytes": peak_bytes,
        "incremental_peak_bytes": max(0, peak_bytes - baseline),
        "reset_status": reset_status,
        "verification_wall_time_us": elapsed_us,
    }, indent=2), encoding="utf-8")
    return {
        "status": status,
        "verdict": verdict,
        "wall_time_us": elapsed_us,
        "baseline_memory_current_bytes": baseline,
        "peak_kg_container_memory_bytes": peak_bytes,
        "incremental_peak_kg_container_memory_bytes": max(0, peak_bytes - baseline),
        "error": error,
    }


def run_one(mode: str, row: Dict[str, Any], client: KrakenGuardClient, cg: Path, timeout: int, run_id: str) -> Dict[str, Any]:
    run_dir = RAW / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    obj = ROOT / row["object_file"]
    expected = row["expected_verdict"]
    abstract = None
    symbolic = None

    if mode == "symbolic_only":
        symbolic = kg_once(client, obj, timeout, cg, run_dir)
        final = symbolic["verdict"]
        route = "SYMBOLIC_ONLY"
    elif mode == "abstract_only":
        abstract = worker_abstract(obj, run_dir)
        final = {"SAFE":"COMPLIANT","VIOLATION":"POLICY VIOLATION","UNKNOWN":"UNKNOWN"}.get(abstract.get("verdict"),"UNKNOWN")
        route = "ABSTRACT_ONLY"
    else:
        abstract = worker_abstract(obj, run_dir)
        if abstract.get("verdict") == "UNKNOWN":
            symbolic = kg_once(client, obj, timeout, cg, run_dir / "symbolic")
            final = symbolic["verdict"]
            route = "FALLBACK_SYMBOLIC"
        elif abstract.get("verdict") == "SAFE":
            final, route = "COMPLIANT", "FAST_PATH_SAFE"
        else:
            final, route = "POLICY VIOLATION", "FAST_PATH_VIOLATION"

    # Memory domains are deliberately reported separately. Host abstract RSS
    # and container cgroup peak are not merged into a fabricated total.
    return {
        "run_id": run_id, "mode": mode, "program_id": row["program_id"],
        "family": row["family"], "scale": row["scale"], "target_paths": row["target_paths"],
        "instructions": row["instructions"], "expected_verdict": expected,
        "abstract_verdict": abstract.get("verdict") if abstract else "",
        "final_verdict": final, "route": route,
        "fallback_invoked": route == "FALLBACK_SYMBOLIC",
        "verdict_correct": final == expected if final != "UNKNOWN" else None,
        "abstract_peak_rss_bytes": abstract.get("peak_rss_bytes") if abstract else None,
        "kg_peak_memory_bytes": symbolic.get("peak_kg_container_memory_bytes") if symbolic else None,
        "kg_incremental_peak_memory_bytes": symbolic.get("incremental_peak_kg_container_memory_bytes") if symbolic else None,
        "symbolic_wall_time_us": symbolic.get("wall_time_us") if symbolic else None,
        "error": (symbolic or {}).get("error"),
        "object_sha256": row["object_sha256"], "source_sha256": row["source_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA, "krakenguard_commit": FROZEN_KG_COMMIT,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--warmups", type=int, default=2)
    p.add_argument("--repetitions", type=int, default=7)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--mode", choices=["all","symbolic_only","abstract_only","hybrid"], default="all")
    args = p.parse_args()

    if sha256(POLICY) != FROZEN_POLICY_SHA:
        raise SystemExit("frozen policy SHA mismatch")
    if platform.machine() != "x86_64":
        raise SystemExit("space study requires x86_64")
    cg = kg_container_cgroup()

    kg_commit = checked(["git","-C",str(KG_ARTIFACT),"rev-parse","HEAD"])
    if kg_commit != FROZEN_KG_COMMIT:
        raise SystemExit("KRAKENGUARD commit mismatch")
    digests = json.loads(checked(["docker","image","inspect",KG_IMAGE,"--format","{{json .RepoDigests}}"]))
    if FROZEN_DIGEST not in digests:
        raise SystemExit("frozen KRAKENGUARD container digest missing")
    if not (CORPUS / "manifest.json").exists():
        raise SystemExit("run generate_scaling_corpus.py first")

    rows = list(csv.DictReader((CORPUS / "metadata.csv").open(newline="",encoding="utf-8")))
    for r in rows:
        r["scale"]=int(r["scale"]); r["target_paths"]=int(r["target_paths"]); r["instructions"]=int(r["instructions"])

    RESULTS.mkdir(parents=True,exist_ok=True); RAW.mkdir(parents=True,exist_ok=True)
    client = KrakenGuardClient(os.path.relpath(SOCKET, Path.cwd()))
    modes = ["symbolic_only","abstract_only","hybrid"] if args.mode=="all" else [args.mode]
    rng=random.Random(args.seed); records=[]

    for w in range(1,args.warmups+1):
        jobs=[(m,r) for m in modes for r in rows]; rng.shuffle(jobs)
        for m,r in jobs:
            rec=run_one(m,r,client,cg,args.timeout,f"{m}-{r['program_id']}-w{w:02d}")
            rec.update({"repetition_type":"warmup","repetition":w}); records.append(rec)

    for rep in range(1,args.repetitions+1):
        jobs=[(m,r) for m in modes for r in rows]; rng.shuffle(jobs)
        for m,r in jobs:
            rec=run_one(m,r,client,cg,args.timeout,f"{m}-{r['program_id']}-m{rep:02d}")
            rec.update({"repetition_type":"measured","repetition":rep}); records.append(rec)

    (RESULTS/"provenance.json").write_text(json.dumps({
        "schema":"scaling-space/v1","timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "repo_branch":checked(["git","-C",str(ROOT),"branch","--show-current"]),
        "repo_head":checked(["git","-C",str(ROOT),"rev-parse","HEAD"]),
        "repo_tree":checked(["git","-C",str(ROOT),"rev-parse","HEAD^{tree}"]),
        "kernel":platform.release(),"architecture":platform.machine(),
        "policy_sha256":FROZEN_POLICY_SHA,"krakenguard_commit":FROZEN_KG_COMMIT,
        "container_digest":FROZEN_DIGEST,"cgroup_path":str(cg),
        "memory_measurement":"cgroup-v2 memory.peak reset before each KRAKENGUARD request",
        "abstract_measurement":"fresh abstract_worker process ru_maxrss",
        "seed":args.seed,"warmups":args.warmups,"repetitions":args.repetitions,
    },indent=2),encoding="utf-8")

    fields=list(records[0].keys())
    with (RESULTS/"runs.csv").open("w",newline="",encoding="utf-8") as fh:
        w=csv.DictWriter(fh,fieldnames=fields); w.writeheader(); w.writerows(records)
    (RESULTS/"runs.jsonl").write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in records),encoding="utf-8")
    print(json.dumps({"status":"completed","programs":len(rows),"total_runs":len(records),
                      "measured_runs":len(rows)*len(modes)*args.repetitions,
                      "results":str((RESULTS/"runs.csv").relative_to(ROOT))},indent=2))


if __name__=="__main__":
    main()
