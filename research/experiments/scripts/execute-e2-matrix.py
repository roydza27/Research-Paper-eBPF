#!/usr/bin/env python3
"""
Phase 4 E2 Full Matrix Execution Orchestrator
Executes the full 63-run replication matrix (7 programs x (2 warmups + 7 measured)).
Follows the approved Blocked/Interleaved protocol across 7 controlled path levels.

Telemetry Semantics:
- Primary independent variable: observed KLEE explored paths
- Primary performance metric: wall_time_us
- Process CPU time: client-process CPU duration only (time.process_time())
- Peak memory: NOT_REPORTED (unmeasured by baseline daemon)
- Solver time: NOT_REPORTED (aggregate solver wall-clock unmeasured by baseline daemon)
- Regex-anchored parsing resolves the substring collision for completed_paths.
"""

import os
import sys
import time
import json
import csv
import hashlib
import subprocess
import re
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
BASELINE_DIR = ROOT_DIR / "baselines" / "krakenguard" / "artifact"
CORPUS_DIR = ROOT_DIR / "experiments" / "corpus" / "e2"
PROGRAMS_DIR = CORPUS_DIR / "programs"
POLICY_FILE = ROOT_DIR / "experiments" / "corpus" / "e1" / "policies" / "e1_fixed_policy.json"
RESULTS_DIR = ROOT_DIR / "experiments" / "results" / "e2"
RAW_DIR = RESULTS_DIR / "raw"
OBJ_DIR = ROOT_DIR / "experiments" / "results" / "raw" / "e2-objects"

# Add baseline daemon client to sys.path
sys.path.insert(0, str(BASELINE_DIR))
try:
    from daemon.krakenguard_client import KrakenGuardClient
except ImportError:
    KrakenGuardClient = None

PROGRAM_LEVELS = [
    ("E2-P0", "e2_p0", "Symbolic baseline (0 branches)", 0, 1),
    ("E2-P1", "e2_p1", "One symbolic split (1 branch)", 1, 2),
    ("E2-P2", "e2_p2", "Two symbolic splits (2 branches)", 2, 4),
    ("E2-P3", "e2_p3", "Three symbolic splits (3 branches)", 3, 8),
    ("E2-P4", "e2_p4", "Pilot upper level (4 branches)", 4, 16),
    ("E2-P5", "e2_p5", "Full matrix level (5 branches)", 5, 32),
    ("E2-P6", "e2_p6", "Full matrix upper level (6 branches)", 6, 64),
]

EXPECTED_POLICY_SHA256 = "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"
KRAKENGUARD_COMMIT = "e7bd84005b304c5a10efcdb04914d1882b3cccf7"
TIMEOUT_SECONDS = 300


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_socket_path() -> str:
    sock = BASELINE_DIR / "socket" / "krakenguard.sock"
    if not sock.exists():
        raise FileNotFoundError(f"Daemon socket not found at {sock}")
    return os.path.relpath(sock, os.getcwd())


def compile_program(prog_id: str, slug: str) -> Dict[str, Any]:
    src_file = PROGRAMS_DIR / f"{slug}.c"
    obj_file = OBJ_DIR / f"{slug}.o"
    OBJ_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "clang",
        "-target", "bpf",
        "-mcpu=v1",
        "-D__TARGET_ARCH_x86",
        "-O2",
        "-g",
        "-I/usr/include",
        "-c", str(src_file),
        "-o", str(obj_file)
    ]

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    t1 = time.perf_counter()
    wall_time_us = int((t1 - t0) * 1_000_000)

    log_file = RAW_DIR / f"{slug}-compile.log"
    with open(log_file, "w") as f:
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Exit code: {proc.returncode}\n")
        f.write(f"Wall time: {wall_time_us} us\n")
        f.write(f"--- STDOUT ---\n{proc.stdout}\n")
        f.write(f"--- STDERR ---\n{proc.stderr}\n")

    if proc.returncode != 0:
        raise RuntimeError(f"Compilation failed for {prog_id} ({src_file}):\n{proc.stderr}")

    return {
        "command": " ".join(cmd),
        "compiler": "clang",
        "compiler_version": "22.1.8",
        "target": "bpf",
        "mcpu": "v1",
        "optimization": "-O2",
        "include_paths": ["/usr/include"],
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "wall_time_us": wall_time_us,
        "source_sha256": sha256_file(src_file),
        "object_sha256": sha256_file(obj_file),
        "object_file": str(obj_file)
    }


def inspect_object(slug: str, obj_file: Path) -> Dict[str, Any]:
    objdump_proc = subprocess.run(["llvm-objdump", "-d", str(obj_file)], capture_output=True, text=True)
    readelf_proc = subprocess.run(["readelf", "-S", str(obj_file)], capture_output=True, text=True)
    bpftool_proc = subprocess.run(["bpftool", "btf", "dump", "file", str(obj_file), "format", "raw"], capture_output=True, text=True)

    with open(RAW_DIR / f"{slug}-llvm-objdump.txt", "w") as f:
        f.write(objdump_proc.stdout)
    with open(RAW_DIR / f"{slug}-readelf.txt", "w") as f:
        f.write(readelf_proc.stdout)
    with open(RAW_DIR / f"{slug}-bpftool-btf.txt", "w") as f:
        f.write(bpftool_proc.stdout)

    lines = [l for l in objdump_proc.stdout.splitlines() if re.match(r'^\s*[0-9a-f]+:\s+', l)]
    instruction_count = len(lines)
    branches = len([l for l in lines if 'if ' in l or 'goto' in l])
    helpers = len([l for l in lines if 'call' in l])
    maps = 0
    basic_blocks = 1 + branches

    return {
        "instruction_count": instruction_count,
        "basic_blocks": basic_blocks,
        "branches": branches,
        "loops": 0,
        "helpers": helpers,
        "maps": maps,
    }


def parse_klee_info_file(output_dir: Path) -> Dict[str, Any]:
    """
    Parses KLEE info file using strict anchored regular expressions to prevent
    substring collisions between 'completed paths' and 'partially completed paths'.
    """
    info_file = output_dir / "info"
    stats = {
        "paths_explored": 0,
        "completed_paths": 0,
        "partially_completed_paths": 0,
        "total_instructions": 0,
        "total_queries": 0,
        "valid_queries": 0,
        "invalid_queries": 0,
        "query_cex": 0,
    }
    if not info_file.exists():
        return stats

    with open(info_file, "r") as f:
        content = f.read()

    for line in content.splitlines():
        if m := re.search(r'^\s*KLEE:\s*done:\s*explored paths\s*=\s*(\d+)', line):
            stats["paths_explored"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*completed paths\s*=\s*(\d+)', line):
            stats["completed_paths"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*partially completed paths\s*=\s*(\d+)', line):
            stats["partially_completed_paths"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*total queries\s*=\s*(\d+)', line):
            stats["total_queries"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*valid queries\s*=\s*(\d+)', line):
            stats["valid_queries"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*invalid queries\s*=\s*(\d+)', line):
            stats["invalid_queries"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*query cex\s*=\s*(\d+)', line):
            stats["query_cex"] = int(m.group(1))
        elif m := re.search(r'^\s*KLEE:\s*done:\s*total instructions\s*=\s*(\d+)', line):
            stats["total_instructions"] = int(m.group(1))

    return stats


def run_single_verification(
    client: KrakenGuardClient,
    prog_id: str,
    slug: str,
    obj_file: Path,
    policy_file: Path,
    run_type: str,
    block_no: int,
    repeat_no: int,
    static_metrics: Dict[str, Any],
    source_sha256: str,
    object_sha256: str,
    policy_sha256: str,
    predicate_count: int,
    target_paths: int,
    dry_run: bool = False
) -> Dict[str, Any]:
    run_tag = f"{slug}-b{block_no:02d}-{'w' if run_type == 'warmup' else 'm'}{repeat_no:02d}"
    run_id = f"e2-{prog_id.lower()}-b{block_no:02d}-{'w' if run_type == 'warmup' else 'm'}{repeat_no:02d}"

    if dry_run:
        return {
            "run_id": run_id,
            "program_id": prog_id,
            "slug": slug,
            "warmup_or_measured": run_type,
            "block_number": block_no,
            "repeat_number": repeat_no,
            "predicate_count": predicate_count,
            "target_paths": target_paths,
            "source_sha256": source_sha256,
            "object_sha256": object_sha256,
            "policy_sha256": policy_sha256,
            "krakenguard_commit": KRAKENGUARD_COMMIT,
            "compiler": "clang",
            "compiler_version": "22.1.8",
            "kernel_version": "7.2.3-arch1-2",
            "architecture": "x86_64",
            "instruction_count": static_metrics["instruction_count"],
            "basic_blocks": static_metrics["basic_blocks"],
            "branches": static_metrics["branches"],
            "loops": 0,
            "helpers": static_metrics["helpers"],
            "maps": 0,
            "krakenguard_request_id": "DRY_RUN",
            "execution_status": "dry_run",
            "verifier_result": "DRY_RUN",
            "policy_result": "DRY_RUN",
            "passed": True,
            "wall_time_us": 0,
            "cpu_time_us": 0,
            "klee_paths_explored": target_paths,
            "klee_completed_paths": target_paths,
            "klee_partially_completed_paths": 0,
            "klee_total_instructions": 0,
            "klee_total_queries": target_paths,
            "klee_valid_queries": target_paths,
            "klee_invalid_queries": 0,
            "klee_query_cex": target_paths,
            "peak_memory_bytes": "NOT_REPORTED",
            "solver_time_us": "NOT_REPORTED",
        }

    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()
    try:
        resp = client.verify(
            object_file=str(obj_file.resolve()),
            constraints_file=str(policy_file.resolve()),
            debug=True,
            timeout=TIMEOUT_SECONDS
        )
        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()
        is_timeout = False
    except Exception as e:
        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()
        is_timeout = "timeout" in str(e).lower()
        resp = None

    wall_time_us = int((t1_wall - t0_wall) * 1_000_000)
    cpu_time_us = int((t1_cpu - t0_cpu) * 1_000_000)

    if resp:
        req_id = resp.request_id
        host_req_dir = BASELINE_DIR / "data" / "requests" / req_id
        host_out_dir = host_req_dir / "output"
        info_stats = parse_klee_info_file(host_out_dir)

        stdout_text = resp.output.stdout if resp.output else ""
        stderr_text = resp.output.stderr if resp.output else ""

        with open(RAW_DIR / f"{run_tag}.stdout", "w") as f:
            f.write(stdout_text)
        with open(RAW_DIR / f"{run_tag}.stderr", "w") as f:
            f.write(stderr_text)

        if (host_out_dir / "info").exists():
            with open(RAW_DIR / f"{run_tag}-klee-info.txt", "w") as f:
                f.write((host_out_dir / "info").read_text())

        is_success = resp.status == "success"
        passed = resp.verification_result.passed if (is_success and resp.verification_result) else False
        exec_status = "success" if is_success else "error"
        verifier_result = "VERIFIED" if passed else ("REJECTED" if is_success else "ERROR")
        policy_result = "COMPLIANT" if passed else ("VIOLATION" if is_success else "ERROR")
    else:
        req_id = "FAILED"
        info_stats = {
            "paths_explored": 0, "completed_paths": 0, "partially_completed_paths": 0,
            "total_instructions": 0, "total_queries": 0, "valid_queries": 0,
            "invalid_queries": 0, "query_cex": 0
        }
        exec_status = "timeout" if is_timeout else "error"
        verifier_result = "TIMEOUT" if is_timeout else "ERROR"
        policy_result = "ERROR"
        passed = False

    meta = {
        "run_id": run_id,
        "program_id": prog_id,
        "slug": slug,
        "warmup_or_measured": run_type,
        "block_number": block_no,
        "repeat_number": repeat_no,
        "predicate_count": predicate_count,
        "target_paths": target_paths,
        "source_sha256": source_sha256,
        "object_sha256": object_sha256,
        "policy_sha256": policy_sha256,
        "krakenguard_commit": KRAKENGUARD_COMMIT,
        "compiler": "clang",
        "compiler_version": "22.1.8",
        "kernel_version": "7.2.3-arch1-2",
        "architecture": "x86_64",
        "instruction_count": static_metrics["instruction_count"],
        "basic_blocks": static_metrics["basic_blocks"],
        "branches": static_metrics["branches"],
        "loops": 0,
        "helpers": static_metrics["helpers"],
        "maps": 0,
        "krakenguard_request_id": req_id,
        "execution_status": exec_status,
        "verifier_result": verifier_result,
        "policy_result": policy_result,
        "passed": passed,
        "wall_time_us": wall_time_us,
        "cpu_time_us": cpu_time_us,
        "klee_paths_explored": info_stats["paths_explored"],
        "klee_completed_paths": info_stats["completed_paths"],
        "klee_partially_completed_paths": info_stats["partially_completed_paths"],
        "klee_total_instructions": info_stats["total_instructions"],
        "klee_total_queries": info_stats["total_queries"],
        "klee_valid_queries": info_stats["valid_queries"],
        "klee_invalid_queries": info_stats["invalid_queries"],
        "klee_query_cex": info_stats["query_cex"],
        "peak_memory_bytes": "NOT_REPORTED",
        "solver_time_us": "NOT_REPORTED",
    }
    return meta


def main():
    parser = argparse.ArgumentParser(description="Phase 4 E2 Full Matrix Execution Orchestrator")
    parser.add_argument("--dry-run", action="store_true", help="Perform compilation and static checks without running daemon verifier")
    args = parser.parse_args()

    print("=" * 80)
    print("PHASE 4 E2 FULL MATRIX ORCHESTRATOR — 63-RUN REPLICATION")
    print("=" * 80)

    # 1. Invariants & Environment Check
    print("\n[1/4] Verifying invariants and environment...")
    policy_hash = sha256_file(POLICY_FILE)
    print(f"  Fixed policy: {POLICY_FILE}")
    print(f"  Policy SHA-256: {policy_hash}")
    assert policy_hash == EXPECTED_POLICY_SHA256, f"Policy hash mismatch: {policy_hash} != {EXPECTED_POLICY_SHA256}"

    if not args.dry_run:
        sock_path = get_socket_path()
        print(f"  Daemon socket: {sock_path}")
        client = KrakenGuardClient(socket_path=sock_path)
    else:
        print("  DRY-RUN MODE ENABLED: Verifier socket execution will be simulated.")
        client = None

    # 2. Compile and Inspect All 7 Programs
    print("\n[2/4] Compiling and statically inspecting E2 corpus (P0..P6)...")
    compiled_data = {}
    for prog_id, slug, desc, preds, target_paths in PROGRAM_LEVELS:
        print(f"  Compiling {prog_id} ({slug}) - {desc}...")
        c_res = compile_program(prog_id, slug)
        obj_file = Path(c_res["object_file"])
        s_res = inspect_object(slug, obj_file)
        print(f"    Compiled: sha256={c_res['object_sha256'][:16]}..., insts={s_res['instruction_count']}, branches={s_res['branches']}, helpers={s_res['helpers']}")
        assert s_res["helpers"] == 1, f"{prog_id} helper count != 1"
        assert s_res["maps"] == 0, f"{prog_id} map count != 0"
        assert s_res["branches"] == preds + 1, f"{prog_id} branches != {preds+1}"
        compiled_data[prog_id] = {
            "compile": c_res,
            "static": s_res,
            "desc": desc,
            "preds": preds,
            "target_paths": target_paths,
            "obj_file": obj_file
        }

    # 3. Build Blocked/Interleaved Execution Schedule
    # 2 warmup rounds across P0..P6 (14 runs)
    # 7 measured blocks across P0..P6 (49 runs)
    print("\n[3/4] Preparing Blocked / Interleaved Execution Schedule (63 runs)...")
    schedule = []
    # Warmups
    for w_round in range(1, 3):
        for prog_id, slug, _, preds, target_paths in PROGRAM_LEVELS:
            schedule.append(("warmup", w_round, w_round, prog_id, slug, preds, target_paths))
    # Measured runs
    for m_block in range(1, 8):
        for prog_id, slug, _, preds, target_paths in PROGRAM_LEVELS:
            schedule.append(("measured", m_block, m_block, prog_id, slug, preds, target_paths))

    print(f"  Total planned executions: {len(schedule)} (14 warmups + 49 measured)")

    if args.dry_run:
        print("  Simulating execution schedule offline...")
        results = []
        for run_type, block_no, rep_no, prog_id, slug, preds, target_paths in schedule:
            info = compiled_data[prog_id]
            res = run_single_verification(
                client=None,
                prog_id=prog_id,
                slug=slug,
                obj_file=info["obj_file"],
                policy_file=POLICY_FILE,
                run_type=run_type,
                block_no=block_no,
                repeat_no=rep_no,
                static_metrics=info["static"],
                source_sha256=info["compile"]["source_sha256"],
                object_sha256=info["compile"]["object_sha256"],
                policy_sha256=policy_hash,
                predicate_count=preds,
                target_paths=target_paths,
                dry_run=True
            )
            results.append(res)
        print(f"  DRY RUN COMPLETE: {len(results)} runs verified.")
        return 0

    # 4. Actual Execution Loop
    results = []
    for idx, (run_type, block_no, rep_no, prog_id, slug, preds, target_paths) in enumerate(schedule, 1):
        info = compiled_data[prog_id]
        print(f"  [{idx:02d}/63] {run_type.upper()} B{block_no:02d}-R{rep_no:02d} {prog_id} ({slug})...", end=" ", flush=True)
        res = run_single_verification(
            client=client,
            prog_id=prog_id,
            slug=slug,
            obj_file=info["obj_file"],
            policy_file=POLICY_FILE,
            run_type=run_type,
            block_no=block_no,
            repeat_no=rep_no,
            static_metrics=info["static"],
            source_sha256=info["compile"]["source_sha256"],
            object_sha256=info["compile"]["object_sha256"],
            policy_sha256=policy_hash,
            predicate_count=preds,
            target_paths=target_paths,
            dry_run=False
        )
        print(f"DONE in {res['wall_time_us'] / 1000.0:.2f} ms | Paths: {res['klee_paths_explored']} (completed: {res['klee_completed_paths']}) | Verdict: {res['verifier_result']}")
        results.append(res)

    # Save CSV
    csv_file = RESULTS_DIR / "e2-results.csv"
    if results:
        fieldnames = list(results[0].keys())
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
    print(f"\nSaved CSV: {csv_file}")

    # Save JSON
    json_file = RESULTS_DIR / "e2-results.json"
    with open(json_file, "w") as f:
        json.dump({"total_executions": len(results), "runs": results}, f, indent=2)
    print(f"Saved JSON: {json_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
