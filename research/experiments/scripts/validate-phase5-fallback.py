#!/usr/bin/env python3
"""Correctness-only integration check for actual UNKNOWN -> KRAKENGUARD fallback.

This is deliberately tiny. It is not E3/E4/E5 and records no performance claim.
"""
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
CORPUS_DIR = ROOT_DIR / "experiments" / "corpus" / "phase5"
PROGRAMS_DIR = CORPUS_DIR / "programs"
POLICY_FILE = CORPUS_DIR / "policies" / "phase5_policy.json"
RESULTS_DIR = ROOT_DIR / "experiments" / "results" / "phase5-validation"
BASELINE_DIR = ROOT_DIR / "baselines" / "krakenguard" / "artifact"
import sys
sys.path.insert(0, str(BASELINE_DIR))
sys.path.insert(0, str(ROOT_DIR))

from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer, Verdict
from daemon.krakenguard_client import KrakenGuardClient
import importlib.util
_validator_path = Path(__file__).with_name("validate-phase5-corpus.py")
_spec = importlib.util.spec_from_file_location("phase5_validator", _validator_path)
_validator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validator)
EXPECTED_KRAKENGUARD_COMMIT = _validator.EXPECTED_KRAKENGUARD_COMMIT
preflight_reference_environment = _validator.preflight_reference_environment
sha256_file = _validator.sha256_file
extract_krakenguard_verdict = _validator.extract_krakenguard_verdict

FIXTURES = {"b1": "UNKNOWN compliant fixture", "d1": "UNKNOWN violating fixture"}


import os
import shutil
import subprocess

REPO_ROOT = ROOT_DIR.parent
RAW_FALLBACK_DIR = RESULTS_DIR / "raw" / "fallback"


def get_git_provenance():
    def _git(args):
        return subprocess.run(
            ["git", "-C", str(REPO_ROOT)] + args,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    return {
        "branch": _git(["branch", "--show-current"]),
        "head": _git(["rev-parse", "HEAD"]),
        "tree": _git(["rev-parse", "HEAD^{tree}"]),
    }


def main():
    policy_hash = sha256_file(POLICY_FILE)
    env = preflight_reference_environment(policy_hash)
    git_prov = get_git_provenance()
    socket_path = BASELINE_DIR / "socket" / "krakenguard.sock"
    if not socket_path.exists():
        raise RuntimeError(f"KRAKENGUARD socket not found: {socket_path}")
    client = KrakenGuardClient(os.path.relpath(socket_path, Path.cwd()))

    RAW_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for program_id, description in FIXTURES.items():
        object_file = PROGRAMS_DIR / f"{program_id}.o"
        if not object_file.exists():
            raise RuntimeError(f"missing compiled fixture: {object_file}")

        t0 = time.perf_counter()
        abstract = AbstractPolicyAnalyzer(str(object_file), str(POLICY_FILE)).analyze()
        abstract_us = int((time.perf_counter() - t0) * 1e6)
        if abstract["verdict"] != Verdict.UNKNOWN.value:
            raise AssertionError(f"{program_id}: expected UNKNOWN, got {abstract['verdict']}")

        # Actual selective fallback invocation.
        t1 = time.perf_counter()
        response = client.verify(object_file=str(object_file), constraints_file=str(POLICY_FILE))
        reference_us = int((time.perf_counter() - t1) * 1e6)
        passed, final_verdict = extract_krakenguard_verdict(response)

        # Preserve request-linked raw KRAKENGUARD evidence
        fixture_raw_dir = RAW_FALLBACK_DIR / program_id
        fixture_raw_dir.mkdir(parents=True, exist_ok=True)

        req_record = {
            "request_id": response.request_id,
            "program_id": program_id,
            "object_file": str(object_file),
            "object_sha256": sha256_file(object_file),
            "policy_file": str(POLICY_FILE),
            "policy_sha256": policy_hash,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        req_file = fixture_raw_dir / "request.json"
        with open(req_file, "w") as f:
            json.dump(req_record, f, indent=2)

        resp_file = fixture_raw_dir / "response.json"
        with open(resp_file, "w") as f:
            json.dump(response.to_dict(), f, indent=2)

        raw_files = {
            "request.json": sha256_file(req_file),
            "response.json": sha256_file(resp_file),
        }

        out_dir = response.output.directory or ""
        host_out_dir = Path(out_dir.replace("/data", str(BASELINE_DIR / "data")))
        cond_src = host_out_dir / "conditional_policy.results.txt"
        if not cond_src.exists():
            raise RuntimeError(f"Missing mandatory output file: {cond_src}")
        cond_dst = fixture_raw_dir / "conditional_policy.results.txt"
        shutil.copyfile(cond_src, cond_dst)
        raw_files["conditional_policy.results.txt"] = sha256_file(cond_dst)

        for log_name in ["messages.txt", "warnings.txt", "info"]:
            src_log = host_out_dir / log_name
            if src_log.exists():
                dst_log = fixture_raw_dir / log_name
                shutil.copyfile(src_log, dst_log)
                raw_files[log_name] = sha256_file(dst_log)

        rows.append({
            "program_id": program_id,
            "description": description,
            "abstract_verdict": abstract["verdict"],
            "fallback_invoked": True,
            "reference_verdict": final_verdict,
            "reference_request_id": response.request_id,
            "reference_status": response.status,
            "abstract_duration_us": abstract_us,
            "reference_duration_us": reference_us,
            "policy_sha256": policy_hash,
            "krakenguard_commit": EXPECTED_KRAKENGUARD_COMMIT,
            "raw_evidence_dir": str(fixture_raw_dir.relative_to(REPO_ROOT)),
            "raw_artifacts": raw_files,
        })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    validation_payload = {
        "schema": "phase5-fallback-validation/v1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_type": "correctness_only",
        "performance_matrix": False,
        "provenance": {
            "git": git_prov,
            "environment": env,
        },
        "fixtures": rows,
    }
    with open(RESULTS_DIR / "fallback-validation.json", "w") as f:
        json.dump(validation_payload, f, indent=2)

    with open(RESULTS_DIR / "fallback-validation.md", "w") as f:
        f.write("# Phase 5 — Actual UNKNOWN Fallback Validation\n\n")
        f.write("Correctness-only integration evidence. No E3/E4/E5 performance claim.\n\n")
        f.write(f"- **Git Branch:** `{git_prov['branch']}`\n")
        f.write(f"- **Git HEAD:** `{git_prov['head']}`\n")
        f.write(f"- **Git Tree:** `{git_prov['tree']}`\n\n")
        f.write("| Program | Abstract | Actual fallback | Final reference verdict | Request ID | Raw Evidence |\n")
        f.write("|---|---|---|---|---|---|\n")
        for row in rows:
            f.write(
                f"| `{row['program_id']}` | `{row['abstract_verdict']}` | KRAKENGUARD invoked | "
                f"`{row['reference_verdict']}` | `{row['reference_request_id']}` | `{row['raw_evidence_dir']}` |\n"
            )


if __name__ == "__main__":
    main()

