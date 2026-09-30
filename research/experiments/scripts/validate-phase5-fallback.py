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

from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer, Verdict
from daemon.krakenguard_client import KrakenGuardClient
from experiments.scripts.validate_phase5_corpus import (
    EXPECTED_KRAKENGUARD_COMMIT,
    preflight_reference_environment,
    sha256_file,
)

FIXTURES = {"b1": "UNKNOWN compliant fixture", "d1": "UNKNOWN violating fixture"}


def main():
    policy_hash = sha256_file(POLICY_FILE)
    env = preflight_reference_environment(policy_hash)
    socket_path = BASELINE_DIR / "socket" / "krakenguard.sock"
    if not socket_path.exists():
        raise RuntimeError(f"KRAKENGUARD socket not found: {socket_path}")
    import os
    client = KrakenGuardClient(os.path.relpath(socket_path, Path.cwd()))

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
        passed = bool(response.verification_result and response.verification_result.passed)
        final_verdict = "COMPLIANT" if passed else "POLICY VIOLATION"
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
        })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "fallback-validation.json", "w") as f:
        json.dump({"schema":"phase5-fallback-validation/v1","execution_type":"correctness_only","performance_matrix":False,"environment":env,"fixtures":rows}, f, indent=2)
    with open(RESULTS_DIR / "fallback-validation.md", "w") as f:
        f.write("# Phase 5 — Actual UNKNOWN Fallback Validation\n\nCorrectness-only integration evidence. No E3/E4/E5 performance claim.\n\n")
        f.write("| Program | Abstract | Actual fallback | Final reference verdict |\n|---|---|---|---|\n")
        for row in rows:
            f.write(f"| {row['program_id']} | {row['abstract_verdict']} | KRAKENGUARD invoked | {row['reference_verdict']} |\n")


if __name__ == "__main__":
    main()
