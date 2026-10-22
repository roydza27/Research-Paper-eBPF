#!/usr/bin/env python3
"""Regression test suite for E3, E4, and E5 verification invariants.

Validates:
- E3: Corpus integrity, abstract analyzer behavior, fallback invocation, resolution rate,
      and fail-closed reference agreement without over-claiming formal soundness.
- E4: Data accounting (432 runs), paired per-program comparisons, median-of-ratios (45.53%)
      vs ratio-of-medians (44.93%), and subpopulation asymmetry.
- E5: Path-strata membership (1..32), unreachability of Stratum 64, and fallback scaling.
"""

import csv
import hashlib
import json
import statistics
from pathlib import Path
import pytest

from research.analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "research" / "experiments" / "corpus" / "phase5"
METADATA_CSV = CORPUS_DIR / "metadata.csv"
POLICY_JSON = CORPUS_DIR / "policies" / "phase5_policy.json"
PROGRAMS_DIR = CORPUS_DIR / "programs"

E3_RESULTS_CSV = REPO_ROOT / "research" / "experiments" / "results" / "e3" / "e3-results.csv"
E4_RESULTS_CSV = REPO_ROOT / "research" / "experiments" / "results" / "e4" / "e4-results.csv"
E5_RESULTS_JSON = REPO_ROOT / "research" / "experiments" / "results" / "e5" / "e5-results.json"
E5_SCALING_CSV = REPO_ROOT / "research" / "experiments" / "results" / "e5" / "e5-scaling-analysis.csv"


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# E3: Corpus & Abstract Verification Invariants
# ==============================================================================

def test_e3_corpus_manifest_and_files_integrity():
    """Verify that all 24 programs exist and match their manifest hashes."""
    assert METADATA_CSV.exists(), "Corpus metadata.csv missing"
    assert POLICY_JSON.exists(), "Phase 5 policy.json missing"

    with open(METADATA_CSV) as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 24, f"Expected 24 programs in corpus, found {len(rows)}"

    cats = {"A": [], "B": [], "C": [], "D": []}
    for r in rows:
        pid = r["program_id"]
        cat = r["category"]
        cats[cat].append(pid)

        c_file = PROGRAMS_DIR / r["source_file"]
        o_file = PROGRAMS_DIR / r["object_file"]

        assert c_file.exists(), f"Source file {c_file} missing"
        assert o_file.exists(), f"Object file {o_file} missing"

        assert sha256_of_file(c_file) == r["source_sha256"], f"Hash mismatch for {c_file}"
        assert sha256_of_file(o_file) == r["object_sha256"], f"Hash mismatch for {o_file}"
        assert r["policy_sha256"] == "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"

    for c in ("A", "B", "C", "D"):
        assert len(cats[c]) == 6, f"Category {c} should have 6 programs, got {len(cats[c])}"


def test_e3_abstract_analyzer_classification_and_discharge_rate():
    """Verify abstract decisions on all 24 programs without consulting labels."""
    with open(METADATA_CSV) as f:
        rows = list(csv.DictReader(f))

    counts = {"SAFE": 0, "VIOLATION": 0, "UNKNOWN": 0}
    discharged_progs = []

    for r in rows:
        pid = r["program_id"]
        cat = r["category"]
        obj_path = PROGRAMS_DIR / r["object_file"]

        analyzer = AbstractPolicyAnalyzer(str(obj_path), str(POLICY_JSON))
        res = analyzer.analyze()
        verdict = res["verdict"]
        counts[verdict] += 1

        if cat == "A":
            assert verdict == "SAFE", f"Program {pid} (Cat A) should be SAFE, got {verdict}"
            assert res["discharged"] is True
            discharged_progs.append(pid)
        elif cat == "B":
            assert verdict == "UNKNOWN", f"Program {pid} (Cat B) should be UNKNOWN, got {verdict}"
            assert res["discharged"] is False
        elif cat == "C":
            assert verdict == "VIOLATION", f"Program {pid} (Cat C) should be VIOLATION, got {verdict}"
            assert res["discharged"] is True
            discharged_progs.append(pid)
        elif cat == "D":
            assert verdict == "UNKNOWN", f"Program {pid} (Cat D) should be UNKNOWN, got {verdict}"
            assert res["discharged"] is False

    assert counts == {"SAFE": 6, "VIOLATION": 6, "UNKNOWN": 12}
    assert len(discharged_progs) == 12

    # Discharge rate must be computed with total eligible programs (24) as denominator
    discharge_rate = len(discharged_progs) / len(rows)
    assert discharge_rate == 0.50, f"Expected 50% discharge rate, got {discharge_rate}"


def test_e3_historical_results_csv_consistency():
    """Verify e3-results.csv accounting: 216 runs, zero mismatches, no false verdicts."""
    assert E3_RESULTS_CSV.exists(), "e3-results.csv missing"
    with open(E3_RESULTS_CSV) as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 216, f"Expected 216 runs in E3 dataset, got {len(rows)}"

    measured = [r for r in rows if r["repetition_type"] == "measured"]
    warmup = [r for r in rows if r["repetition_type"] == "warmup"]
    assert len(measured) == 168, f"Expected 168 measured runs (24*7), got {len(measured)}"
    assert len(warmup) == 48, f"Expected 48 warmup runs (24*2), got {len(warmup)}"

    # Check zero mismatches and no false positives/negatives
    for r in measured:
        assert r["correctness_agreement"] == "True"
        if r["abstract_verdict"] == "SAFE":
            assert r["reference_verdict"] == "COMPLIANT"
        elif r["abstract_verdict"] == "VIOLATION":
            assert r["reference_verdict"] == "POLICY VIOLATION"


# ==============================================================================
# E4: Hybrid vs Symbolic Performance Invariants
# ==============================================================================

def test_e4_execution_accounting_and_paired_metrics():
    """Verify E4 matrix accounting (432 runs) and independent derivation of savings."""
    assert E4_RESULTS_CSV.exists(), "e4-results.csv missing"
    with open(E4_RESULTS_CSV) as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 432, f"Expected 432 runs in E4 dataset, got {len(rows)}"
    measured = [r for r in rows if r["repetition_type"] == "measured"]
    assert len(measured) == 336, f"Expected 336 measured runs (24*2*7), got {len(measured)}"

    # Group by program and condition
    programs = sorted(list(set(r["program_id"] for r in measured)))
    assert len(programs) == 24

    sym_by_prog = {}
    hyb_by_prog = {}
    for r in measured:
        p = r["program_id"]
        t = float(r["total_wall_time_ms"])
        if r["condition"] == "symbolic_only":
            sym_by_prog.setdefault(p, []).append(t)
        elif r["condition"] == "hybrid":
            hyb_by_prog.setdefault(p, []).append(t)

    prog_sym_med = {}
    prog_hyb_med = {}
    paired_savings = []
    for p in programs:
        assert len(sym_by_prog[p]) == 7, f"Program {p} symbolic runs != 7"
        assert len(hyb_by_prog[p]) == 7, f"Program {p} hybrid runs != 7"
        s_med = statistics.median(sym_by_prog[p])
        h_med = statistics.median(hyb_by_prog[p])
        prog_sym_med[p] = s_med
        prog_hyb_med[p] = h_med
        sav = (s_med - h_med) / s_med * 100
        paired_savings.append(sav)

    # 1. Median of per-program paired percentage savings is 45.53%
    median_of_paired = round(statistics.median(paired_savings), 2)
    assert median_of_paired == 45.53, f"Expected median paired saving 45.53%, got {median_of_paired}%"

    # 2. Percentage reduction of dataset medians is 44.93%
    all_sym_meds = [prog_sym_med[p] for p in programs]
    all_hyb_meds = [prog_hyb_med[p] for p in programs]
    overall_sym_med = statistics.median(all_sym_meds)
    overall_hyb_med = statistics.median(all_hyb_meds)
    aggregate_reduction = round((overall_sym_med - overall_hyb_med) / overall_sym_med * 100, 2)
    assert aggregate_reduction == 44.93, f"Expected aggregate reduction 44.93%, got {aggregate_reduction}%"

    # 3. Subpopulation asymmetry: Discharged cases achieve >90% savings, fallback cases pay ~5% penalty
    discharged_progs = [p for p in programs if p.startswith("a") or p.startswith("c")]
    fallback_progs = [p for p in programs if p.startswith("b") or p.startswith("d")]

    dis_sym = statistics.median([prog_sym_med[p] for p in discharged_progs])
    dis_hyb = statistics.median([prog_hyb_med[p] for p in discharged_progs])
    dis_sav = (dis_sym - dis_hyb) / dis_sym * 100
    assert dis_sav > 90.0, f"Discharged savings {dis_sav}% should exceed 90%"

    fb_sym = statistics.median([prog_sym_med[p] for p in fallback_progs])
    fb_hyb = statistics.median([prog_hyb_med[p] for p in fallback_progs])
    fb_overhead = (fb_sym - fb_hyb) / fb_sym * 100
    assert -10.0 < fb_overhead < 0.0, f"Fallback overhead {fb_overhead}% should be bounded around -5%"


# ==============================================================================
# E5: Path Strata Invariants & Stratum 64 Unreachability
# ==============================================================================

def test_e5_path_strata_membership_and_stratum_64():
    """Verify E5 path strata mapping and ensure Stratum 64 is marked unreachable."""
    assert E5_SCALING_CSV.exists(), "e5-scaling-analysis.csv missing"
    assert E5_RESULTS_JSON.exists(), "e5-results.json missing"

    with open(E5_SCALING_CSV) as f:
        rows = list(csv.DictReader(f))

    strata_map = {int(r["path_stratum"]): r for r in rows}

    # Tested strata: 1, 2, 4, 8, 16, 32, 64
    assert set(strata_map.keys()) == {1, 2, 4, 8, 16, 32, 64}

    # Stratum 1: 12 programs, 0 fallbacks, 100% discharged
    s1 = strata_map[1]
    assert s1["reachable"] == "True"
    assert int(s1["program_count"]) == 12
    assert int(s1["discharged_count"]) == 12
    assert int(s1["fallback_count"]) == 0
    assert float(s1["fallback_fraction"]) == 0.0
    assert float(s1["savings_median_pct"]) > 90.0

    # Stratum 2: 4 programs (b1, b2, d1, d2), 100% fallback
    s2 = strata_map[2]
    assert s2["reachable"] == "True"
    assert int(s2["program_count"]) == 4
    assert int(s2["discharged_count"]) == 0
    assert int(s2["fallback_count"]) == 4
    assert float(s2["fallback_fraction"]) == 1.0

    # Strata 4, 8, 16, 32: 2 programs each, 100% fallback
    for stratum in (4, 8, 16, 32):
        st = strata_map[stratum]
        assert st["reachable"] == "True"
        assert int(st["program_count"]) == 2
        assert int(st["discharged_count"]) == 0
        assert int(st["fallback_count"]) == 2
        assert float(st["fallback_fraction"]) == 1.0

    # Stratum 64: Unreachable, unmeasured, must NOT contain synthetic measurements
    s64 = strata_map[64]
    assert s64["reachable"] == "False"
    assert s64["programs_reaching"] == "NONE"
    assert int(s64["program_count"]) == 0
    assert s64["fallback_fraction"] == "N/A"
    assert s64["total_hybrid_median_ms"] == "N/A"
    assert s64["savings_median_pct"] == "N/A"
