import pytest
from pathlib import Path
from work.analyze_comparison import read_runs, summarize, RESULTS

RUNS_PATH = RESULTS / "runs.csv"


def test_runs_csv_accounting_on_benchmark_data():
    """Verify that summarize() on real benchmark data accounts for all 504 measured rows."""
    assert RUNS_PATH.exists(), f"Benchmark data not found at {RUNS_PATH}"
    rows = read_runs(RUNS_PATH)
    summary = summarize(rows)

    c = summary["correctness"]
    # Total measured rows must be exactly 504 (24 programs * 3 modes * 7 repetitions)
    assert summary["total_measured_rows"] == 504
    assert c["total_measured_rows"] == 504

    # Exactly 420 definitive checked rows
    assert c["checked_measured_rows"] == 420
    assert c["all_checked_agree"] is True
    assert c["false_safe"] == 0
    assert c["false_violation"] == 0

    # Exactly 84 conservative abstentions, all from abstract_only
    assert c["abstentions"]["count"] == 84
    assert c["abstentions"]["by_mode"]["abstract_only"] == 84
    assert c["abstentions"]["by_mode"]["symbolic_only"] == 0
    assert c["abstentions"]["by_mode"]["hybrid"] == 0

    # Unreferenced or malformed rows must be 0
    assert c["unreferenced_or_malformed"] == 0
    assert c["accounting_balanced"] is True

    # Mode breakdown checks
    m = c["by_mode"]
    assert m["symbolic_only"]["total_measured"] == 168
    assert m["symbolic_only"]["checked_definitive"] == 168
    assert m["symbolic_only"]["agreed"] == 168
    assert m["symbolic_only"]["abstentions"] == 0
    assert m["symbolic_only"]["failed"] == 0

    assert m["hybrid"]["total_measured"] == 168
    assert m["hybrid"]["checked_definitive"] == 168
    assert m["hybrid"]["agreed"] == 168
    assert m["hybrid"]["abstentions"] == 0
    assert m["hybrid"]["failed"] == 0

    assert m["abstract_only"]["total_measured"] == 168
    assert m["abstract_only"]["checked_definitive"] == 84
    assert m["abstract_only"]["agreed"] == 84
    assert m["abstract_only"]["abstentions"] == 84
    assert m["abstract_only"]["failed"] == 0


def test_missing_reference_verdict_never_counts_as_agreement():
    """A row with missing/empty reference_verdict must never be counted as agreement."""
    rows = read_runs(RUNS_PATH)
    # Corrupt one definitive row by stripping its reference_verdict
    corrupted = [dict(r) for r in rows]
    target = next(r for r in corrupted if r["repetition_type"] == "measured" and r["final_verdict"] == "COMPLIANT")
    target["reference_verdict"] = ""
    target["verdict_correct"] = True  # Forged flag should NOT fool the audit

    summary = summarize(corrupted)
    c = summary["correctness"]
    assert c["all_checked_agree"] is False
    assert c["unreferenced_or_malformed"] >= 1


def test_corrupted_verdict_fails_correctness():
    """A row with mismatching verdict must fail all_checked_agree and flag false violation/safe."""
    rows = read_runs(RUNS_PATH)
    corrupted = [dict(r) for r in rows]
    # Invert a COMPLIANT row to POLICY VIOLATION
    target = next(r for r in corrupted if r["repetition_type"] == "measured" and r["reference_verdict"] == "COMPLIANT")
    target["final_verdict"] = "POLICY VIOLATION"
    target["verdict_correct"] = False

    summary = summarize(corrupted)
    c = summary["correctness"]
    assert c["all_checked_agree"] is False
    assert c["false_violation"] >= 1


def test_false_safe_detected():
    """A row where reference is violation but abstract says SAFE must be detected as false_safe."""
    rows = read_runs(RUNS_PATH)
    corrupted = [dict(r) for r in rows]
    target = next(r for r in corrupted if r["repetition_type"] == "measured" and r["reference_verdict"] == "POLICY VIOLATION")
    target["abstract_verdict"] = "SAFE"

    summary = summarize(corrupted)
    c = summary["correctness"]
    assert c["false_safe"] >= 1


def test_metrics_recalculation_and_statistical_significance():
    """Verify independent recalculation of paired median savings, sign test, and bootstrap CI."""
    rows = read_runs(RUNS_PATH)
    summary = summarize(rows)
    p = summary["primary_endpoint"]

    # Paired median percentage saving: ~46.16%
    assert abs(p["median_saving_pct"] - 46.157) < 0.01

    # Exact two-sided sign test: 12 positive, 12 negative -> p = 1.0
    sign = p["exact_two_sided_sign_test"]
    assert sign["n"] == 24
    assert sign["positive"] == 12
    assert sign["negative"] == 12
    assert sign["p_two_sided"] == 1.0

    # Bootstrap 95% CI must span zero (lower < 0 and upper > 0)
    lower, upper = p["bootstrap_95ci_median_absolute_saving_ms"]
    assert lower < 0.0
    assert upper > 0.0
