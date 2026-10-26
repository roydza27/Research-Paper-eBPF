import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
from analyze_runs import summarize
from prepare_corpus import SOURCES


class CorpusDefinitionTests(unittest.TestCase):
    def test_program_ids_are_stable_and_unique(self):
        self.assertEqual(len(SOURCES), len(set(SOURCES)))
        self.assertEqual(set(SOURCES), {
            "A01_straight_small", "A02_straight_medium", "A03_helper_clock",
            "B01_branch_safe", "B02_branch_policy_sensitive",
            "C01_join_different_values", "C02_join_policy_sensitive",
            "D01_helper_unknown_candidate", "D02_packet_memory_candidate",
            "E01_bounded_loop",
        })

    def test_every_source_is_a_complete_xdp_fixture(self):
        for program_id, spec in SOURCES.items():
            with self.subTest(program_id=program_id):
                self.assertIn('SEC("xdp")', spec["source"])
                self.assertIn('SEC("license")', spec["source"])
                self.assertIn("GPL", spec["source"])
                self.assertTrue(spec["hypothesis"])

    def test_hypotheses_are_not_reference_verdicts(self):
        for spec in SOURCES.values():
            self.assertIn("hypothesis", spec)
            self.assertNotIn("expected_verdict", spec)


class SummaryTests(unittest.TestCase):
    def test_missing_oracle_is_not_counted_as_agreement(self):
        report = summarize([{
            "program_id": "A01", "pipeline": "baseline",
            "overall_verdict": "SAFE", "end_to_end_duration_ms": 10.0,
            "symbolic_invoked": False,
        }], bootstrap_samples=100, seed=7)
        row = report["per_program_pipeline"][0]
        self.assertIsNone(row["oracle_agreement_rate"])
        self.assertEqual(row["oracle_comparisons"], 0)
        self.assertEqual(row["false_safe_count"], 0)

    def test_explicit_oracle_detects_false_safe_and_false_reject(self):
        report = summarize([
            {"program_id": "p1", "pipeline": "baseline", "reference_verdict": "VIOLATION",
             "overall_verdict": "SAFE", "end_to_end_duration_ms": 2},
            {"program_id": "p2", "pipeline": "baseline", "reference_verdict": "SAFE",
             "overall_verdict": "VIOLATION", "end_to_end_duration_ms": 3},
        ], bootstrap_samples=100, seed=7)
        by_prog = {r["program_id"]: r for r in report["per_program_pipeline"]}
        self.assertEqual(len(by_prog), 2)
        # p1: reference VIOLATION but produced SAFE -> false_safe_count is 1
        self.assertEqual(by_prog["p1"]["false_safe_count"], 1)
        self.assertEqual(by_prog["p1"]["false_reject_count"], 0)
        self.assertEqual(by_prog["p1"]["oracle_agreement_rate"], 0.0)
        # p2: reference SAFE but produced VIOLATION -> false_reject_count is 1
        self.assertEqual(by_prog["p2"]["false_safe_count"], 0)
        self.assertEqual(by_prog["p2"]["false_reject_count"], 1)
        self.assertEqual(by_prog["p2"]["oracle_agreement_rate"], 0.0)

    def test_multiple_programs_maintain_independent_aggregates(self):
        report = summarize([
            {"program_id": "p1", "pipeline": "baseline", "reference_verdict": "SAFE",
             "overall_verdict": "SAFE", "end_to_end_duration_ms": 10},
            {"program_id": "p2", "pipeline": "baseline", "reference_verdict": "VIOLATION",
             "overall_verdict": "VIOLATION", "end_to_end_duration_ms": 20},
        ], bootstrap_samples=100, seed=7)
        by_prog = {r["program_id"]: r for r in report["per_program_pipeline"]}
        self.assertEqual(len(by_prog), 2)
        self.assertEqual(by_prog["p1"]["oracle_agreement_rate"], 1.0)
        self.assertEqual(by_prog["p2"]["oracle_agreement_rate"], 1.0)
        self.assertEqual(by_prog["p1"]["end_to_end_ms_median"], 10.0)
        self.assertEqual(by_prog["p2"]["end_to_end_ms_median"], 20.0)

    def test_single_program_multiple_runs_accumulates_errors(self):
        report = summarize([
            {"program_id": "p1", "pipeline": "baseline", "reference_verdict": "VIOLATION",
             "overall_verdict": "SAFE", "end_to_end_duration_ms": 2},
            {"program_id": "p1", "pipeline": "baseline", "reference_verdict": "SAFE",
             "overall_verdict": "VIOLATION", "end_to_end_duration_ms": 3},
        ], bootstrap_samples=100, seed=7)
        self.assertEqual(len(report["per_program_pipeline"]), 1)
        row = report["per_program_pipeline"][0]
        self.assertEqual(row["false_safe_count"], 1)
        self.assertEqual(row["false_reject_count"], 1)
        self.assertEqual(row["run_count"], 2)
        self.assertEqual(row["oracle_agreement_rate"], 0.0)

    def test_timeouts_and_errors_counted_as_unresolved(self):
        report = summarize([
            {"program_id": "p1", "pipeline": "baseline", "overall_verdict": "TIMEOUT"},
            {"program_id": "p1", "pipeline": "baseline", "overall_verdict": "ERROR"},
            {"program_id": "p1", "pipeline": "baseline", "overall_verdict": "UNKNOWN"},
        ], bootstrap_samples=100, seed=7)
        row = report["per_program_pipeline"][0]
        self.assertEqual(row["unknown_or_unresolved_count"], 3)
        self.assertEqual(row["unknown_count"], 1)
        self.assertEqual(row["timeout_count"], 1)
        self.assertEqual(row["error_count"], 1)
        self.assertEqual(row["oracle_comparisons"], 0)

    def test_warmup_runs_excluded_from_latency_metrics(self):
        report = summarize([
            {"program_id": "p1", "pipeline": "baseline", "end_to_end_duration_ms": 100.0,
             "is_warmup": True},
            {"program_id": "p1", "pipeline": "baseline", "end_to_end_duration_ms": 10.0,
             "is_warmup": False},
            {"program_id": "p1", "pipeline": "baseline", "end_to_end_duration_ms": 12.0,
             "is_warmup": False},
        ], bootstrap_samples=100, seed=7)
        row = report["per_program_pipeline"][0]
        self.assertEqual(row["run_count"], 3)
        self.assertEqual(row["warmup_count"], 1)
        self.assertEqual(row["measured_count"], 2)
        # Median of [10.0, 12.0] is 11.0; 100.0 warmup must be excluded
        self.assertEqual(row["end_to_end_ms_median"], 11.0)
        self.assertEqual(row["end_to_end_ms_mean"], 11.0)

    def test_only_explicit_pair_ids_create_paired_estimates(self):
        rows = [
            {"program_id": "p", "pipeline": "baseline", "pair_id": "run-1",
             "end_to_end_duration_ms": 10},
            {"program_id": "p", "pipeline": "experiment", "pair_id": "run-1",
             "end_to_end_duration_ms": 12},
            {"program_id": "q", "pipeline": "baseline", "end_to_end_duration_ms": 8},
            {"program_id": "q", "pipeline": "experiment", "end_to_end_duration_ms": 5},
        ]
        report = summarize(rows, bootstrap_samples=100, seed=7)
        pair = report["paired_latency_comparisons"][0]
        self.assertEqual(pair["paired_n"], 1)
        self.assertEqual(pair["mean_difference_ms"], 2.0)

    def test_input_rows_require_pipeline_and_program(self):
        with self.assertRaises(ValueError):
            summarize([{"overall_verdict": "SAFE"}])


if __name__ == "__main__":
    unittest.main()
