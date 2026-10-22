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
            "A01_straight_small", "A02_straight_medium", "A03_helper_clock", "A04_map_lookup",
            "B01_branch_safe", "B02_branch_policy_sensitive", "B03_branch_depth",
            "C01_join_different_values", "C02_join_policy_sensitive", "C03_join_violation_candidate",
            "D01_helper_unknown_candidate", "D02_packet_memory_candidate",
            "E01_bounded_loop", "E02_nested_bounded_loop",
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
        rows = report["per_program_pipeline"]
        self.assertEqual(sum(row["false_safe_count"] for row in rows), 1)
        self.assertEqual(sum(row["false_reject_count"] for row in rows), 1)
        self.assertTrue(all(row["oracle_agreement_rate"] == 0.0 for row in rows))

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
