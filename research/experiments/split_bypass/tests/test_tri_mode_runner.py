#!/usr/bin/env python3
"""Validation tests for tri-mode runner integration and telemetry instrumentation.

Validates:
1. Mode dispatch for Mode A (symbolic_only), Mode B (whole_hybrid), and Mode C (region_hybrid).
2. Proper analyzer naming, scopes, and fallback scopes.
3. SAFE, VIOLATION, UNKNOWN, error, and timeout handling across all modes.
4. Fallback replacement of UNKNOWN only on authoritative symbolic completion.
5. Errors and timeouts NEVER becoming SAFE.
6. Telemetry consistency, monotonic timing boundaries, and explicit None (not 0.0) for skipped stages.
7. Oracle agreement status, ensuring UNKNOWN is never treated as agreement.
8. Warmup run status and exclusion from latency aggregates.
"""
from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCRIPTS_DIR = REPO_ROOT / "research" / "experiments" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
SPLIT_SCRIPTS_DIR = REPO_ROOT / "research" / "experiments" / "split_bypass" / "scripts"
if str(SPLIT_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SPLIT_SCRIPTS_DIR))

# Import runner components
from split_analyze_bypass import (
    MODE_REGION_HYBRID,
    MODE_SYMBOLIC_ONLY,
    MODE_WHOLE_HYBRID,
    compute_oracle_agreement,
    normalize_mode,
    run_program,
    tri_mode_gate,
)
from analyze_runs import summarize


def make_verdict(v: str, **kwargs: Any) -> dict[str, Any]:
    return {"verdict": v, **kwargs}


class TriModeDispatchTests(unittest.TestCase):
    """Proves each mode dispatches to its intended implementation and analyzer."""

    def test_mode_a_symbolic_only_dispatches_symbolic_directly(self):
        abstract_called = []
        symbolic_called = []

        def abs_runner():
            abstract_called.append(True)
            return make_verdict("SAFE")

        def sym_runner():
            symbolic_called.append(True)
            return make_verdict("SAFE")

        res = tri_mode_gate(
            MODE_SYMBOLIC_ONLY,
            abstract_runner=abs_runner,
            symbolic_runner=sym_runner,
        )

        self.assertEqual(abstract_called, [], "Mode A must not call abstract analyzer")
        self.assertEqual(len(symbolic_called), 1, "Mode A must call symbolic verifier")
        self.assertEqual(res["analyzer"], "krakenguard_symbolic")
        self.assertEqual(res["analyzer_scope"], "whole_program")
        self.assertIsNone(res["abstract_verdict"], "Abstract verdict must be None in Mode A")
        self.assertIsNone(res["abstract_duration_ms"], "Abstract duration must be None in Mode A")
        self.assertFalse(res["fallback_invoked"], "Mode A does not invoke fallback; symbolic is primary")
        self.assertIsNone(res["fallback_scope"], "Fallback scope must be None when no fallback occurs")
        self.assertTrue(res["symbolic_invoked"])
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertEqual(res["disposition"], "symbolic_pass")

    def test_mode_b_whole_hybrid_dispatches_legacy_analyzer(self):
        abstract_called = []
        symbolic_called = []

        def abs_runner():
            abstract_called.append(True)
            return make_verdict("SAFE")

        def sym_runner():
            symbolic_called.append(True)
            return make_verdict("SAFE")

        res = tri_mode_gate(
            MODE_WHOLE_HYBRID,
            abstract_runner=abs_runner,
            symbolic_runner=sym_runner,
        )

        self.assertEqual(len(abstract_called), 1)
        self.assertEqual(symbolic_called, [], "Abstract SAFE must bypass symbolic verifier")
        self.assertEqual(res["analyzer"], "legacy_whole_program_analyzer")
        self.assertEqual(res["analyzer_scope"], "whole_program")
        self.assertEqual(res["abstract_verdict"], "SAFE")
        self.assertIsNotNone(res["abstract_duration_ms"])
        self.assertFalse(res["fallback_invoked"])
        self.assertIsNone(res["fallback_scope"])
        self.assertFalse(res["symbolic_invoked"])
        self.assertIsNone(res["symbolic_duration_ms"], "Symbolic duration must be None when bypassed")
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertEqual(res["disposition"], "abstract_pass")

    def test_mode_c_region_hybrid_dispatches_region_analyzer(self):
        abstract_called = []
        symbolic_called = []

        def abs_runner():
            abstract_called.append(True)
            return make_verdict("SAFE")

        def sym_runner():
            symbolic_called.append(True)
            return make_verdict("SAFE")

        res = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=abs_runner,
            symbolic_runner=sym_runner,
        )

        self.assertEqual(len(abstract_called), 1)
        self.assertEqual(symbolic_called, [], "Region abstract SAFE must bypass symbolic verifier")
        self.assertEqual(res["analyzer"], "region_level_analyzer")
        self.assertEqual(res["analyzer_scope"], "region_level")
        self.assertEqual(res["abstract_verdict"], "SAFE")
        self.assertIsNotNone(res["abstract_duration_ms"])
        self.assertFalse(res["fallback_invoked"])
        self.assertIsNone(res["fallback_scope"])
        self.assertFalse(res["symbolic_invoked"])
        self.assertIsNone(res["symbolic_duration_ms"])
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertEqual(res["disposition"], "abstract_pass")

    def test_mode_c_region_hybrid_unresolved_falls_back_to_whole_program_symbolic(self):
        abstract_called = []
        symbolic_called = []

        def abs_runner():
            abstract_called.append(True)
            return make_verdict("UNKNOWN", reason="CFG cycle / back-edge detected")

        def sym_runner():
            symbolic_called.append(True)
            return make_verdict("SAFE", proof="klee compliant")

        res = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=abs_runner,
            symbolic_runner=sym_runner,
        )

        self.assertEqual(len(abstract_called), 1)
        self.assertEqual(len(symbolic_called), 1)
        self.assertEqual(res["analyzer"], "region_level_analyzer")
        self.assertEqual(res["analyzer_scope"], "region_level")
        self.assertEqual(res["abstract_verdict"], "UNKNOWN")
        self.assertTrue(res["fallback_invoked"])
        self.assertEqual(res["fallback_scope"], "whole_program", "KRAKENGUARD fallback is strictly whole_program")
        self.assertTrue(res["symbolic_invoked"])
        self.assertEqual(res["symbolic_verdict"], "SAFE")
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertEqual(res["disposition"], "symbolic_pass")

    def test_invalid_mode_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_mode("nonexistent_mode")


class VerdictAndFallbackHandlingTests(unittest.TestCase):
    """Tests SAFE, VIOLATION, UNKNOWN/fallback, error, and timeout handling."""

    def test_abstract_violation_short_circuits_in_all_hybrid_modes(self):
        for mode in [MODE_WHOLE_HYBRID, MODE_REGION_HYBRID]:
            sym_called = []
            res = tri_mode_gate(
                mode,
                abstract_runner=lambda: make_verdict("VIOLATION", reason="Forbidden helper"),
                symbolic_runner=lambda: sym_called.append(1) or make_verdict("SAFE"),
            )
            self.assertEqual(res["abstract_verdict"], "VIOLATION")
            self.assertEqual(res["overall_verdict"], "VIOLATION")
            self.assertEqual(res["disposition"], "violation")
            self.assertFalse(res["fallback_invoked"])
            self.assertFalse(res["symbolic_invoked"])
            self.assertEqual(sym_called, [])
            self.assertIsNone(res["symbolic_duration_ms"])

    def test_fallback_replaces_unknown_only_on_authoritative_safe(self):
        res = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=lambda: make_verdict("UNKNOWN"),
            symbolic_runner=lambda: make_verdict("SAFE"),
        )
        self.assertEqual(res["abstract_verdict"], "UNKNOWN")
        self.assertEqual(res["symbolic_verdict"], "SAFE")
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertEqual(res["disposition"], "symbolic_pass")

    def test_fallback_replaces_unknown_only_on_authoritative_violation(self):
        res = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=lambda: make_verdict("UNKNOWN"),
            symbolic_runner=lambda: make_verdict("VIOLATION"),
        )
        self.assertEqual(res["abstract_verdict"], "UNKNOWN")
        self.assertEqual(res["symbolic_verdict"], "VIOLATION")
        self.assertEqual(res["overall_verdict"], "VIOLATION")
        self.assertEqual(res["disposition"], "violation")

    def test_fallback_unknown_remains_unresolved(self):
        res = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=lambda: make_verdict("UNKNOWN"),
            symbolic_runner=lambda: make_verdict("UNKNOWN"),
        )
        self.assertEqual(res["abstract_verdict"], "UNKNOWN")
        self.assertEqual(res["symbolic_verdict"], "UNKNOWN")
        self.assertEqual(res["overall_verdict"], "UNKNOWN")
        self.assertEqual(res["disposition"], "unresolved")

    def test_errors_and_timeouts_never_become_safe_mode_a(self):
        # Mode A timeout
        def timeout_runner():
            raise TimeoutError("symbolic verifier exceeded 120s")

        res_to = tri_mode_gate(MODE_SYMBOLIC_ONLY, symbolic_runner=timeout_runner)
        self.assertNotEqual(res_to["overall_verdict"], "SAFE")
        self.assertEqual(res_to["overall_verdict"], "TIMEOUT")
        self.assertEqual(res_to["disposition"], "unresolved")
        self.assertIn("timeout", res_to["symbolic_error"])

        # Mode A error
        def error_runner():
            raise RuntimeError("daemon connection refused")

        res_err = tri_mode_gate(MODE_SYMBOLIC_ONLY, symbolic_runner=error_runner)
        self.assertNotEqual(res_err["overall_verdict"], "SAFE")
        self.assertEqual(res_err["overall_verdict"], "ERROR")
        self.assertEqual(res_err["disposition"], "unresolved")
        self.assertIn("daemon connection refused", res_err["symbolic_error"])

    def test_errors_and_timeouts_never_become_safe_hybrid_modes(self):
        for mode in [MODE_WHOLE_HYBRID, MODE_REGION_HYBRID]:
            # Fallback timeout
            def sym_timeout():
                raise TimeoutError("fallback deadline")

            res_to = tri_mode_gate(
                mode,
                abstract_runner=lambda: make_verdict("UNKNOWN"),
                symbolic_runner=sym_timeout,
            )
            self.assertNotEqual(res_to["overall_verdict"], "SAFE")
            self.assertEqual(res_to["overall_verdict"], "TIMEOUT")
            self.assertEqual(res_to["disposition"], "unresolved")

            # Fallback tool error
            def sym_fail():
                raise RuntimeError("lifter crash")

            res_err = tri_mode_gate(
                mode,
                abstract_runner=lambda: make_verdict("UNKNOWN"),
                symbolic_runner=sym_fail,
            )
            self.assertNotEqual(res_err["overall_verdict"], "SAFE")
            self.assertEqual(res_err["overall_verdict"], "ERROR")
            self.assertEqual(res_err["disposition"], "unresolved")

            # Abstract error with failing symbolic fallback
            def abs_fail():
                raise RuntimeError("ast parse failed")

            res_both_err = tri_mode_gate(
                mode,
                abstract_runner=abs_fail,
                symbolic_runner=sym_fail,
            )
            self.assertNotEqual(res_both_err["overall_verdict"], "SAFE")
            self.assertEqual(res_both_err["overall_verdict"], "ERROR")


class TelemetryAndTimingTests(unittest.TestCase):
    """Validates telemetry schema, monotonic timing boundaries, and missing field representation."""

    def test_missing_measurements_are_explicit_none_not_zero(self):
        # In Mode A: abstract duration is None
        res_a = tri_mode_gate(
            MODE_SYMBOLIC_ONLY,
            symbolic_runner=lambda: make_verdict("SAFE"),
        )
        self.assertIsNone(res_a["abstract_duration_ms"])
        self.assertIsNotNone(res_a["symbolic_duration_ms"])
        self.assertGreater(res_a["symbolic_duration_ms"], 0.0)

        # In Mode C abstract pass: symbolic duration is None
        res_c = tri_mode_gate(
            MODE_REGION_HYBRID,
            abstract_runner=lambda: make_verdict("SAFE"),
            symbolic_runner=lambda: make_verdict("SAFE"),
        )
        self.assertIsNotNone(res_c["abstract_duration_ms"])
        self.assertGreater(res_c["abstract_duration_ms"], 0.0)
        self.assertIsNone(res_c["symbolic_duration_ms"], "Must be None, NOT 0.0")

    def test_run_program_emits_complete_telemetry_payload(self):
        repo_root = Path(__file__).resolve().parents[4]
        obj = repo_root / "research/experiments/split_bypass/programs/A01_straight_small.o"
        pol = repo_root / "research/experiments/split_bypass/policies/policy-c0f0ac4d1a5e.json"

        args = argparse.Namespace(
            mode=MODE_REGION_HYBRID,
            object=str(obj),
            policy=str(pol),
            program_id="A01_straight_small",
            repetition=1,
            is_warmup=False,
            reference_verdict="SAFE",
            fixture_family="A_straight_line",
            policy_id="c0f0ac4d1a5e",
            source=None,
            baseline_dir=None,
            socket_path=None,
            abstract_timeout_seconds=60.0,
            symbolic_timeout_seconds=120.0,
        )

        mock_region_abstract = lambda: {
            "verdict": "SAFE",
            "proof": "All 1 reachable regions proven compliant",
        }

        payload = run_program(args, abstract_runner=mock_region_abstract)

        # Check required schema fields
        self.assertEqual(payload["schema"], "split-bypass-run-record/v2")
        self.assertEqual(payload["program_id"], "A01_straight_small")
        self.assertEqual(payload["mode"], MODE_REGION_HYBRID)
        self.assertEqual(payload["pipeline"], MODE_REGION_HYBRID)
        self.assertEqual(payload["repetition"], 1)
        self.assertFalse(payload["is_warmup"])
        self.assertEqual(payload["analyzer"], "region_level_analyzer")
        self.assertEqual(payload["analyzer_scope"], "region_level")
        self.assertEqual(payload["abstract_stage_verdict"], "SAFE")
        self.assertEqual(payload["overall_verdict"], "SAFE")
        self.assertEqual(payload["final_verdict"], "SAFE")
        self.assertEqual(payload["disposition"], "abstract_pass")
        self.assertFalse(payload["fallback_invoked"])
        self.assertIsNone(payload["fallback_scope"])
        self.assertFalse(payload["symbolic_invoked"])
        self.assertIsNone(payload["symbolic_duration_ms"])
        self.assertIsNotNone(payload["abstract_duration_ms"])
        self.assertIsNotNone(payload["end_to_end_duration_ms"])
        self.assertGreater(payload["end_to_end_duration_ms"], 0.0)

        # Provenance and identity
        self.assertIsNotNone(payload["elf_sha256"])
        self.assertIsNotNone(payload["policy_sha256"])
        self.assertEqual(payload["reference_verdict"], "SAFE")
        self.assertTrue(payload["oracle_agreement"])


class OracleAgreementTests(unittest.TestCase):
    """Proves oracle agreement correctly matches verdicts and NEVER treats UNKNOWN as agreement."""

    def test_safe_agrees_with_safe(self):
        self.assertTrue(compute_oracle_agreement("SAFE", "SAFE"))

    def test_violation_agrees_with_violation(self):
        self.assertTrue(compute_oracle_agreement("VIOLATION", "VIOLATION"))

    def test_safe_disagrees_with_violation(self):
        self.assertFalse(compute_oracle_agreement("SAFE", "VIOLATION"))

    def test_unknown_never_agrees_with_safe(self):
        self.assertFalse(compute_oracle_agreement("SAFE", "UNKNOWN"))

    def test_timeout_never_agrees_with_safe(self):
        self.assertFalse(compute_oracle_agreement("SAFE", "TIMEOUT"))

    def test_error_never_agrees_with_safe(self):
        self.assertFalse(compute_oracle_agreement("SAFE", "ERROR"))

    def test_no_reference_verdict_yields_none(self):
        self.assertIsNone(compute_oracle_agreement(None, "SAFE"))


class WarmupExclusionTests(unittest.TestCase):
    """Proves warmup runs are tagged and excluded from summarizer latency aggregates."""

    def test_warmup_runs_excluded_from_latency_summary(self):
        records = [
            {
                "program_id": "P1",
                "mode": MODE_REGION_HYBRID,
                "pipeline": MODE_REGION_HYBRID,
                "is_warmup": True,
                "repetition": 0,
                "overall_verdict": "SAFE",
                "reference_verdict": "SAFE",
                "end_to_end_duration_ms": 200.0,
                "abstract_duration_ms": 190.0,
            },
            {
                "program_id": "P1",
                "mode": MODE_REGION_HYBRID,
                "pipeline": MODE_REGION_HYBRID,
                "is_warmup": False,
                "repetition": 1,
                "overall_verdict": "SAFE",
                "reference_verdict": "SAFE",
                "end_to_end_duration_ms": 20.0,
                "abstract_duration_ms": 15.0,
            },
            {
                "program_id": "P1",
                "mode": MODE_REGION_HYBRID,
                "pipeline": MODE_REGION_HYBRID,
                "is_warmup": False,
                "repetition": 2,
                "overall_verdict": "SAFE",
                "reference_verdict": "SAFE",
                "end_to_end_duration_ms": 22.0,
                "abstract_duration_ms": 17.0,
            },
        ]

        summary = summarize(records)
        self.assertEqual(len(summary["per_program_pipeline"]), 1)
        row = summary["per_program_pipeline"][0]

        self.assertEqual(row["run_count"], 3)
        self.assertEqual(row["warmup_count"], 1)
        self.assertEqual(row["measured_count"], 2)
        # Median of measured latencies [20.0, 22.0] is 21.0; 200.0 warmup must be excluded!
        self.assertEqual(row["end_to_end_ms_median"], 21.0)
        self.assertEqual(row["abstract_ms_median"], 16.0)
        self.assertEqual(row["oracle_agreement_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
