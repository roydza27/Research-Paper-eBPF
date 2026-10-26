#!/usr/bin/env python3
"""Contract-level unit tests for region-level verification data structures and composition.

Validates the mathematical and structural invariants of RegionBoundary, IncomingAbstractState,
RegionResult, and ProgramVerdictComposer without simulating an unimplemented verifier.
"""
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from region_contract import (
    AbstractRegisterState,
    AbstractValue,
    AnalysisMethod,
    IncomingAbstractState,
    ProgramVerdictComposer,
    RegionBoundary,
    RegionResult,
    RegionVerdict,
    ScopeLevel,
)


class RegionBoundaryValidationTests(unittest.TestCase):
    def test_invalid_region_boundaries_rejected(self):
        # 1. Empty blocks rejected
        with self.assertRaises(ValueError):
            RegionBoundary(
                region_id="r1",
                entry_block_id="bb_0",
                blocks=(),
            )

        # 2. Entry block not in constituent blocks rejected
        with self.assertRaises(ValueError):
            RegionBoundary(
                region_id="r1",
                entry_block_id="bb_missing",
                blocks=("bb_0", "bb_1"),
                scope=ScopeLevel.MULTI_BLOCK_REGION,
            )

        # 3. Exit block not in constituent blocks rejected
        with self.assertRaises(ValueError):
            RegionBoundary(
                region_id="r1",
                entry_block_id="bb_0",
                blocks=("bb_0", "bb_1"),
                exit_blocks=("bb_outside",),
                scope=ScopeLevel.MULTI_BLOCK_REGION,
            )

        # 4. BASIC_BLOCK scope with multiple blocks rejected
        with self.assertRaises(ValueError):
            RegionBoundary(
                region_id="r1",
                entry_block_id="bb_0",
                blocks=("bb_0", "bb_1"),
                scope=ScopeLevel.BASIC_BLOCK,
            )

    def test_valid_region_boundary_accepted(self):
        rb = RegionBoundary(
            region_id="r_branch",
            entry_block_id="bb_0",
            blocks=("bb_0", "bb_1", "bb_2"),
            predecessors=(),
            successors=("bb_3",),
            exit_blocks=("bb_1", "bb_2"),
            scope=ScopeLevel.MULTI_BLOCK_REGION,
        )
        self.assertEqual(rb.region_id, "r_branch")
        self.assertEqual(len(rb.blocks), 3)


class IncomingAbstractStateTests(unittest.TestCase):
    def test_missing_incoming_state_does_not_default_to_safe(self):
        # Uninitialized / non-explicit incoming state is rejected
        with self.assertRaises(ValueError):
            IncomingAbstractState(
                registers=AbstractRegisterState.default_entry(),
                is_explicit=False,
            )

        # None registers rejected
        with self.assertRaises(ValueError):
            IncomingAbstractState(
                registers=None,  # type: ignore
                is_explicit=True,
            )

    def test_explicit_incoming_state_stores_constraints(self):
        regs = AbstractRegisterState.default_entry()
        state = IncomingAbstractState(
            registers=regs,
            path_constraints=("r1 > 0", "r2 == 0"),
        )
        self.assertEqual(len(state.path_constraints), 2)
        self.assertTrue(state.is_explicit)


class RegionResultValidationTests(unittest.TestCase):
    def setUp(self):
        self.entry_state = IncomingAbstractState(
            registers=AbstractRegisterState.default_entry()
        )

    def test_unknown_error_timeout_remain_non_safe(self):
        # UNKNOWN requires an unresolved_reason
        with self.assertRaises(ValueError):
            RegionResult(
                region_id="r1",
                verdict=RegionVerdict.UNKNOWN,
                scope=ScopeLevel.BASIC_BLOCK,
                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                entry_assumptions=self.entry_state,
                unresolved_reason=None,  # Missing reason rejected
            )

        # Contradiction: SAFE with unresolved_reason rejected
        with self.assertRaises(ValueError):
            RegionResult(
                region_id="r1",
                verdict=RegionVerdict.SAFE,
                scope=ScopeLevel.BASIC_BLOCK,
                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                entry_assumptions=self.entry_state,
                unresolved_reason="Timeout in lifter",
            )

    def test_region_verdict_includes_assumptions_and_scope(self):
        res = RegionResult(
            region_id="r_bb0",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
            exit_states={"r0": AbstractValue.const(2)},
        )
        self.assertEqual(res.region_id, "r_bb0")
        self.assertEqual(res.scope, ScopeLevel.BASIC_BLOCK)
        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        self.assertIsNotNone(res.entry_assumptions)

    def test_whole_program_fallback_cannot_be_mislabeled_as_region_scoped(self):
        # An execution backend with whole-program scope (e.g. KRAKENGUARD)
        # cannot be labeled as a BASIC_BLOCK or MULTI_BLOCK_REGION verdict
        with self.assertRaises(ValueError):
            RegionResult(
                region_id="r_bb0",
                verdict=RegionVerdict.SAFE,
                scope=ScopeLevel.BASIC_BLOCK,  # Mislabeled scope!
                analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
                entry_assumptions=self.entry_state,
                backend_executor_scope=ScopeLevel.WHOLE_PROGRAM,  # Backend executed whole ELF
            )


class PredecessorJoinTests(unittest.TestCase):
    def test_multiple_predecessor_states_require_explicit_join_or_unresolved(self):
        # State from Path A: r1 = 10
        regs_a = AbstractRegisterState(registers={
            **{f"r{i}": AbstractValue.unknown() for i in range(10)},
            "r1": AbstractValue.const(10),
            "r10": AbstractValue.const(0),
        })

        # State from Path B: r1 = 20
        regs_b = AbstractRegisterState(registers={
            **{f"r{i}": AbstractValue.unknown() for i in range(10)},
            "r1": AbstractValue.const(20),
            "r10": AbstractValue.const(0),
        })

        # Sound join computes bounded interval [10, 20]
        joined = regs_a.join(regs_b)
        val = joined.get("r1")
        self.assertEqual(val.kind, "interval")
        self.assertEqual(val.value, (10, 20))

        # Join with unknown yields sound unknown
        regs_c = AbstractRegisterState(registers={
            **{f"r{i}": AbstractValue.unknown() for i in range(10)},
            "r1": AbstractValue.unknown(),
            "r10": AbstractValue.const(0),
        })
        joined_unk = regs_a.join(regs_c)
        self.assertTrue(joined_unk.get("r1").is_unknown())


class ProgramCompositionTests(unittest.TestCase):
    def setUp(self):
        self.entry_state = IncomingAbstractState(
            registers=AbstractRegisterState.default_entry()
        )

    def test_unresolved_reachable_path_prevents_program_safe(self):
        # Region r1 is SAFE, but Region r2 is UNKNOWN
        r1 = RegionResult(
            region_id="r1",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
        )
        r2 = RegionResult(
            region_id="r2",
            verdict=RegionVerdict.UNKNOWN,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
            unresolved_reason="Unsupported packet store instruction",
        )

        outcome = ProgramVerdictComposer.compose([r1, r2], reachable_region_ids=["r1", "r2"])
        # Whole program CANNOT be safe if any reachable region is UNKNOWN
        self.assertEqual(outcome["overall_verdict"], RegionVerdict.UNKNOWN.value)
        self.assertEqual(outcome["disposition"], "unresolved")
        self.assertFalse(outcome["soundly_discharged"])

    def test_confirmed_reachable_violation_terminates_early(self):
        # Region r1 has a confirmed policy violation
        r1 = RegionResult(
            region_id="r1",
            verdict=RegionVerdict.VIOLATION,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
            violating_path_evidence="Helper 9999 forbidden by policy",
        )

        # Region r2 was not even analyzed (or unknown)
        outcome = ProgramVerdictComposer.compose([r1], reachable_region_ids=["r1"])
        self.assertEqual(outcome["overall_verdict"], RegionVerdict.VIOLATION.value)
        self.assertEqual(outcome["disposition"], "violation")
        self.assertTrue(outcome["soundly_discharged"])
        self.assertEqual(outcome["violating_region"], "r1")

    def test_all_reachable_safe_yields_program_safe(self):
        r1 = RegionResult(
            region_id="r1",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
        )
        r2 = RegionResult(
            region_id="r2",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=self.entry_state,
        )

        outcome = ProgramVerdictComposer.compose([r1, r2], reachable_region_ids=["r1", "r2"])
        self.assertEqual(outcome["overall_verdict"], RegionVerdict.SAFE.value)
        self.assertEqual(outcome["disposition"], "pass")
        self.assertTrue(outcome["soundly_discharged"])


if __name__ == "__main__":
    unittest.main()
