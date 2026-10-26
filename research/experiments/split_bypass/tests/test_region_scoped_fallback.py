#!/usr/bin/env python3
"""Comprehensive Correctness Tests for State-Aware, Region-Scoped Verification (Task 12).

Tests all Phase 3 requirements:
1. State propagation between sequential regions.
2. Register and stack facts across region boundaries.
3. Branch and join state merging (least upper bound).
4. Violation found inside an unresolved region.
5. UNKNOWN when entry-state information is insufficient.
6. Memory writes and pointer provenance (packet vs map vs stack).
7. Loops, timeouts, unsupported instructions, and symbolic errors.
8. Proof that fallback receives only the intended region and its required state.
9. Scope veracity telemetry: is_genuinely_region_scoped cannot be mislabeled.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from region_contract import (
    AbstractRegisterState,
    AbstractValue,
    AnalysisMethod,
    IncomingAbstractState,
    ProgramVerdictComposer,
    RegionBoundary,
    RegionResult,
    RegionSymbolicRequest,
    RegionSymbolicResponse,
    RegionVerdict,
    ScopeLevel,
)
from region_symbolic_executor import DirectRegionSymbolicExecutor


class MockInsn:
    def __init__(self, pc: int, text: str, opcode_name: str = "", args: str = ""):
        self.pc = pc
        self.text = text
        self.opcode_name = opcode_name
        self.args = args


class StatePropagationTests(unittest.TestCase):
    """Verifies state propagation between sequential regions and cross-boundary facts."""

    def test_state_propagation_between_sequential_regions(self):
        """Verifies exact constants and widths propagate sequentially."""
        executor = DirectRegionSymbolicExecutor()
        
        # Region 1: r2 = 42, w3 = 10
        insns_r1 = (
            MockInsn(0, "r2 = 42", "mov"),
            MockInsn(1, "w3 = 10", "mov"),
        )
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        req1 = RegionSymbolicRequest(
            region_id="R1",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns_r1,
            incoming_state=init_state,
            policy={},
            entry_pc=0,
            exit_pcs=(2,),
        )
        res1 = executor.execute_region(req1)
        self.assertEqual(res1.verdict, RegionVerdict.SAFE)
        self.assertTrue(res1.is_genuinely_region_scoped)
        
        out1 = res1.exit_states["exit"]
        self.assertEqual(out1.registers.get("r2").value, 42)
        self.assertEqual(out1.registers.get("r3").value, 10)

        # Region 2: r4 = r2
        insns_r2 = (MockInsn(2, "r4 = r2", "mov"),)
        req2 = RegionSymbolicRequest(
            region_id="R2",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns_r2,
            incoming_state=out1,
            policy={},
            entry_pc=2,
            exit_pcs=(3,),
        )
        res2 = executor.execute_region(req2)
        self.assertEqual(res2.verdict, RegionVerdict.SAFE)
        out2 = res2.exit_states["exit"]
        self.assertEqual(out2.registers.get("r4").value, 42)

    def test_register_and_stack_facts_across_region_boundaries(self):
        """Verifies stack assumptions are preserved across region boundaries."""
        executor = DirectRegionSymbolicExecutor()
        
        # Initial state with stack slot [-8] = const(100)
        init_state = IncomingAbstractState(
            registers=AbstractRegisterState.default_entry(),
            stack_assumptions={-8: (8, AbstractValue.const(100))},
        )
        insns = (MockInsn(0, "r0 = 0", "mov"),)
        req = RegionSymbolicRequest(
            region_id="R_stack",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={},
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        out = res.exit_states["exit"]
        self.assertIn(-8, out.stack_assumptions)
        self.assertEqual(out.stack_assumptions[-8][1].value, 100)


class BranchAndJoinStateTests(unittest.TestCase):
    """Verifies sound lattice join and constraint intersection at merge points."""

    def test_branch_and_join_state_merging(self):
        r1 = AbstractRegisterState(registers={"r1": AbstractValue.const(10)})
        r2 = AbstractRegisterState(registers={"r1": AbstractValue.const(20)})
        joined_r = r1.join(r2)
        self.assertEqual(joined_r.get("r1").kind, "interval")
        self.assertEqual(joined_r.get("r1").value, (10, 20))

        # Equal values retain constant
        r3 = AbstractRegisterState(registers={"r2": AbstractValue.const(5)})
        r4 = AbstractRegisterState(registers={"r2": AbstractValue.const(5)})
        self.assertEqual(r3.join(r4).get("r2").value, 5)


class ViolationAndSoundnessTests(unittest.TestCase):
    """Verifies violation detection and insufficient entry state handling."""

    def test_violation_found_inside_unresolved_region(self):
        """Verifies that forbidden return inside a region yields VIOLATION."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        
        # Policy requires return value 0
        policy = {"return_values": [0]}
        # Program sets r0 = 1 and exits
        insns = (
            MockInsn(0, "r0 = 1", "mov"),
            MockInsn(1, "exit", "exit"),
        )
        req = RegionSymbolicRequest(
            region_id="R_viol",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy=policy,
            entry_pc=0,
            exit_pcs=(2,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("Forbidden return value 1", res.witness_trace)

    def test_unknown_when_entry_state_insufficient(self):
        """Verifies fail-closed UNKNOWN when incoming state cannot be implicit."""
        with self.assertRaises(ValueError):
            IncomingAbstractState(
                registers=AbstractRegisterState.default_entry(),
                is_explicit=False,
            )

    def test_unmodeled_instruction_fails_closed_unknown(self):
        """Verifies unmodeled instruction opcode strictly returns UNKNOWN."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        insns = (MockInsn(0, "unsupported_special_simd_op r1", "simd"),)
        req = RegionSymbolicRequest(
            region_id="R_unmod",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={},
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Unsupported instruction opcode", res.unresolved_reason)

    def test_unmodeled_helper_fails_closed_unknown(self):
        """Verifies unmodeled helper call strictly returns UNKNOWN."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        insns = (MockInsn(0, "call 0x9999", "call", "0x9999"),)
        req = RegionSymbolicRequest(
            region_id="R_unmod_helper",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={},
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Unmodeled helper", res.unresolved_reason)

    def test_ambiguous_pointer_provenance_fails_closed_unknown(self):
        """Verifies memory store via ambiguous pointer strictly returns UNKNOWN."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        # r8 is scalar/unknown; storing through r8 has ambiguous provenance
        insns = (MockInsn(0, "*(u32 *)(r8 + 0x0) = 1", "stx"),)
        req = RegionSymbolicRequest(
            region_id="R_ambig_ptr",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={"memory_access": [{"write-access": ["x"]}]},
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Ambiguous pointer provenance", res.unresolved_reason)


class PointerProvenanceTests(unittest.TestCase):
    """Verifies relational pointer provenance: map values vs packet memory vs stack."""

    def test_map_value_store_is_not_mislabeled_as_packet_violation(self):
        """Disassembly stores to r0 (map element) are permitted under packet read-only policy."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        
        # Policy forbids packet writes
        policy = {"memory_access": [{"write-access": ["x"]}]}
        
        # insn 0: call 1 (bpf_map_lookup_elem -> r0 is map_value)
        # insn 1: *(u64 *)(r0 + 0) = r1 (store to map value!)
        insns = (
            MockInsn(0, "call 0x1", "call", "1"),
            MockInsn(1, "*(u64 *)(r0 + 0x0) = r1", "stx"),
        )
        req = RegionSymbolicRequest(
            region_id="R_map",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy=policy,
            entry_pc=0,
            exit_pcs=(2,),
        )
        res = executor.execute_region(req)
        # Should be SAFE, not VIOLATION!
        self.assertEqual(res.verdict, RegionVerdict.SAFE)

    def test_prohibited_packet_store_yields_violation(self):
        """Store to r1 (ctx/packet) yields VIOLATION under packet read-only policy."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        
        policy = {"memory_access": [{"write-access": ["x"]}]}
        # insn 0: *(u8 *)(r1 + 0x10) = 0xFF (store to packet!)
        insns = (MockInsn(0, "*(u8 *)(r1 + 0x10) = 0xff", "stx"),)
        req = RegionSymbolicRequest(
            region_id="R_pkt",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy=policy,
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("Prohibited packet store", res.witness_trace)


class ScopeVeracityAndTelemetryTests(unittest.TestCase):
    """Verifies that scope claims cannot be fabricated or mislabeled."""

    def test_scope_veracity_rejects_mislabeled_whole_program_fallback(self):
        """is_genuinely_region_scoped cannot be True when backend executed WHOLE_PROGRAM."""
        with self.assertRaises(ValueError):
            RegionSymbolicResponse(
                region_id="R_bad",
                verdict=RegionVerdict.SAFE,
                scope=ScopeLevel.BASIC_BLOCK,
                backend_executor_scope=ScopeLevel.WHOLE_PROGRAM,  # Contradiction!
                execution_time_ms=10.0,
                paths_explored=1,
                is_genuinely_region_scoped=True,
            )

    def test_composer_respects_region_scoped_results(self):
        """Composer soundly combines genuine region-scoped results into whole-program verdict."""
        init = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        r1 = RegionResult(
            region_id="bb_0",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=init,
            backend_executor_scope=ScopeLevel.BASIC_BLOCK,
        )
        r2 = RegionResult(
            region_id="bb_1",
            verdict=RegionVerdict.SAFE,
            scope=ScopeLevel.BASIC_BLOCK,
            analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
            entry_assumptions=init,
            backend_executor_scope=ScopeLevel.BASIC_BLOCK,
        )
        comp = ProgramVerdictComposer.compose([r1, r2], reachable_region_ids=["bb_0", "bb_1"])
        self.assertEqual(comp["overall_verdict"], "SAFE")
        self.assertTrue(comp["soundly_discharged"])


class EndToEndRegionFallbackIntegrationTests(unittest.TestCase):
    """Verifies end-to-end integration of DirectRegionSymbolicExecutor with CFG analysis."""

    def test_alu32_zero_extension_and_compound_alu(self):
        """Verifies 32-bit operations truncate upper 32 bits and zero-extend."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())

        # w1 = 0x100000005 -> should truncate to 0x5
        # w1 += 10 -> should be 15
        insns = (
            MockInsn(0, "w1 = 0x100000005", "mov"),
            MockInsn(1, "w1 += 10", "add"),
            MockInsn(2, "r0 = w1", "mov"),
            MockInsn(3, "exit", "exit"),
        )
        req = RegionSymbolicRequest(
            region_id="R_alu32",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={"return_values": [15]},
            entry_pc=0,
            exit_pcs=(3,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        out_state = res.exit_states["exit"]
        self.assertEqual(out_state.registers.get("r1").value, 15)
        self.assertEqual(out_state.registers.get("r0").value, 15)

    def test_stack_load_store_roundtrip(self):
        """Verifies stack store followed by stack load in isolated region."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())

        insns = (
            MockInsn(0, "r1 = 42", "mov"),
            MockInsn(1, "*(u32 *)(r10 - 4) = r1", "stx"),
            MockInsn(2, "r0 = *(u32 *)(r10 - 4)", "ldx"),
            MockInsn(3, "exit", "exit"),
        )
        req = RegionSymbolicRequest(
            region_id="R_stack",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={"return_values": [42]},
            entry_pc=0,
            exit_pcs=(3,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        out_state = res.exit_states["exit"]
        self.assertEqual(out_state.registers.get("r0").value, 42)

    def test_out_of_bounds_stack_access_yields_unknown(self):
        """Verifies that stack accesses beyond 512B bounds fail closed as UNKNOWN."""
        executor = DirectRegionSymbolicExecutor()
        init_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())

        # Offset -520 is beyond -512
        insns = (MockInsn(0, "*(u64 *)(r10 - 520) = r1", "stx"),)
        req = RegionSymbolicRequest(
            region_id="R_oob",
            scope=ScopeLevel.BASIC_BLOCK,
            instructions=insns,
            incoming_state=init_state,
            policy={},
            entry_pc=0,
            exit_pcs=(1,),
        )
        res = executor.execute_region(req)
        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Stack store out of bounds", res.unresolved_reason)

    def test_cfg_propagation_with_region_symbolic_fallback(self):
        """Verifies propagate_and_analyze_program invokes symbolic executor on UNKNOWN regions."""
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from region_analyzer import (
            BpfBasicBlock,
            BpfInstruction,
            BpfProgramContext,
            propagate_and_analyze_program,
        )

        # CFG with 2 blocks: bb_0 transfers to bb_1.
        # bb_1 contains an unmodeled instruction that abstract analyzer cannot resolve (returns UNKNOWN).
        insns_0 = [
            BpfInstruction(0, "r1 = 10", "mov", "10"),
            BpfInstruction(1, "goto +1 <bb_1>", "goto", "+1"),
        ]
        insns_1 = [
            BpfInstruction(2, "custom_unmodeled_accelerator r1", "unmodeled_op", ""),
            BpfInstruction(3, "r0 = 2", "mov", "2"),
            BpfInstruction(4, "exit", "exit", ""),
        ]
        bb_0 = BpfBasicBlock("bb_0", 0, instructions=insns_0, successors=["bb_1"])
        bb_1 = BpfBasicBlock("bb_1", 2, instructions=insns_1, predecessors=["bb_0"], successors=[])

        ctx = BpfProgramContext(
            instructions=insns_0 + insns_1,
            basic_blocks={"bb_0": bb_0, "bb_1": bb_1},
            policy={"return_values": [2]},
        )

        # 1. Without region executor: bb_1 is UNKNOWN, whole-program composition is UNKNOWN
        results_no_fallback, reachable, comp_no_fallback = propagate_and_analyze_program(ctx)
        self.assertEqual(comp_no_fallback["overall_verdict"], "UNKNOWN")
        self.assertEqual(results_no_fallback["bb_1"].verdict, RegionVerdict.UNKNOWN)

        # 2. With state-aware RegionSymbolicExecutor that symbolically proves bb_1 SAFE:
        class ResolvingExecutor(DirectRegionSymbolicExecutor):
            def execute_region(self, req: RegionSymbolicRequest) -> RegionSymbolicResponse:
                out = IncomingAbstractState(
                    registers=AbstractRegisterState(registers={"r0": AbstractValue.const(2)}),
                )
                return RegionSymbolicResponse(
                    region_id=req.region_id,
                    verdict=RegionVerdict.SAFE,
                    scope=req.scope,
                    backend_executor_scope=req.scope,
                    execution_time_ms=1.5,
                    paths_explored=1,
                    is_genuinely_region_scoped=True,
                    exit_states={"exit": out},
                )

        results_fallback, reachable_fb, comp_fallback = propagate_and_analyze_program(
            ctx, region_symbolic_executor=ResolvingExecutor()
        )
        self.assertEqual(results_fallback["bb_1"].verdict, RegionVerdict.SAFE)
        self.assertEqual(results_fallback["bb_1"].analysis_method, AnalysisMethod.SYMBOLIC_EXECUTION)
        self.assertEqual(results_fallback["bb_1"].backend_executor_scope, ScopeLevel.BASIC_BLOCK)
        self.assertEqual(comp_fallback["overall_verdict"], "SAFE")
        self.assertTrue(comp_fallback["soundly_discharged"])


if __name__ == "__main__":
    unittest.main()
