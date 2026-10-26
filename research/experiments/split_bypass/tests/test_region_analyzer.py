#!/usr/bin/env python3
"""Comprehensive unit and integration tests for Region-Level Abstract Interpretation.

Validates:
1. Rejection of uninitialized / implicit incoming states.
2. Instruction transfer functions (constants, intervals, unknowns, ALU operations).
3. Helper policy validation (allowed, forbidden, unknown helpers).
4. Map access policy validation.
5. Exit / return value policy checks.
6. CFG state propagation across sequential and branching paths.
7. Multi-predecessor state join (least upper bound).
8. Cycle / back-edge fail-closed detection.
9. Whole-program sound composition via ProgramVerdictComposer.
10. Integration on actual compiled ELF fixtures from corpus-manifest.json.
"""
from __future__ import annotations

import json
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
from region_analyzer import (
    BpfBasicBlock,
    BpfInstruction,
    BpfProgramContext,
    analyze_region,
    partition_basic_blocks,
    propagate_and_analyze_program,
)


class RegionAnalyzerUnitTests(unittest.TestCase):
    def setUp(self):
        self.default_policy = {
            "p1": {
                "type": "ACTION",
                "actions": {
                    "helper_access": ["bpf_trace_printk", "bpf_map_lookup_elem"],
                    "return_value": [0, 2],
                    "map_access": ["allowed_map"],
                },
            },
            "helper_func": ["bpf_ktime_get_ns"],
        }
        self.entry_state = IncomingAbstractState(
            registers=AbstractRegisterState.default_entry()
        )

    def test_missing_incoming_state_raises_value_error(self):
        ctx = BpfProgramContext(policy=self.default_policy)
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        with self.assertRaises(ValueError):
            analyze_region(ctx, rb, None)  # type: ignore

    def test_basic_block_transfer_constant_alu(self):
        # Program:
        # r1 = 10
        # r2 = 20
        # r1 += 5
        # r2 -= r1
        # exit
        insns = [
            BpfInstruction(0, "r1 = 10", "r1", "= 10"),
            BpfInstruction(1, "r2 = 20", "r2", "= 20"),
            BpfInstruction(2, "r1 += 5", "r1", "+= 5"),
            BpfInstruction(3, "r2 -= r1", "r2", "-= r1"),
            BpfInstruction(4, "r0 = r2", "r0", "= r2"),
            BpfInstruction(5, "exit", "exit", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, is_exit=True)
        ctx = BpfProgramContext(
            instructions=insns,
            basic_blocks={"bb_0": bb},
            policy={"rule": {"actions": {"return_value": [5]}}},
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        self.assertEqual(res.scope, ScopeLevel.BASIC_BLOCK)
        self.assertIn("terminal_exit", res.exit_states)
        exit_regs = res.exit_states["terminal_exit"].registers
        self.assertEqual(exit_regs.get("r1"), AbstractValue.const(15))
        self.assertEqual(exit_regs.get("r2"), AbstractValue.const(5))
        self.assertEqual(exit_regs.get("r0"), AbstractValue.const(5))

    def test_transfer_unknown_alu(self):
        # r1 = unknown
        # r2 = r1 + 10
        # r3 = r2 * 2
        regs = {f"r{i}": AbstractValue.unknown() for i in range(11)}
        insns = [
            BpfInstruction(0, "r2 = r1 + 10", "r2", "= r1 + 10"),
            BpfInstruction(1, "r3 = r2 * 2", "r3", "= r2 * 2"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, successors=["bb_1"])
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",), successors=("bb_1",))
        in_state = IncomingAbstractState(registers=AbstractRegisterState(registers=regs))

        res = analyze_region(ctx, rb, in_state)
        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        out_state = res.exit_states["bb_1"]
        self.assertTrue(out_state.registers.get("r2").is_unknown())
        self.assertTrue(out_state.registers.get("r3").is_unknown())

    def test_forbidden_helper_call_yields_violation(self):
        # Helper 5 is bpf_ktime_get_ns, which is forbidden in default_policy
        insns = [
            BpfInstruction(0, "call 5", "call", "5"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(
            instructions=insns, basic_blocks={"bb_0": bb}, policy=self.default_policy
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("forbidden helper 'bpf_ktime_get_ns'", res.violating_path_evidence)

    def test_unauthorized_helper_call_yields_violation(self):
        # Helper 7 is bpf_get_prandom_u32, not in allowlist
        insns = [
            BpfInstruction(0, "call 7", "call", "7"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(
            instructions=insns, basic_blocks={"bb_0": bb}, policy=self.default_policy
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("unauthorized helper 'bpf_get_prandom_u32'", res.violating_path_evidence)

    def test_allowed_helper_call_sets_r0_and_clobbers_r1_r5(self):
        # Helper 6 is bpf_trace_printk, allowed in default_policy
        insns = [
            BpfInstruction(0, "r1 = 1", "r1", "= 1"),
            BpfInstruction(1, "r2 = 2", "r2", "= 2"),
            BpfInstruction(2, "call 6", "call", "6"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, successors=["bb_1"])
        ctx = BpfProgramContext(
            instructions=insns, basic_blocks={"bb_0": bb}, policy=self.default_policy
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",), successors=("bb_1",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        out_regs = res.exit_states["bb_1"].registers
        self.assertEqual(out_regs.get("r0"), AbstractValue.symbolic("bpf_trace_printk"))
        for r in ["r1", "r2", "r3", "r4", "r5"]:
            self.assertTrue(out_regs.get(r).is_unknown(), f"{r} should be clobbered to unknown")

    def test_unmodeled_helper_id_yields_unknown(self):
        insns = [
            BpfInstruction(0, "call 99999", "call", "99999"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(
            instructions=insns, basic_blocks={"bb_0": bb}, policy=self.default_policy
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Unknown or unmodeled helper id", res.unresolved_reason)

    def test_map_access_unauthorized_map_yields_violation(self):
        # Helper 1 is bpf_map_lookup_elem
        insns = [
            BpfInstruction(0, "call 1", "call", "1"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(
            instructions=insns,
            basic_blocks={"bb_0": bb},
            relocations={0: "unauthorized_map"},
            policy=self.default_policy,
        )
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("unauthorized map 'unauthorized_map'", res.violating_path_evidence)

    def test_unmodeled_instruction_yields_unknown(self):
        insns = [
            BpfInstruction(0, "some_weird_unsupported_insn", "weird", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("Unsupported instruction opcode", res.unresolved_reason)

    def test_exit_return_value_policy_compliance(self):
        policy = {"rule": {"actions": {"return_value": [0, 2]}}}

        # 1. Compliant return (r0 = 2)
        insns_safe = [
            BpfInstruction(0, "r0 = 2", "r0", "= 2"),
            BpfInstruction(1, "exit", "exit", ""),
        ]
        bb_safe = BpfBasicBlock("bb_0", 0, instructions=insns_safe, is_exit=True)
        ctx_safe = BpfProgramContext(instructions=insns_safe, basic_blocks={"bb_0": bb_safe}, policy=policy)
        res_safe = analyze_region(ctx_safe, RegionBoundary("bb_0", "bb_0", ("bb_0",)), self.entry_state)
        self.assertEqual(res_safe.verdict, RegionVerdict.SAFE)

        # 2. Violating return (r0 = 1)
        insns_viol = [
            BpfInstruction(0, "r0 = 1", "r0", "= 1"),
            BpfInstruction(1, "exit", "exit", ""),
        ]
        bb_viol = BpfBasicBlock("bb_0", 0, instructions=insns_viol, is_exit=True)
        ctx_viol = BpfProgramContext(instructions=insns_viol, basic_blocks={"bb_0": bb_viol}, policy=policy)
        res_viol = analyze_region(ctx_viol, RegionBoundary("bb_0", "bb_0", ("bb_0",)), self.entry_state)
        self.assertEqual(res_viol.verdict, RegionVerdict.VIOLATION)
        self.assertIn("forbidden return value 1", res_viol.violating_path_evidence)

        # 3. Indeterminate return (r0 = unknown)
        insns_unk = [
            BpfInstruction(0, "exit", "exit", ""),
        ]
        bb_unk = BpfBasicBlock("bb_0", 0, instructions=insns_unk, is_exit=True)
        ctx_unk = BpfProgramContext(instructions=insns_unk, basic_blocks={"bb_0": bb_unk}, policy=policy)
        res_unk = analyze_region(ctx_unk, RegionBoundary("bb_0", "bb_0", ("bb_0",)), self.entry_state)
        self.assertEqual(res_unk.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("indeterminate return value", res_unk.unresolved_reason)


class RegionPropagationAndCompositionTests(unittest.TestCase):
    def test_sequential_blocks_propagation(self):
        # Block 0: r1 = 42; goto Block 1
        # Block 1: r0 = r1; exit
        insns_b0 = [
            BpfInstruction(0, "r1 = 42", "r1", "= 42"),
            BpfInstruction(1, "goto +0x1", "goto", "+0x1"),
        ]
        insns_b1 = [
            BpfInstruction(2, "r0 = r1", "r0", "= r1"),
            BpfInstruction(3, "exit", "exit", ""),
        ]
        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_2"])
        bb1 = BpfBasicBlock("bb_2", 2, instructions=insns_b1, predecessors=["bb_0"], is_exit=True)
        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_b1,
            basic_blocks={"bb_0": bb0, "bb_2": bb1},
            policy={"rule": {"actions": {"return_value": [42]}}},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertEqual(len(reachable), 2)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.SAFE.value)
        self.assertTrue(composition["soundly_discharged"])

    def test_branching_path_splitting_known_condition(self):
        # r1 = 5
        # if r1 == 5 goto bb_target else bb_fallthrough
        insns_b0 = [
            BpfInstruction(0, "r1 = 5", "r1", "= 5"),
            BpfInstruction(1, "if r1 == 5 goto +0x2", "if", "r1 == 5 goto +0x2"),
        ]
        # Target: r0 = 10; exit
        insns_target = [
            BpfInstruction(3, "r0 = 10", "r0", "= 10"),
            BpfInstruction(4, "exit", "exit", ""),
        ]
        # Fallthrough: r0 = 999; exit (violation)
        insns_fallthrough = [
            BpfInstruction(2, "r0 = 999", "r0", "= 999"),
            BpfInstruction(5, "exit", "exit", ""),
        ]
        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_3", "bb_2"], cond_target="bb_3", fallthrough="bb_2")
        bb_target = BpfBasicBlock("bb_3", 3, instructions=insns_target, predecessors=["bb_0"], is_exit=True)
        bb_fallthrough = BpfBasicBlock("bb_2", 2, instructions=insns_fallthrough, predecessors=["bb_0"], is_exit=True)

        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_fallthrough + insns_target,
            basic_blocks={"bb_0": bb0, "bb_2": bb_fallthrough, "bb_3": bb_target},
            policy={"rule": {"actions": {"return_value": [10]}}},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        # Because r1 == 5 is deterministically true, fallthrough is NOT reachable!
        self.assertIn("bb_3", reachable)
        self.assertNotIn("bb_2", reachable)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.SAFE.value)

    def test_state_merging_join_at_merge_point(self):
        # Entry (bb_0): branching on unknown r1
        # Path A (bb_1): r2 = 10; goto merge (bb_3)
        # Path B (bb_2): r2 = 20; goto merge (bb_3)
        # Merge (bb_3): exit
        insns_b0 = [BpfInstruction(0, "if r1 == 0 goto +0x2", "if", "r1 == 0 goto +0x2")]
        insns_b1 = [BpfInstruction(1, "r2 = 10", "r2", "= 10"), BpfInstruction(2, "goto +0x1", "goto", "+0x1")]
        insns_b2 = [BpfInstruction(3, "r2 = 20", "r2", "= 20"), BpfInstruction(4, "goto +0x0", "goto", "+0x0")]
        insns_b3 = [BpfInstruction(5, "exit", "exit", "")]

        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_3_target", "bb_1"], cond_target="bb_3_target", fallthrough="bb_1")
        bb1 = BpfBasicBlock("bb_1", 1, instructions=insns_b1, predecessors=["bb_0"], successors=["bb_merge"])
        bb2 = BpfBasicBlock("bb_3_target", 3, instructions=insns_b2, predecessors=["bb_0"], successors=["bb_merge"])
        bb_merge = BpfBasicBlock("bb_merge", 5, instructions=insns_b3, predecessors=["bb_1", "bb_3_target"], is_exit=True)

        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_b1 + insns_b2 + insns_b3,
            basic_blocks={"bb_0": bb0, "bb_1": bb1, "bb_3_target": bb2, "bb_merge": bb_merge},
            policy={},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertIn("bb_merge", reachable)
        merge_res = results["bb_merge"]
        # r2 was 10 along bb_1 and 20 along bb_3_target -> joined to interval (10, 20)
        r2_joined = merge_res.entry_assumptions.registers.get("r2")
        self.assertEqual(r2_joined.kind, "interval")
        self.assertEqual(r2_joined.value, (10, 20))

    def test_cycle_backedge_detection_yields_unknown(self):
        # Simple loop: bb_0 jumps to bb_2, bb_2 jumps back to bb_0
        insns_b0 = [BpfInstruction(0, "r1 += 1", "r1", "+= 1"), BpfInstruction(1, "goto +0x1", "goto", "+0x1")]
        insns_b1 = [BpfInstruction(2, "goto -0x2", "goto", "-0x2")]

        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_2"], predecessors=["bb_2"])
        bb1 = BpfBasicBlock("bb_2", 2, instructions=insns_b1, successors=["bb_0"], predecessors=["bb_0"])

        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_b1,
            basic_blocks={"bb_0": bb0, "bb_2": bb1},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.UNKNOWN.value)
        self.assertIn("back-edge", composition["reason"])

    def test_sound_composition_reachable_violation(self):
        # bb_0 is safe, bb_1 violates
        insns_b0 = [BpfInstruction(0, "r1 = 1", "r1", "= 1"), BpfInstruction(1, "goto +0x1", "goto", "+0x1")]
        insns_b1 = [BpfInstruction(2, "call 5", "call", "5")]  # forbidden helper

        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_2"])
        bb1 = BpfBasicBlock("bb_2", 2, instructions=insns_b1, predecessors=["bb_0"])

        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_b1,
            basic_blocks={"bb_0": bb0, "bb_2": bb1},
            policy={"helper_func": ["bpf_ktime_get_ns"]},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.VIOLATION.value)
        self.assertEqual(composition["violating_region"], "bb_2")


class RealCorpusFixtureIntegrationTests(unittest.TestCase):
    def setUp(self):
        manifest_path = Path(__file__).resolve().parents[1] / "manifests" / "corpus-manifest.json"
        self.manifest_path = manifest_path
        self.assertTrue(manifest_path.exists(), f"Corpus manifest not found: {manifest_path}")
        with open(manifest_path) as f:
            self.manifest = json.load(f)

    def _get_program_entry(self, pid: str) -> dict:
        for p in self.manifest["programs"]:
            if p["program_id"] == pid:
                return p
        raise ValueError(f"Program ID '{pid}' not found in manifest")

    def test_straight_line_fixture_a01_discharges_safe(self):
        p = self._get_program_entry("A01_straight_small")
        repo_root = Path(__file__).resolve().parents[4]
        elf_path = repo_root / p["elf_path"]
        policy_path = repo_root / p["policy_path"]

        self.assertTrue(elf_path.exists())
        self.assertTrue(policy_path.exists())

        ctx = BpfProgramContext(object_path=elf_path, policy_path=policy_path)
        results, reachable, composition = propagate_and_analyze_program(ctx)

        self.assertEqual(len(reachable), 1)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.SAFE.value)
        self.assertTrue(composition["soundly_discharged"])

    def test_forbidden_helper_fixture_a03_discharges_violation(self):
        # A03_helper_clock calls helper 5 (bpf_ktime_get_ns)
        p = self._get_program_entry("A03_helper_clock")
        repo_root = Path(__file__).resolve().parents[4]
        elf_path = repo_root / p["elf_path"]

        # Policy explicitly forbidding bpf_ktime_get_ns
        ctx = BpfProgramContext(
            object_path=elf_path,
            policy={"helper_func": ["bpf_ktime_get_ns"]},
        )
        results, reachable, composition = propagate_and_analyze_program(ctx)

        self.assertEqual(composition["overall_verdict"], RegionVerdict.VIOLATION.value)
        self.assertIsNotNone(composition["violating_region"])

    def test_loop_fixture_e01_flags_unknown_conservatively(self):
        p = self._get_program_entry("E01_bounded_loop")
        repo_root = Path(__file__).resolve().parents[4]
        elf_path = repo_root / p["elf_path"]
        policy_path = repo_root / p["policy_path"]

        # Loop with stack spills halts conservatively on CFG back-edge cycle
        ctx = BpfProgramContext(object_path=elf_path, policy_path=policy_path)
        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertEqual(composition["overall_verdict"], RegionVerdict.UNKNOWN.value)
        self.assertIn("back-edge", composition["reason"])

    def test_backend_executor_scope_cannot_be_mislabeled(self):
        # Enforce contract invariant: backend_executor_scope must match region scope
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",), scope=ScopeLevel.BASIC_BLOCK)
        in_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())
        with self.assertRaises(ValueError):
            RegionResult(
                region_id="bb_0",
                verdict=RegionVerdict.SAFE,
                scope=ScopeLevel.BASIC_BLOCK,
                analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
                entry_assumptions=in_state,
                backend_executor_scope=ScopeLevel.WHOLE_PROGRAM,  # Mislabeling rejected!
            )


class StackMemoryModelTests(unittest.TestCase):
    def setUp(self):
        self.entry_state = IncomingAbstractState(
            registers=AbstractRegisterState.default_entry()
        )
        self.packet_ro_policy = {
            "p": {
                "type": "ACTION",
                "actions": {
                    "memory_access": [{"read-access": ["0-54"], "write-access": ["x"]}]
                },
            }
        }

    def test_stack_spill_and_reload_roundtrip(self):
        # Store 42 to stack at -4, reload to r2, verify exact constant
        insns = [
            BpfInstruction(0, "r1 = 42", "r1", "= 42"),
            BpfInstruction(1, "*(u32 *)(r10 - 0x4) = r1", "*", "(u32 *)(r10 - 0x4) = r1"),
            BpfInstruction(2, "r2 = *(u32 *)(r10 - 0x4)", "r2", "= *(u32 *)(r10 - 0x4)"),
            BpfInstruction(3, "exit", "exit", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, is_exit=True)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb}, policy=self.packet_ro_policy)
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        exit_regs = res.exit_states["terminal_exit"].registers
        self.assertEqual(exit_regs.get("r2"), AbstractValue.const(42))

    def test_stack_uninitialized_read_yields_unknown(self):
        # Read from unwritten slot -8
        insns = [
            BpfInstruction(0, "r1 = *(u32 *)(r10 - 0x8)", "r1", "= *(u32 *)(r10 - 0x8)"),
            BpfInstruction(1, "exit", "exit", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, is_exit=True)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        exit_regs = res.exit_states["terminal_exit"].registers
        self.assertTrue(exit_regs.get("r1").is_unknown())

    def test_stack_width_mismatch_yields_unknown(self):
        # Store u32, read as u16 from same offset
        insns = [
            BpfInstruction(0, "r1 = 0x12345678", "r1", "= 0x12345678"),
            BpfInstruction(1, "*(u32 *)(r10 - 0x4) = r1", "*", "(u32 *)(r10 - 0x4) = r1"),
            BpfInstruction(2, "r2 = *(u16 *)(r10 - 0x4)", "r2", "= *(u16 *)(r10 - 0x4)"),
            BpfInstruction(3, "exit", "exit", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, is_exit=True)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        exit_regs = res.exit_states["terminal_exit"].registers
        self.assertTrue(exit_regs.get("r2").is_unknown())

    def test_stack_overlapping_stores_invalidate(self):
        # Store u32 at -4, then overwrite u8 at -3, read u32 at -4 -> must be unknown
        insns = [
            BpfInstruction(0, "r1 = 100", "r1", "= 100"),
            BpfInstruction(1, "*(u32 *)(r10 - 0x4) = r1", "*", "(u32 *)(r10 - 0x4) = r1"),
            BpfInstruction(2, "r2 = 5", "r2", "= 5"),
            BpfInstruction(3, "*(u8 *)(r10 - 0x3) = r2", "*", "(u8 *)(r10 - 0x3) = r2"),
            BpfInstruction(4, "r3 = *(u32 *)(r10 - 0x4)", "r3", "= *(u32 *)(r10 - 0x4)"),
            BpfInstruction(5, "exit", "exit", ""),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns, is_exit=True)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.SAFE)
        exit_regs = res.exit_states["terminal_exit"].registers
        self.assertTrue(exit_regs.get("r3").is_unknown())

    def test_stack_out_of_bounds_store_yields_unknown(self):
        # Offset > 0: *(u32 *)(r10 + 0x4)
        insns = [
            BpfInstruction(0, "r1 = 1", "r1", "= 1"),
            BpfInstruction(1, "*(u32 *)(r10 + 0x4) = r1", "*", "(u32 *)(r10 + 0x4) = r1"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("out of bounds", res.unresolved_reason)

    def test_stack_out_of_bounds_load_yields_unknown(self):
        # Offset -516 (exceeds 512B stack)
        insns = [
            BpfInstruction(0, "r1 = *(u32 *)(r10 - 0x204)", "r1", "= *(u32 *)(r10 - 0x204)"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb})
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.UNKNOWN)
        self.assertIn("out of bounds", res.unresolved_reason)

    def test_packet_memory_write_under_policy_yields_violation(self):
        # Store to r1 (packet pointer): *(u32 *)(r1 + 0) = w2
        insns = [
            BpfInstruction(0, "*(u32 *)(r1 + 0x0) = w2", "*", "(u32 *)(r1 + 0x0) = w2"),
        ]
        bb = BpfBasicBlock("bb_0", 0, instructions=insns)
        ctx = BpfProgramContext(instructions=insns, basic_blocks={"bb_0": bb}, policy=self.packet_ro_policy)
        rb = RegionBoundary("bb_0", "bb_0", ("bb_0",))
        res = analyze_region(ctx, rb, self.entry_state)

        self.assertEqual(res.verdict, RegionVerdict.VIOLATION)
        self.assertIn("Forbidden memory write via 'r1'", res.violating_path_evidence)

    def test_multiblock_stack_join(self):
        # Branch into bb_1 and bb_2, store 10 and 20 to stack slot -4, join at bb_3
        insns_b0 = [BpfInstruction(0, "if r1 == 0 goto +0x2", "if", "r1 == 0 goto +0x2")]
        insns_b1 = [
            BpfInstruction(1, "r2 = 10", "r2", "= 10"),
            BpfInstruction(2, "*(u32 *)(r10 - 0x4) = r2", "*", "(u32 *)(r10 - 0x4) = r2"),
            BpfInstruction(3, "goto +0x2", "goto", "+0x2"),
        ]
        insns_b2 = [
            BpfInstruction(4, "r2 = 20", "r2", "= 20"),
            BpfInstruction(5, "*(u32 *)(r10 - 0x4) = r2", "*", "(u32 *)(r10 - 0x4) = r2"),
            BpfInstruction(6, "goto +0x0", "goto", "+0x0"),
        ]
        insns_b3 = [
            BpfInstruction(7, "r3 = *(u32 *)(r10 - 0x4)", "r3", "= *(u32 *)(r10 - 0x4)"),
            BpfInstruction(8, "exit", "exit", ""),
        ]

        bb0 = BpfBasicBlock("bb_0", 0, instructions=insns_b0, successors=["bb_4_target", "bb_1"], cond_target="bb_4_target", fallthrough="bb_1")
        bb1 = BpfBasicBlock("bb_1", 1, instructions=insns_b1, predecessors=["bb_0"], successors=["bb_merge"])
        bb2 = BpfBasicBlock("bb_4_target", 4, instructions=insns_b2, predecessors=["bb_0"], successors=["bb_merge"])
        bb_merge = BpfBasicBlock("bb_merge", 7, instructions=insns_b3, predecessors=["bb_1", "bb_4_target"], is_exit=True)

        ctx = BpfProgramContext(
            instructions=insns_b0 + insns_b1 + insns_b2 + insns_b3,
            basic_blocks={"bb_0": bb0, "bb_1": bb1, "bb_4_target": bb2, "bb_merge": bb_merge},
            policy={},
        )

        results, reachable, composition = propagate_and_analyze_program(ctx)
        self.assertIn("bb_merge", reachable)
        merge_res = results["bb_merge"]
        # r3 reloads from stack slot -4, which joined (4, const(10)) and (4, const(20)) -> interval(10, 20)
        exit_r3 = merge_res.exit_states["terminal_exit"].registers.get("r3")
        self.assertEqual(exit_r3.kind, "interval")
        self.assertEqual(exit_r3.value, (10, 20))


if __name__ == "__main__":
    unittest.main()
