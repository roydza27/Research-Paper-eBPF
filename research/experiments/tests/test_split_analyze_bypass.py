import unittest
from types import SimpleNamespace

from split_analyze_bypass import control_flow_order, extract_cfg, gate


def result(verdict, **extra):
    return {"verdict": verdict, **extra}


class GateTests(unittest.TestCase):
    def test_all_abstract_safe(self):
        calls = []
        row = gate("program", lambda: result("SAFE"), lambda: calls.append("symbolic") or result("SAFE"))
        self.assertEqual(row["disposition"], "abstract_pass")
        self.assertFalse(row["symbolic_invoked"])
        self.assertEqual(calls, [])

    def test_unknown_resolved_safe_by_symbolic(self):
        row = gate("program", lambda: result("UNKNOWN"), lambda: result("SAFE"))
        self.assertEqual(row["disposition"], "symbolic_pass")
        self.assertTrue(row["symbolic_invoked"])

    def test_unknown_rejected_by_symbolic(self):
        row = gate("program", lambda: result("UNKNOWN"), lambda: result("VIOLATION"))
        self.assertEqual(row["disposition"], "violation")

    def test_unknown_after_fallback_remains_unresolved(self):
        row = gate("program", lambda: result("UNKNOWN"), lambda: result("UNKNOWN"))
        self.assertEqual(row["disposition"], "unresolved")

    def test_abstract_violation_short_circuits(self):
        calls = []
        row = gate("program", lambda: result("VIOLATION"), lambda: calls.append(1) or result("SAFE"))
        self.assertEqual(row["disposition"], "violation")
        self.assertFalse(row["symbolic_invoked"])
        self.assertEqual(calls, [])

    def test_symbolic_error_is_not_safe(self):
        def fail():
            raise RuntimeError("tool unavailable")
        row = gate("program", lambda: result("UNKNOWN"), fail)
        self.assertEqual(row["symbolic_verdict"], "UNKNOWN")
        self.assertEqual(row["disposition"], "unresolved")
        self.assertIn("tool unavailable", row["symbolic_error"])

    def test_symbolic_timeout_is_not_safe(self):
        def fail():
            raise TimeoutError("deadline")
        row = gate("program", lambda: result("UNKNOWN"), fail)
        self.assertEqual(row["disposition"], "unresolved")
        self.assertIn("timeout", row["symbolic_error"])

    def test_unrecognized_verdict_fails_closed(self):
        row = gate("program", lambda: result("TOOL_ERROR"), lambda: result("SAFE"))
        self.assertEqual(row["abstract_verdict"], "UNKNOWN")
        self.assertEqual(row["disposition"], "symbolic_pass")

    def test_reject_alias_normalizes_to_violation(self):
        row = gate("program", lambda: result("REJECT"), lambda: result("SAFE"))
        self.assertEqual(row["abstract_verdict"], "VIOLATION")
        self.assertEqual(row["disposition"], "violation")


class CFGTests(unittest.TestCase):
    def test_reachability_excludes_unreachable_violating_block(self):
        a = SimpleNamespace(start_pc=0, instructions=[SimpleNamespace(pc=0)], successors=[2])
        b = SimpleNamespace(start_pc=1, instructions=[SimpleNamespace(pc=1)], successors=[])
        c = SimpleNamespace(start_pc=2, instructions=[SimpleNamespace(pc=2)], successors=[])
        analyzer = SimpleNamespace(instructions=[SimpleNamespace(pc=0)], basic_blocks={0: a, 1: b, 2: c})
        records = extract_cfg(analyzer)
        by_pc = {r["start_pc"]: r for r in records}
        self.assertTrue(by_pc[0]["reachable"])
        self.assertFalse(by_pc[1]["reachable"])
        self.assertTrue(by_pc[2]["reachable"])

    def test_branch_explores_both_successors_in_order_metadata(self):
        blocks = {
            0: SimpleNamespace(start_pc=0, instructions=[SimpleNamespace(pc=0)], successors=[1, 2]),
            1: SimpleNamespace(start_pc=1, instructions=[SimpleNamespace(pc=1)], successors=[3]),
            2: SimpleNamespace(start_pc=2, instructions=[SimpleNamespace(pc=2)], successors=[3]),
            3: SimpleNamespace(start_pc=3, instructions=[SimpleNamespace(pc=3)], successors=[]),
        }
        analyzer = SimpleNamespace(instructions=[SimpleNamespace(pc=0)], basic_blocks=blocks)
        records = extract_cfg(analyzer)
        order = control_flow_order(records)
        self.assertEqual(set(order), {"bb_0", "bb_1", "bb_2", "bb_3"})
        self.assertEqual(set(records[0]["successors"]), {"bb_1", "bb_2"})

    def test_join_records_multiple_predecessors(self):
        blocks = {
            0: SimpleNamespace(start_pc=0, instructions=[SimpleNamespace(pc=0)], successors=[1, 2]),
            1: SimpleNamespace(start_pc=1, instructions=[SimpleNamespace(pc=1)], successors=[3]),
            2: SimpleNamespace(start_pc=2, instructions=[SimpleNamespace(pc=2)], successors=[3]),
            3: SimpleNamespace(start_pc=3, instructions=[SimpleNamespace(pc=3)], successors=[]),
        }
        records = extract_cfg(SimpleNamespace(instructions=[SimpleNamespace(pc=0)], basic_blocks=blocks))
        join = next(r for r in records if r["start_pc"] == 3)
        self.assertEqual(set(join["predecessors"]), {"bb_1", "bb_2"})

    def test_loop_order_terminates_and_includes_revisited_block(self):
        blocks = {
            0: SimpleNamespace(start_pc=0, instructions=[SimpleNamespace(pc=0)], successors=[1]),
            1: SimpleNamespace(start_pc=1, instructions=[SimpleNamespace(pc=1)], successors=[0, 2]),
            2: SimpleNamespace(start_pc=2, instructions=[SimpleNamespace(pc=2)], successors=[]),
        }
        records = extract_cfg(SimpleNamespace(instructions=[SimpleNamespace(pc=0)], basic_blocks=blocks))
        order = control_flow_order(records)
        self.assertEqual(set(order), {"bb_0", "bb_1", "bb_2"})


if __name__ == "__main__":
    unittest.main()
