import json
from pathlib import Path

import pytest

from research.analyzer.abstract_policy_analyzer import (
    AbstractPolicyAnalyzer,
    Instruction,
    Verdict,
)

SAFE_POLICY = {
    "phase5": {
        "type": "ACTION",
        "dependencies": {"memory": [], "previous_actions": []},
        "actions": {
            "helper_access": ["bpf_ktime_get_ns"],
            "map_access": [{"name": "e1_map", "access": "Read"}],
            "return_value": [1, 2],
        },
    },
    "helper_func": ["bpf_trace_printk", "bpf_get_prandom_u32"],
}


def make_analyzer(tmp_path, policy=None):
    obj = tmp_path / "fixture.o"
    policy_file = tmp_path / "policy.json"
    obj.write_bytes(b"fixture")
    policy_file.write_text(json.dumps(policy or SAFE_POLICY))
    return AbstractPolicyAnalyzer(str(obj), str(policy_file))


def install_disassembly(analyzer, lines):
    instructions = []
    for pc, text in enumerate(lines):
        parts = text.split(None, 1)
        opcode = parts[0]
        args = parts[1] if len(parts) == 2 else ""
        instructions.append(Instruction(pc, text, opcode, args))
    analyzer.instructions = instructions
    analyzer._build_cfg()


def analyze_fixture(tmp_path, lines, policy=None):
    analyzer = make_analyzer(tmp_path, policy)
    original = analyzer._disassemble_object

    def fake_disassemble():
        install_disassembly(analyzer, lines)

    analyzer._disassemble_object = fake_disassemble
    return analyzer.analyze()


def test_supported_compliant_operation_is_safe(tmp_path):
    result = analyze_fixture(tmp_path, ["r0 = 2", "exit"])
    assert result["verdict"] == Verdict.SAFE.value


def test_supported_provable_violation_is_violation(tmp_path):
    result = analyze_fixture(tmp_path, ["r0 = 3", "exit"])
    assert result["verdict"] == Verdict.VIOLATION.value


def test_unresolved_conditional_is_unknown(tmp_path):
    result = analyze_fixture(
        tmp_path,
        [
            "if r1 == 0 goto +0x2",
            "r0 = 2",
            "exit",
            "r0 = 3",
            "exit",
        ],
    )
    assert result["verdict"] == Verdict.UNKNOWN.value


def test_unknown_helper_id_is_unknown(tmp_path):
    result = analyze_fixture(tmp_path, ["call 999", "r0 = 2", "exit"])
    assert result["verdict"] == Verdict.UNKNOWN.value


def test_explicitly_forbidden_helper_is_violation(tmp_path):
    result = analyze_fixture(tmp_path, ["call 7", "r0 = 2", "exit"])
    assert result["verdict"] == Verdict.VIOLATION.value


def test_unknown_memory_store_under_memory_policy_is_unknown(tmp_path):
    policy = json.loads(json.dumps(SAFE_POLICY))
    policy["phase5"]["dependencies"]["memory"] = ["restricted"]
    result = analyze_fixture(
        tmp_path,
        ["*(u64 *)(r1 + 0x0) = r2", "r0 = 2", "exit"],
        policy,
    )
    assert result["verdict"] == Verdict.UNKNOWN.value


def test_unsupported_instruction_is_unknown(tmp_path):
    result = analyze_fixture(tmp_path, ["totally_unknown_instruction r0", "exit"])
    assert result["verdict"] == Verdict.UNKNOWN.value


def test_analysis_failure_is_unknown(tmp_path):
    analyzer = make_analyzer(tmp_path)

    def fail():
        raise RuntimeError("synthetic parser failure")

    analyzer._disassemble_object = fail
    result = analyzer.analyze()
    assert result["verdict"] == Verdict.UNKNOWN.value
    assert "analysis failure" in result["proof"]


def test_map_update_cannot_be_assumed_safe(tmp_path):
    policy = json.loads(json.dumps(SAFE_POLICY))
    policy["phase5"]["actions"]["helper_access"].append("bpf_map_update_elem")
    analyzer = make_analyzer(tmp_path, policy)
    analyzer.relocations = {0: "e1_map"}
    result = analyze_fixture(tmp_path, ["call 2", "r0 = 2", "exit"], policy)
    assert result["verdict"] == Verdict.UNKNOWN.value
