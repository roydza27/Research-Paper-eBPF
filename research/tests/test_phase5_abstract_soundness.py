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


def test_64bit_immediate_ll_parsing(tmp_path):
    """Ensure instructions with 64-bit immediate 'll' syntax parse correctly without degrading to UNKNOWN."""
    result = analyze_fixture(
        tmp_path,
        [
            "r1 = 0x0 ll",
            "r2 = 0x123456789abcdef0 ll",
            "r0 = 2",
            "exit",
        ],
    )
    assert result["verdict"] == Verdict.SAFE.value
    assert "policy-allowed values" in result["proof"]


def test_absent_return_value_policy_allows_all_returns(tmp_path):
    """Ensure policy without 'return_value' rule does not invent a default {1, 2} restriction."""
    policy_no_ret = {
        "phase5": {
            "type": "ACTION",
            "dependencies": {"memory": [], "previous_actions": []},
            "actions": {
                "helper_access": ["bpf_ktime_get_ns"],
                "map_access": [],
            },
        },
        "helper_func": ["bpf_trace_printk"],
    }
    # r0 = 3 would be a VIOLATION under SAFE_POLICY (which specifies [1, 2]),
    # but under policy_no_ret it must be SAFE.
    result = analyze_fixture(tmp_path, ["r0 = 3", "exit"], policy_no_ret)
    assert result["verdict"] == Verdict.SAFE.value
    assert "policy-allowed values" in result["proof"]


def test_extract_krakenguard_verdict_fail_closed(tmp_path, monkeypatch):
    """Ensure authoritative extraction requires conditional_policy.results.txt and fails closed."""
    import importlib.util

    val_script = (
        Path(__file__).resolve().parents[1]
        / "experiments"
        / "scripts"
        / "validate-phase5-corpus.py"
    )
    spec = importlib.util.spec_from_file_location("corpus_val", val_script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    extract_verdict = mod.extract_krakenguard_verdict

    # Redirect BASELINE_DIR in module so test creates directories inside tmp_path
    monkeypatch.setattr(mod, "BASELINE_DIR", tmp_path)

    class DummyExecution:
        def __init__(self, return_code=0):
            self.return_code = return_code

    class DummyOutput:
        def __init__(self, directory="", stderr=""):
            self.directory = directory
            self.stderr = stderr

    class DummyResponse:
        def __init__(self, return_code=0, directory="", stderr=""):
            self.execution = DummyExecution(return_code)
            self.output = DummyOutput(directory, stderr)

    # 1. Non-zero return code must fail closed
    fail_resp = DummyResponse(return_code=1, stderr="KLEE crashed")
    with pytest.raises(RuntimeError, match="KRAKENGUARD execution failed"):
        extract_verdict(fail_resp)

    # 2. Missing output directory must fail closed
    no_dir_resp = DummyResponse(return_code=0, directory="")
    with pytest.raises(RuntimeError, match="missing output directory"):
        extract_verdict(no_dir_resp)

    # 3. Missing conditional_policy.results.txt must fail closed
    fake_data_dir = tmp_path / "data" / "fake_test_run"
    fake_data_dir.mkdir(parents=True, exist_ok=True)

    resp_missing_cond = DummyResponse(
        return_code=0, directory="/data/fake_test_run"
    )
    with pytest.raises(RuntimeError, match="Mandatory conditional policy output missing"):
        extract_verdict(resp_missing_cond)

    # 4. Empty conditional_policy.results.txt must fail closed
    cond_file = fake_data_dir / "conditional_policy.results.txt"
    cond_file.write_text("   \n")
    with pytest.raises(RuntimeError, match="Mandatory conditional policy output is empty"):
        extract_verdict(resp_missing_cond)

    # 5. Malformed/ambiguous output must fail closed
    cond_file.write_text("Status: UNEXPECTED INTERNAL ERROR")
    with pytest.raises(RuntimeError, match="Unrecognized or ambiguous"):
        extract_verdict(resp_missing_cond)

    # 6. Valid violation
    cond_file.write_text("Some trace...\nStatus: POLICY VIOLATIONS DETECTED\nDetails...")
    passed, verdict = extract_verdict(resp_missing_cond)
    assert passed is False
    assert verdict == "POLICY VIOLATION"

    # 7. Valid compliant
    cond_file.write_text("Some trace...\nStatus: NO VIOLATIONS\nDetails...")
    passed, verdict = extract_verdict(resp_missing_cond)
    assert passed is True
    assert verdict == "COMPLIANT"


