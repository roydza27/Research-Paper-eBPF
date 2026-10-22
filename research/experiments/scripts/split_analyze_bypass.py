#!/usr/bin/env python3
"""Isolated split/analyze/bypass experiment (conservative program-scope adapter).

The current AbstractPolicyAnalyzer exposes only analyze(object, policy) semantics.
This module records CFG regions but deliberately does not invent block-level
verdicts. Until the analyzer accepts an explicit incoming abstract state and
bounded region, the only sound abstract/symbolic scope is the whole ELF program.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable


SEMANTIC = {"SAFE", "VIOLATION", "UNKNOWN"}


def _semantic_verdict(value: Any) -> str:
    value = getattr(value, "value", value)
    if not isinstance(value, str):
        return "UNKNOWN"
    value = value.strip().upper()
    if value in {"REJECT", "REJECTED", "VIOLATION", "POLICY VIOLATION"}:
        return "VIOLATION"
    if value in {"COMPLIANT", "VERIFIED"}:
        return "SAFE"
    return value if value in SEMANTIC else "UNKNOWN"


def extract_cfg(analyzer: Any) -> list[dict[str, Any]]:
    """Extract metadata from the analyzer's already-built CFG; no re-parsing."""
    blocks = getattr(analyzer, "basic_blocks", None)
    instructions = getattr(analyzer, "instructions", None)
    if not isinstance(blocks, dict) or not blocks or not instructions:
        return []
    entry = instructions[0].pc
    preds = {pc: [] for pc in blocks}
    for pc, block in blocks.items():
        for succ in getattr(block, "successors", []):
            if succ in preds:
                preds[succ].append(pc)
    reachable: set[int] = set()
    queue = deque([entry])
    while queue:
        pc = queue.popleft()
        if pc in reachable or pc not in blocks:
            continue
        reachable.add(pc)
        queue.extend(s for s in getattr(blocks[pc], "successors", []) if s not in reachable)
    records = []
    for pc, block in sorted(blocks.items()):
        ins = list(getattr(block, "instructions", []))
        pcs = [int(i.pc) for i in ins]
        records.append({
            "block_id": f"bb_{pc:x}",
            "start_pc": int(pc),
            "end_pc": max(pcs) if pcs else None,
            "instruction_pcs": pcs,
            "predecessors": [f"bb_{p:x}" for p in sorted(preds[pc])],
            "successors": [f"bb_{s:x}" for s in getattr(block, "successors", [])],
            "reachable": pc in reachable,
            "entry_assumptions": None,
            "block_verdict": None,
            "scope_note": "metadata_only; analyzer has no sound independent-block API",
        })
    return records


def control_flow_order(records: list[dict[str, Any]]) -> list[str]:
    """Deterministic reachable reverse-postorder, valid for CFGs with cycles."""
    by_id = {r["block_id"]: r for r in records}
    entry_candidates = [r for r in records if r["reachable"] and not r["predecessors"]]
    if not entry_candidates:
        entry_candidates = [r for r in records if r["reachable"]]
    if not entry_candidates:
        return []
    seen: set[str] = set()
    post: list[str] = []

    def visit(node: str) -> None:
        if node in seen or node not in by_id or not by_id[node]["reachable"]:
            return
        seen.add(node)
        for child in sorted(by_id[node]["successors"]):
            visit(child)
        post.append(node)

    for root in sorted(r["block_id"] for r in entry_candidates):
        visit(root)
    for r in records:
        if r["reachable"]:
            visit(r["block_id"])
    return list(reversed(post))


def gate(scope_id: str, abstract_runner: Callable[[], dict[str, Any]],
         symbolic_runner: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Sequential gate for one scope. UNKNOWN routes to fallback, never passes."""
    t0 = time.monotonic_ns()
    try:
        abstract = abstract_runner()
        abstract_error = None
    except Exception as exc:
        abstract = {"verdict": "UNKNOWN", "proof": ""}
        abstract_error = f"{type(exc).__name__}: {exc}"
    abstract_ms = (time.monotonic_ns() - t0) / 1_000_000
    av = _semantic_verdict(abstract.get("verdict"))
    row = {
        "scope_id": scope_id, "abstract_verdict": av,
        "abstract_duration_ms": abstract_ms,
        "abstract_reason": abstract.get("proof", abstract.get("reason", "")),
        "abstract_error": abstract_error,
        "symbolic_invoked": False, "symbolic_verdict": None,
        "symbolic_duration_ms": None, "symbolic_reason": None,
        "symbolic_error": None, "disposition": "unresolved",
    }
    if av == "SAFE":
        row["disposition"] = "abstract_pass"
        return row
    if av == "VIOLATION":
        row["disposition"] = "violation"
        return row
    row["symbolic_invoked"] = True
    t1 = time.monotonic_ns()
    try:
        symbolic = symbolic_runner()
        sv = _semantic_verdict(symbolic.get("verdict"))
        row["symbolic_reason"] = symbolic.get("reason", symbolic.get("proof", ""))
        row["symbolic_error"] = symbolic.get("error")
    except TimeoutError as exc:
        sv = "UNKNOWN"
        row["symbolic_error"] = f"timeout: {exc}"
    except Exception as exc:
        sv = "UNKNOWN"
        row["symbolic_error"] = f"{type(exc).__name__}: {exc}"
    row["symbolic_duration_ms"] = (time.monotonic_ns() - t1) / 1_000_000
    row["symbolic_verdict"] = sv
    if sv == "SAFE":
        row["disposition"] = "symbolic_pass"
    elif sv == "VIOLATION":
        row["disposition"] = "violation"
    return row


def _symbolic_worker(args: argparse.Namespace) -> int:
    """Isolated worker so the parent can enforce a hard wall-clock timeout."""
    baseline = Path(args.baseline_dir).resolve()
    sys.path.insert(0, str(baseline))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from daemon.krakenguard_client import KrakenGuardClient
    # Load only the existing verdict-parser function AST. Importing the full
    # validator module has top-level side effects (including result-directory
    # creation), which this isolated runner must avoid.
    validator_path = Path(__file__).with_name("validate-phase5-corpus.py")
    source = ast.parse(validator_path.read_text(), filename=str(validator_path))
    parser_node = next((node for node in source.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "extract_krakenguard_verdict"), None)
    if parser_node is None:
        raise RuntimeError("existing KRAKENGUARD verdict parser was not found")
    parser_module = ast.Module(body=[parser_node], type_ignores=[])
    namespace = {"Path": Path, "BASELINE_DIR": baseline}
    exec(compile(ast.fix_missing_locations(parser_module), str(validator_path), "exec"), namespace)
    extract_verdict = namespace["extract_krakenguard_verdict"]
    socket_path = args.socket_path or str(baseline / "socket" / "krakenguard.sock")
    socket_path = os.path.relpath(socket_path, Path.cwd())
    client = KrakenGuardClient(socket_path)
    response = client.verify(object_file=args.object, constraints_file=args.policy)
    passed, verdict = extract_verdict(response)
    result = {
        "verdict": _semantic_verdict(verdict),
        "reason": f"existing extract_krakenguard_verdict; response status={getattr(response, 'status', None)}",
        "request_id": getattr(response, "request_id", None),
        "response_status": getattr(response, "status", None),
        "parser_passed": bool(passed),
    }
    print(json.dumps(result))
    return 0


def run_program(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "analyzer"))
    from abstract_policy_analyzer import AbstractPolicyAnalyzer

    analyzer = AbstractPolicyAnalyzer(args.object, args.policy)
    t0 = time.monotonic_ns()
    abstract_result = analyzer.analyze()
    abstract_ms = (time.monotonic_ns() - t0) / 1_000_000
    cfg = extract_cfg(analyzer)
    order = control_flow_order(cfg)
    scope = "program"
    fallback_info: dict[str, Any] = {}

    def abstract_once() -> dict[str, Any]:
        fallback_info["elapsed_ms"] = abstract_ms
        return abstract_result

    def symbolic_once() -> dict[str, Any]:
        if not args.baseline_dir:
            return {"verdict": "UNKNOWN", "error": "baseline_dir not supplied",
                    "reason": "whole-program symbolic fallback unavailable"}
        cmd = [
            sys.executable, str(Path(__file__).resolve()), "--symbolic-worker",
            "--object", args.object, "--policy", args.policy,
            "--baseline-dir", args.baseline_dir,
        ]
        if args.socket_path:
            cmd.extend(["--socket-path", args.socket_path])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=args.symbolic_timeout_seconds, check=False)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"exceeded {args.symbolic_timeout_seconds}s") from exc
        if proc.returncode != 0:
            return {"verdict": "UNKNOWN", "error": f"worker exit {proc.returncode}: {proc.stderr[-2000:]}",
                    "reason": "symbolic worker failed"}
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"verdict": "UNKNOWN", "error": "symbolic worker returned unparsable output",
                    "reason": proc.stdout[-2000:]}

    # A single program-scope gate is intentional: block verdicts would be unsound
    # without explicit incoming-state and path-constraint support in the analyzer.
    result = gate(scope, abstract_once, symbolic_once)
    result["abstract_duration_ms"] = abstract_ms
    return {
        "schema": "split-analyze-bypass-prototype/v1",
        "program_id": args.program_id or Path(args.object).stem,
        "scope": "whole_program",
        "scope_limitation": "The analyzer cannot classify extracted blocks independently. CFG is metadata only; no per-block verdicts are fabricated.",
        "object": str(Path(args.object).resolve()),
        "policy": str(Path(args.policy).resolve()),
        "cfg": {"blocks": cfg, "reachable_order": order},
        "units": [result],
        "overall_status": result["disposition"],
        "overall_verdict": (result["abstract_verdict"] if not result["symbolic_invoked"]
                            else result["symbolic_verdict"]),
        "errors": [e for e in [result.get("abstract_error"), result.get("symbolic_error")] if e],
        "tool_versions": {"python": platform.python_version(), "platform": platform.platform()},
        "limits": {"symbolic_timeout_seconds": args.symbolic_timeout_seconds},
        "experiment_mode": "program_scope_safety_wrapper_not_block_level",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--object", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--program-id")
    p.add_argument("--output", help="new result JSON path; existing files are refused")
    p.add_argument("--baseline-dir", help="path to frozen KRAKENGUARD artifact directory")
    p.add_argument("--socket-path")
    p.add_argument("--symbolic-timeout-seconds", type=float, default=120.0)
    p.add_argument("--symbolic-worker", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.symbolic_worker:
        return _symbolic_worker(args)
    if not args.output:
        p.error("--output is required outside symbolic-worker mode")
    if args.symbolic_timeout_seconds <= 0:
        p.error("--symbolic-timeout-seconds must be positive")
    output = Path(args.output)
    if output.exists():
        p.error(f"refusing to overwrite existing result: {output}")
    payload = run_program(args)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({"output": str(output), "overall_status": payload["overall_status"],
                      "overall_verdict": payload["overall_verdict"]}, indent=2))
    return 0 if payload["overall_status"] != "unresolved" else 2


if __name__ == "__main__":
    raise SystemExit(main())
