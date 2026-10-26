#!/usr/bin/env python3
"""Isolated split/analyze/bypass experiment and tri-mode evaluation runner.

Supports three explicit verification modes:
- Mode A (symbolic_only): Whole-program symbolic verification via KRAKENGUARD without abstract stage.
- Mode B (whole_hybrid): Existing legacy whole-program abstract analyzer with whole-program symbolic fallback.
- Mode C (region_hybrid): Region-level abstract analyzer with explicit CFG state propagation,
  lattice joins, cycle detection, and whole-program symbolic fallback for unresolved cases.

Scope Boundary:
KRAKENGUARD symbolic verification strictly operates at whole-program (full ELF) granularity.
Mode C analyzer operates at region_level, but its fallback scope is explicitly 'whole_program'.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
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
INTEGRATION_BASE_COMMIT = "9250b53243714f00868f8c73a3c794634cfc5ad2"
PROTOTYPE_SOURCE_COMMIT = "0d81b13a03c6294051620c6157b10b8d36922a81"

# Canonical mode identifiers
MODE_SYMBOLIC_ONLY = "symbolic_only"
MODE_WHOLE_HYBRID = "whole_hybrid"
MODE_REGION_HYBRID = "region_hybrid"

VALID_MODES: dict[str, str] = {
    "symbolic_only": MODE_SYMBOLIC_ONLY,
    "symbolic-only": MODE_SYMBOLIC_ONLY,
    "symbolic": MODE_SYMBOLIC_ONLY,
    "mode_a": MODE_SYMBOLIC_ONLY,
    "a": MODE_SYMBOLIC_ONLY,
    "whole_hybrid": MODE_WHOLE_HYBRID,
    "whole-hybrid": MODE_WHOLE_HYBRID,
    "legacy_hybrid": MODE_WHOLE_HYBRID,
    "legacy-hybrid": MODE_WHOLE_HYBRID,
    "mode_b": MODE_WHOLE_HYBRID,
    "b": MODE_WHOLE_HYBRID,
    "region_hybrid": MODE_REGION_HYBRID,
    "region-hybrid": MODE_REGION_HYBRID,
    "region": MODE_REGION_HYBRID,
    "mode_c": MODE_REGION_HYBRID,
    "c": MODE_REGION_HYBRID,
}


def normalize_mode(mode: str | None) -> str:
    """Normalize mode string or alias to canonical form."""
    if mode is None:
        return MODE_WHOLE_HYBRID
    key = str(mode).strip().lower()
    if key not in VALID_MODES:
        valid_keys = sorted(set(VALID_MODES.values()))
        raise ValueError(f"Unknown mode '{mode}'. Expected one of: {valid_keys}")
    return VALID_MODES[key]


def _semantic_verdict(value: Any) -> str:
    value = getattr(value, "value", value)
    if not isinstance(value, str):
        return "UNKNOWN"
    value = value.strip().upper()
    if value in {"REJECT", "REJECTED", "VIOLATION", "POLICY VIOLATION"}:
        return "VIOLATION"
    if value == "COMPLIANT":
        return "SAFE"
    return value if value in SEMANTIC else "UNKNOWN"


def sha256_file(path: str | Path | None) -> str | None:
    """Calculate SHA256 digest of a file; returns None if path is None or does not exist."""
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_oracle_agreement(reference_verdict: str | None, final_verdict: str | None) -> bool | None:
    """Compute oracle agreement status.

    Returns True if reference and final verdicts agree and are decisive (SAFE or VIOLATION).
    Returns False if they disagree OR if the final verdict is UNKNOWN/unresolved.
    Returns None if no reference verdict is available.
    CRITICAL: UNKNOWN is NEVER treated as agreement.
    """
    if not reference_verdict:
        return None
    ref_norm = _semantic_verdict(reference_verdict)
    final_norm = _semantic_verdict(final_verdict)
    if final_norm not in {"SAFE", "VIOLATION"}:
        return False
    return ref_norm == final_norm


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


def tri_mode_gate(
    mode: str,
    abstract_runner: Callable[[], dict[str, Any]] | None = None,
    symbolic_runner: Callable[[], dict[str, Any]] | None = None,
    scope_id: str = "program",
) -> dict[str, Any]:
    """Tri-mode execution gate enforcing uniform timing boundaries and fail-closed semantics.

    Mode A (symbolic_only): directly invokes symbolic verifier without abstract pass.
    Mode B (whole_hybrid): invokes legacy whole-program abstract analyzer; UNKNOWN routes to whole-program symbolic fallback.
    Mode C (region_hybrid): invokes region-level analyzer with CFG state propagation; UNKNOWN routes to whole-program symbolic fallback.
    """
    canonical_mode = normalize_mode(mode)

    if canonical_mode == MODE_SYMBOLIC_ONLY:
        row: dict[str, Any] = {
            "scope_id": scope_id,
            "analyzer": "krakenguard_symbolic",
            "analyzer_scope": "whole_program",
            "abstract_verdict": None,
            "abstract_duration_ms": None,
            "abstract_reason": None,
            "abstract_error": None,
            "symbolic_invoked": True,
            "fallback_invoked": False,
            "fallback_scope": None,
            "symbolic_verdict": None,
            "symbolic_duration_ms": None,
            "symbolic_reason": None,
            "symbolic_error": None,
            "disposition": "unresolved",
            "overall_verdict": "UNKNOWN",
        }
        if symbolic_runner is None:
            row["symbolic_error"] = "symbolic runner not provided"
            return row

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

        if row["symbolic_error"] and "timeout" in str(row["symbolic_error"]).lower():
            row["overall_verdict"] = "TIMEOUT"
            row["disposition"] = "unresolved"
        elif row["symbolic_error"]:
            row["overall_verdict"] = "ERROR"
            row["disposition"] = "unresolved"
        elif sv == "SAFE":
            row["disposition"] = "symbolic_pass"
            row["overall_verdict"] = "SAFE"
        elif sv == "VIOLATION":
            row["disposition"] = "violation"
            row["overall_verdict"] = "VIOLATION"
        else:
            row["overall_verdict"] = "UNKNOWN"
            row["disposition"] = "unresolved"
        return row

    # For Modes B (whole_hybrid) and C (region_hybrid):
    analyzer_name = (
        "legacy_whole_program_analyzer"
        if canonical_mode == MODE_WHOLE_HYBRID
        else "region_level_analyzer"
    )
    analyzer_scope = (
        "whole_program"
        if canonical_mode == MODE_WHOLE_HYBRID
        else "region_level"
    )

    t0 = time.monotonic_ns()
    try:
        if abstract_runner is None:
            raise RuntimeError("abstract runner not provided")
        abstract = abstract_runner()
        abstract_error = None
    except TimeoutError as exc:
        abstract = {"verdict": "UNKNOWN", "proof": ""}
        abstract_error = f"timeout: {exc}"
    except Exception as exc:
        abstract = {"verdict": "UNKNOWN", "proof": ""}
        abstract_error = f"{type(exc).__name__}: {exc}"
    abstract_ms = (time.monotonic_ns() - t0) / 1_000_000

    if abstract_error and "timeout" in abstract_error.lower():
        av = "UNKNOWN"
    else:
        av = _semantic_verdict(abstract.get("verdict"))

    row = {
        "scope_id": scope_id,
        "analyzer": analyzer_name,
        "analyzer_scope": analyzer_scope,
        "abstract_verdict": av,
        "abstract_duration_ms": abstract_ms,
        "abstract_reason": abstract.get("proof", abstract.get("reason", "")),
        "abstract_error": abstract_error,
        "symbolic_invoked": False,
        "fallback_invoked": False,
        "fallback_scope": None,
        "symbolic_verdict": None,
        "symbolic_duration_ms": None,
        "symbolic_reason": None,
        "symbolic_error": None,
        "disposition": "unresolved",
        "overall_verdict": "UNKNOWN",
    }

    if abstract_error and not symbolic_runner:
        row["overall_verdict"] = "ERROR" if "timeout" not in abstract_error.lower() else "TIMEOUT"
        row["disposition"] = "unresolved"
        return row

    if av == "SAFE" and not abstract_error:
        row["disposition"] = "abstract_pass"
        row["overall_verdict"] = "SAFE"
        return row
    if av == "VIOLATION" and not abstract_error:
        row["disposition"] = "violation"
        row["overall_verdict"] = "VIOLATION"
        return row

    # Unresolved or error: Fallback to symbolic verification
    row["symbolic_invoked"] = True
    row["fallback_invoked"] = True
    row["fallback_scope"] = "whole_program"

    if symbolic_runner is None:
        row["symbolic_error"] = "whole-program symbolic fallback unavailable"
        row["overall_verdict"] = "UNKNOWN"
        row["disposition"] = "unresolved"
        return row

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

    if row["symbolic_error"] and "timeout" in str(row["symbolic_error"]).lower():
        row["overall_verdict"] = "TIMEOUT"
        row["disposition"] = "unresolved"
    elif row["symbolic_error"]:
        row["overall_verdict"] = "ERROR"
        row["disposition"] = "unresolved"
    elif sv == "SAFE":
        row["disposition"] = "symbolic_pass"
        row["overall_verdict"] = "SAFE"
    elif sv == "VIOLATION":
        row["disposition"] = "violation"
        row["overall_verdict"] = "VIOLATION"
    else:
        row["overall_verdict"] = "UNKNOWN"
        row["disposition"] = "unresolved"
    return row


def gate(scope_id: str, abstract_runner: Callable[[], dict[str, Any]],
         symbolic_runner: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Sequential gate for legacy whole-program hybrid mode (backward compatible wrapper)."""
    return tri_mode_gate(MODE_WHOLE_HYBRID, abstract_runner, symbolic_runner, scope_id=scope_id)


def _abstract_worker(args: argparse.Namespace) -> int:
    """Run the existing whole-program analyzer in a killable child process."""
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "analyzer"))
    from abstract_policy_analyzer import AbstractPolicyAnalyzer
    analyzer = AbstractPolicyAnalyzer(args.object, args.policy)
    result = analyzer.analyze()
    payload = {"result": result, "cfg": extract_cfg(analyzer)}
    print(json.dumps(payload))
    return 0


def _region_worker(args: argparse.Namespace) -> int:
    """Run the Task 6/8 region-level analyzer in a killable child process."""
    scripts_dir = Path(__file__).resolve().parents[1] / "split_bypass" / "scripts"
    sys.path.insert(0, str(scripts_dir))
    from region_analyzer import BpfProgramContext, propagate_and_analyze_program

    ctx = BpfProgramContext(object_path=args.object, policy_path=args.policy)
    region_results, reachable_ids, composition = propagate_and_analyze_program(ctx)

    serialized_regions = {}
    for rid, r in region_results.items():
        serialized_regions[rid] = {
            "region_id": r.region_id,
            "verdict": r.verdict.value,
            "scope": r.scope.value,
            "analysis_method": r.analysis_method.value,
            "unresolved_reason": r.unresolved_reason,
            "violating_path_evidence": r.violating_path_evidence,
        }

    cfg_records = []
    for bb_id, bb in sorted(ctx.basic_blocks.items()):
        cfg_records.append({
            "block_id": bb.block_id,
            "start_pc": bb.start_pc,
            "instruction_count": len(bb.instructions),
            "predecessors": sorted(bb.predecessors),
            "successors": sorted(bb.successors),
        })

    payload = {
        "composition": composition,
        "region_results": serialized_regions,
        "reachable_regions": reachable_ids,
        "total_regions": len(region_results),
        "total_basic_blocks": len(ctx.basic_blocks),
        "cfg": cfg_records,
    }
    print(json.dumps(payload))
    return 0


def _symbolic_worker(args: argparse.Namespace) -> int:
    """Isolated worker so the parent can enforce a hard wall-clock timeout."""
    baseline = Path(args.baseline_dir).resolve()
    sys.path.insert(0, str(baseline))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from daemon.krakenguard_client import KrakenGuardClient

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

    try:
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
    except Exception as exc:
        result = {
            "verdict": "UNKNOWN",
            "error": f"{type(exc).__name__}: {exc}",
            "reason": "symbolic client execution failed",
        }
    print(json.dumps(result))
    return 0


def run_program(
    args: argparse.Namespace,
    abstract_runner: Callable[[], dict[str, Any]] | None = None,
    symbolic_runner: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    run_start_ns = time.monotonic_ns()
    canonical_mode = normalize_mode(getattr(args, "mode", MODE_WHOLE_HYBRID))

    program_id = getattr(args, "program_id", None) or Path(args.object).stem
    repetition = getattr(args, "repetition", 0)
    is_warmup = getattr(args, "is_warmup", False)
    reference_verdict = getattr(args, "reference_verdict", None)
    fixture_family = getattr(args, "fixture_family", None)
    policy_id = getattr(args, "policy_id", None)

    # Inferred policy ID if not explicitly provided
    if not policy_id:
        policy_stem = Path(args.policy).stem
        if policy_stem.startswith("policy-"):
            policy_id = policy_stem[len("policy-"):]
        else:
            policy_id = policy_stem

    # Provenance digests
    elf_sha256 = sha256_file(args.object)
    policy_sha256 = sha256_file(args.policy)
    source_path = getattr(args, "source", None)
    if not source_path:
        # Check adjacent .c or standard corpus directory
        candidate_c = Path(args.object).with_suffix(".c")
        if candidate_c.is_file():
            source_path = str(candidate_c)
        else:
            repo_root = Path(__file__).resolve().parents[2]
            corpus_c = repo_root / "research" / "experiments" / "split_bypass" / "programs" / f"{program_id}.c"
            if corpus_c.is_file():
                source_path = str(corpus_c)
    source_sha256 = sha256_file(source_path)

    cfg_holder: dict[str, Any] = {"blocks": []}
    abstract_holder: dict[str, Any] = {}
    region_holder: dict[str, Any] = {}

    def abstract_once_legacy() -> dict[str, Any]:
        cmd = [
            sys.executable, str(Path(__file__).resolve()), "--abstract-worker",
            "--object", args.object, "--policy", args.policy,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=args.abstract_timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"abstract analyzer exceeded {args.abstract_timeout_seconds}s") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"abstract worker exit {proc.returncode}: {proc.stderr[-2000:]}")
        try:
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
            abstract_holder["result"] = payload["result"]
            cfg_holder["blocks"] = payload["cfg"]
            return payload["result"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"abstract worker returned invalid output: {proc.stdout[-2000:]}") from exc

    def abstract_once_region() -> dict[str, Any]:
        cmd = [
            sys.executable, str(Path(__file__).resolve()), "--region-worker",
            "--object", args.object, "--policy", args.policy,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=args.abstract_timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"region analyzer exceeded {args.abstract_timeout_seconds}s") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"region worker exit {proc.returncode}: {proc.stderr[-2000:]}")
        try:
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
            region_holder.update(payload)
            composition = payload.get("composition", {})
            return {
                "verdict": composition.get("overall_verdict", "UNKNOWN"),
                "reason": composition.get("reason", ""),
                "composition": composition,
            }
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"region worker returned invalid output: {proc.stdout[-2000:]}") from exc

    def symbolic_once() -> dict[str, Any]:
        if not args.baseline_dir:
            return {
                "verdict": "UNKNOWN",
                "error": "baseline_dir not supplied",
                "reason": "whole-program symbolic fallback unavailable",
            }
        cmd = [
            sys.executable, str(Path(__file__).resolve()), "--symbolic-worker",
            "--object", args.object, "--policy", args.policy,
            "--baseline-dir", args.baseline_dir,
        ]
        if args.socket_path:
            cmd.extend(["--socket-path", args.socket_path])
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=args.symbolic_timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"symbolic verifier exceeded {args.symbolic_timeout_seconds}s") from exc
        if proc.returncode != 0:
            return {
                "verdict": "UNKNOWN",
                "error": f"worker exit {proc.returncode}: {proc.stderr[-2000:]}",
                "reason": "symbolic worker failed",
            }
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {
                "verdict": "UNKNOWN",
                "error": "symbolic worker returned unparsable output",
                "reason": proc.stdout[-2000:],
            }

    # Dispatch abstract runner according to mode
    actual_abstract_runner: Callable[[], dict[str, Any]] | None
    if abstract_runner is not None:
        actual_abstract_runner = abstract_runner
    elif canonical_mode == MODE_WHOLE_HYBRID:
        actual_abstract_runner = abstract_once_legacy
    elif canonical_mode == MODE_REGION_HYBRID:
        actual_abstract_runner = abstract_once_region
    else:
        actual_abstract_runner = None

    actual_symbolic_runner: Callable[[], dict[str, Any]] | None
    if symbolic_runner is not None:
        actual_symbolic_runner = symbolic_runner
    else:
        actual_symbolic_runner = symbolic_once

    gate_result = tri_mode_gate(
        canonical_mode,
        abstract_runner=actual_abstract_runner,
        symbolic_runner=actual_symbolic_runner,
        scope_id="program",
    )

    end_to_end_duration_ms = (time.monotonic_ns() - run_start_ns) / 1_000_000

    # Collect structural information based on mode
    cfg_blocks: list[dict[str, Any]]
    reachable_order: list[str]
    regions_count: int | None
    reachable_regions_count: int | None
    basic_blocks_count: int | None
    serialized_regions: dict[str, Any] | None

    if canonical_mode == MODE_REGION_HYBRID:
        regions_count = region_holder.get("total_regions")
        reachable_regions_count = len(region_holder.get("reachable_regions", []))
        basic_blocks_count = region_holder.get("total_basic_blocks")
        serialized_regions = region_holder.get("region_results")
        cfg_blocks = region_holder.get("cfg", [])
        reachable_order = region_holder.get("reachable_regions", [])
        gate_result["abstract_reason"] = (
            gate_result.get("abstract_reason")
            or region_holder.get("composition", {}).get("reason", "")
        )
    elif canonical_mode == MODE_WHOLE_HYBRID:
        cfg_blocks = cfg_holder.get("blocks", [])
        reachable_order = control_flow_order(cfg_blocks)
        basic_blocks_count = len(cfg_blocks)
        regions_count = None
        reachable_regions_count = sum(1 for b in cfg_blocks if b.get("reachable"))
        serialized_regions = None
        gate_result["abstract_reason"] = (
            gate_result.get("abstract_reason")
            or abstract_holder.get("result", {}).get("proof", "")
        )
    else:  # MODE_SYMBOLIC_ONLY
        cfg_blocks = []
        reachable_order = []
        basic_blocks_count = None
        regions_count = None
        reachable_regions_count = None
        serialized_regions = None

    # Error and timeout aggregation
    raw_errors = [e for e in [gate_result.get("abstract_error"), gate_result.get("symbolic_error")] if e]
    errors: list[str] = []
    timeouts: list[str] = []
    for err in raw_errors:
        if "timeout" in str(err).lower():
            timeouts.append(err)
        else:
            errors.append(err)

    # Unresolved reason only if the run is unresolved
    if gate_result.get("disposition") == "unresolved" or gate_result.get("overall_verdict") in {"UNKNOWN", "TIMEOUT", "ERROR"}:
        unresolved_reason = (
            timeouts[0] if timeouts else (
                errors[0] if errors else (
                    gate_result.get("abstract_reason")
                    if gate_result.get("overall_verdict") in {"UNKNOWN", "TIMEOUT", "ERROR"}
                    and not gate_result.get("symbolic_verdict")
                    else gate_result.get("symbolic_reason")
                )
            )
        )
    else:
        unresolved_reason = None

    final_verdict = gate_result["overall_verdict"]
    oracle_agreement = compute_oracle_agreement(reference_verdict, final_verdict)
    tag = "warmup" if is_warmup else f"rep{repetition}"
    run_id = f"{program_id}_{canonical_mode}_{tag}"
    pair_id = f"{program_id}_{tag}"

    payload = {
        "schema": "split-bypass-run-record/v2",
        "run_id": run_id,
        "pair_id": pair_id,
        "program_id": program_id,
        "mode": canonical_mode,
        "pipeline": canonical_mode,
        "fixture_family": fixture_family,
        "repetition": repetition,
        "is_warmup": is_warmup,

        "object": str(Path(args.object).resolve()),
        "elf_path": str(args.object),
        "elf_sha256": elf_sha256,
        "source_path": source_path,
        "source_sha256": source_sha256,
        "policy": str(Path(args.policy).resolve()),
        "policy_path": str(args.policy),
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,

        "analyzer": gate_result["analyzer"],
        "analyzer_scope": gate_result["analyzer_scope"],
        "abstract_stage_verdict": gate_result["abstract_verdict"],
        "abstract_verdict": gate_result["abstract_verdict"],
        "abstract_reason": gate_result["abstract_reason"],
        "abstract_duration_ms": gate_result["abstract_duration_ms"],

        "symbolic_invoked": gate_result["symbolic_invoked"],
        "symbolic_verdict": gate_result["symbolic_verdict"],
        "symbolic_reason": gate_result["symbolic_reason"],
        "symbolic_duration_ms": gate_result["symbolic_duration_ms"],
        "fallback_invoked": gate_result["fallback_invoked"],
        "fallback_scope": gate_result["fallback_scope"],

        "overall_verdict": final_verdict,
        "final_verdict": final_verdict,
        "overall_status": gate_result["disposition"],
        "disposition": gate_result["disposition"],

        "regions_analyzed_count": regions_count,
        "reachable_regions_count": reachable_regions_count,
        "basic_blocks_count": basic_blocks_count,
        "regions": serialized_regions,

        "errors": errors,
        "timeouts": timeouts,
        "unresolved_reason": unresolved_reason,

        "reference_verdict": reference_verdict,
        "oracle_agreement": oracle_agreement,

        "end_to_end_duration_ms": end_to_end_duration_ms,
        "metrics": {
            "end_to_end_duration_ms": end_to_end_duration_ms,
            "abstract_duration_ms": gate_result["abstract_duration_ms"],
            "symbolic_duration_ms": gate_result["symbolic_duration_ms"],
            "symbolic_invoked": gate_result["symbolic_invoked"],
            "symbolic_fallback_count": 1 if gate_result["fallback_invoked"] else 0,
            "abstract_pass_count": int(gate_result["disposition"] == "abstract_pass"),
            "symbolic_pass_count": int(gate_result["disposition"] == "symbolic_pass"),
            "violation_count": int(gate_result["disposition"] == "violation"),
            "unresolved_count": int(gate_result["disposition"] == "unresolved"),
            "cfg_block_count": basic_blocks_count or 0,
            "reachable_block_count": reachable_regions_count or basic_blocks_count or 0,
            "regions_analyzed_count": regions_count,
            "reachable_regions_count": reachable_regions_count,
        },
        "cfg": {"blocks": cfg_blocks, "reachable_order": reachable_order},
        "units": [gate_result],
        "source_provenance": {
            "integration_base_commit": INTEGRATION_BASE_COMMIT,
            "prototype_source_commit": PROTOTYPE_SOURCE_COMMIT,
            "experiment_script": "research/experiments/scripts/split_analyze_bypass.py",
        },
        "run_configuration": {
            "mode": canonical_mode,
            "abstract_timeout_seconds": args.abstract_timeout_seconds,
            "symbolic_timeout_seconds": args.symbolic_timeout_seconds,
            "baseline_dir": str(Path(args.baseline_dir).resolve()) if args.baseline_dir else None,
            "socket_path": args.socket_path,
        },
        "tool_versions": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "abstract_analyzer_git_blob": "ca07c1ad340e4220f227a8051b91a62faa0dce5d",
            "krakenguard_expected_commit": "e7bd84005b304c5a10efcdb04914d1882b3cccf7",
        },
        "limits": {
            "abstract_timeout_seconds": args.abstract_timeout_seconds,
            "symbolic_timeout_seconds": args.symbolic_timeout_seconds,
        },
        "experiment_mode": canonical_mode,
    }
    return payload


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--object", required=True, help="path to compiled eBPF ELF binary")
    p.add_argument("--policy", required=True, help="path to JSON policy specification")
    p.add_argument(
        "--mode",
        default=MODE_WHOLE_HYBRID,
        help="verification mode: symbolic_only, whole_hybrid, or region_hybrid (default: whole_hybrid)",
    )
    p.add_argument("--program-id", help="fixture ID or program name")
    p.add_argument("--output", help="new result JSON path; existing files are refused")
    p.add_argument("--baseline-dir", help="path to frozen KRAKENGUARD artifact directory")
    p.add_argument("--socket-path", help="path to KRAKENGUARD unix domain socket")
    p.add_argument("--abstract-timeout-seconds", type=float, default=60.0)
    p.add_argument("--symbolic-timeout-seconds", type=float, default=120.0)
    p.add_argument("--repetition", type=int, default=0, help="repetition index (0 for warmup)")
    p.add_argument("--is-warmup", action="store_true", help="mark this execution as a warmup run")
    p.add_argument("--reference-verdict", help="expected ground-truth oracle verdict (SAFE or VIOLATION)")
    p.add_argument("--source", help="path to source C code")
    p.add_argument("--fixture-family", help="corpus family name")
    p.add_argument("--policy-id", help="policy identifier or short hash")
    p.add_argument("--abstract-worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--region-worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--symbolic-worker", action="store_true", help=argparse.SUPPRESS)

    args = p.parse_args()
    if args.abstract_worker:
        return _abstract_worker(args)
    if args.region_worker:
        return _region_worker(args)
    if args.symbolic_worker:
        return _symbolic_worker(args)

    if not args.output:
        p.error("--output is required outside worker modes")
    if args.abstract_timeout_seconds <= 0:
        p.error("--abstract-timeout-seconds must be positive")
    if args.symbolic_timeout_seconds <= 0:
        p.error("--symbolic-timeout-seconds must be positive")

    output = Path(args.output)
    if output.exists():
        p.error(f"refusing to overwrite existing result: {output}")

    payload = run_program(args)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({
        "output": str(output),
        "mode": payload["mode"],
        "overall_status": payload["overall_status"],
        "overall_verdict": payload["overall_verdict"],
        "fallback_invoked": payload["fallback_invoked"],
        "oracle_agreement": payload["oracle_agreement"],
        "end_to_end_duration_ms": payload["end_to_end_duration_ms"],
    }, indent=2))
    return 0 if payload["overall_status"] != "unresolved" else 2


if __name__ == "__main__":
    raise SystemExit(main())
