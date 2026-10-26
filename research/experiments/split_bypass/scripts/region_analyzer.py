#!/usr/bin/env python3
"""Region-level abstract interpreter and CFG abstract state propagator.

Implements genuine region-scoped abstract interpretation:
    analyze_region(program, region, incoming_state, policy, path_constraints)
and sound propagation across reachable CFG blocks and regions with multi-predecessor
state joins and cycle / loop detection.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

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

# Standard BPF helper function ID mapping
BPF_HELPER_MAP: dict[int, str] = {
    1: "bpf_map_lookup_elem",
    2: "bpf_map_update_elem",
    3: "bpf_map_delete_elem",
    4: "bpf_probe_read",
    5: "bpf_ktime_get_ns",
    6: "bpf_trace_printk",
    7: "bpf_get_prandom_u32",
    8: "bpf_get_smp_processor_id",
    9: "bpf_skb_store_bytes",
    10: "bpf_l3_csum_replace",
    11: "bpf_l4_csum_replace",
    12: "bpf_tail_call",
    13: "bpf_clone_redirect",
    14: "bpf_get_current_pid_tgid",
    15: "bpf_get_current_uid_gid",
    16: "bpf_get_current_comm",
    25: "bpf_perf_event_output",
    26: "bpf_redirect",
    43: "bpf_xdp_adjust_head",
    51: "bpf_redirect_map",
}

WIDTH_MAP: dict[str, int] = {
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
}


@dataclass(frozen=True)
class BpfInstruction:
    pc: int
    text: str
    opcode_name: str
    args: str


@dataclass
class BpfBasicBlock:
    block_id: str
    start_pc: int
    instructions: list[BpfInstruction] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    cond_target: str | None = None
    fallthrough: str | None = None
    is_exit: bool = False


class BpfProgramContext:
    """Encapsulates parsed eBPF program instructions, CFG basic blocks, relocations, and policy."""

    def __init__(
        self,
        instructions: Sequence[BpfInstruction] | None = None,
        basic_blocks: Mapping[str, BpfBasicBlock] | None = None,
        relocations: Mapping[int, str] | None = None,
        policy: Mapping[str, Any] | None = None,
        object_path: Path | str | None = None,
        policy_path: Path | str | None = None,
    ):
        self.instructions: list[BpfInstruction] = list(instructions or [])
        self.basic_blocks: dict[str, BpfBasicBlock] = dict(basic_blocks or {})
        self.relocations: dict[int, str] = dict(relocations or {})
        self.policy: dict[str, Any] = dict(policy or {})

        if object_path:
            self._disassemble_object(Path(object_path).resolve())
            self._build_cfg()
        if policy_path:
            with open(policy_path) as f:
                self.policy = json.load(f)

        self.allowed_helpers = self._parse_allowed_helpers()
        self.forbidden_helpers = set(self.policy.get("helper_func", []))
        self.has_return_rule, self.allowed_returns = self._parse_allowed_returns()
        self.allowed_maps = self._parse_allowed_maps()

    def _parse_allowed_helpers(self) -> set[str]:
        out = []
        for v in self.policy.values():
            if isinstance(v, dict) and isinstance(v.get("actions"), dict):
                out.extend(v["actions"].get("helper_access", []))
        return set(out)

    def _parse_allowed_returns(self) -> tuple[bool, set[int]]:
        has_rule = False
        out = []
        for v in self.policy.values():
            if isinstance(v, dict) and isinstance(v.get("actions"), dict):
                if "return_value" in v["actions"]:
                    has_rule = True
                    out.extend(v["actions"].get("return_value", []))
        return (has_rule, set(out))

    def _parse_allowed_maps(self) -> set[str]:
        out = []
        for v in self.policy.values():
            if isinstance(v, dict) and isinstance(v.get("actions"), dict):
                for m in v["actions"].get("map_access", []):
                    out.append(m.get("name") if isinstance(m, dict) else m)
        return {x for x in out if x}

    def _memory_policy_constrained(self) -> bool:
        for v in self.policy.values():
            if isinstance(v, dict):
                deps = v.get("dependencies")
                if isinstance(deps, dict) and deps.get("memory"):
                    return True
                actions = v.get("actions")
                if isinstance(actions, dict) and actions.get("memory_access"):
                    return True
        return False

    def _is_packet_write_forbidden(self) -> bool:
        for v in self.policy.values():
            if isinstance(v, dict):
                actions = v.get("actions")
                if isinstance(actions, dict):
                    mem = actions.get("memory_access")
                    if isinstance(mem, list):
                        for m in mem:
                            if isinstance(m, dict) and m.get("write-access") == ["x"]:
                                return True
        return False

    def _disassemble_object(self, obj_path: Path) -> None:
        if not obj_path.exists():
            raise FileNotFoundError(f"Object file not found: {obj_path}")

        # Relocations
        rel = subprocess.run(
            ["llvm-readelf", "-r", str(obj_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if rel.returncode == 0:
            for line in rel.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and re.fullmatch(r"[0-9A-Fa-f]+", parts[0]):
                    try:
                        self.relocations[int(parts[0], 16)] = parts[-1]
                    except ValueError:
                        pass

        # Disassembly
        dump = subprocess.run(
            ["llvm-objdump", "-d", "--no-show-raw-insn", str(obj_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if dump.returncode != 0:
            raise RuntimeError(f"llvm-objdump failed for {obj_path}: {dump.stderr}")

        active = False
        self.instructions.clear()
        for line in dump.stdout.splitlines():
            s = line.strip()
            if "Disassembly of section" in s:
                active = "xdp" in s or ".text" in s
                continue
            if not active or not s or s.endswith(":"):
                continue
            m = re.match(r"^([0-9A-Fa-f]+):\s*(.*)$", s)
            if not m:
                continue
            pc = int(m.group(1), 16)
            rest = m.group(2).strip()
            toks = rest.split(None, 1)
            opcode = toks[0] if toks else ""
            args = toks[1] if len(toks) > 1 else ""
            self.instructions.append(BpfInstruction(pc, rest, opcode, args))

        if not self.instructions:
            raise RuntimeError(f"No executable instructions parsed from {obj_path}")

    @staticmethod
    def _branch_target(ins: BpfInstruction) -> int | None:
        m = re.search(r"goto\s+([+-]?0x[0-9A-Fa-f]+|-?\d+)", ins.args)
        if not m:
            return None
        val_str = m.group(1)
        offset = int(val_str, 16 if "0x" in val_str.lower() else 10)
        return ins.pc + 1 + offset

    def _build_cfg(self) -> None:
        pcs = [x.pc for x in self.instructions]
        leaders = {pcs[0]}
        idx = {p: i for i, p in enumerate(pcs)}

        for i, ins in enumerate(self.instructions):
            if ins.opcode_name.startswith("if") or ins.opcode_name == "goto":
                t = self._branch_target(ins)
                if t is not None:
                    leaders.add(t)
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].pc)
            elif ins.opcode_name == "exit" and i + 1 < len(self.instructions):
                leaders.add(self.instructions[i + 1].pc)

        self.basic_blocks.clear()
        for p in sorted(leaders):
            bid = f"bb_{p:x}"
            self.basic_blocks[bid] = BpfBasicBlock(block_id=bid, start_pc=p)

        # Populate instructions per block
        cur: BpfBasicBlock | None = None
        for ins in self.instructions:
            bid = f"bb_{ins.pc:x}"
            if bid in self.basic_blocks:
                cur = self.basic_blocks[bid]
            if cur:
                cur.instructions.append(ins)

        # Establish successors and predecessors
        for bid, bb in self.basic_blocks.items():
            if not bb.instructions:
                continue
            last = bb.instructions[-1]
            i = idx[last.pc]
            nxt_pc = self.instructions[i + 1].pc if i + 1 < len(self.instructions) else None
            nxt_bid = f"bb_{nxt_pc:x}" if nxt_pc is not None else None

            if last.opcode_name == "exit":
                bb.is_exit = True
            elif last.opcode_name == "goto":
                t = self._branch_target(last)
                t_bid = f"bb_{t:x}" if t is not None else None
                if t_bid:
                    bb.successors = [t_bid]
            elif last.opcode_name.startswith("if"):
                t = self._branch_target(last)
                t_bid = f"bb_{t:x}" if t is not None else None
                if t_bid and nxt_bid:
                    bb.cond_target = t_bid
                    bb.fallthrough = nxt_bid
                    bb.successors = [t_bid, nxt_bid]
            elif nxt_bid is not None:
                bb.successors = [nxt_bid]

        # Invert for predecessors
        for bid, bb in self.basic_blocks.items():
            for succ in bb.successors:
                if succ in self.basic_blocks and bid not in self.basic_blocks[succ].predecessors:
                    self.basic_blocks[succ].predecessors.append(bid)


def partition_basic_blocks(context: BpfProgramContext) -> list[RegionBoundary]:
    """Partitions the program CFG into single-block regions."""
    regions = []
    for bid, bb in sorted(context.basic_blocks.items(), key=lambda kv: kv[1].start_pc):
        regions.append(
            RegionBoundary(
                region_id=bid,
                entry_block_id=bid,
                blocks=(bid,),
                predecessors=tuple(sorted(bb.predecessors)),
                successors=tuple(sorted(bb.successors)),
                exit_blocks=(bid,),
                scope=ScopeLevel.BASIC_BLOCK,
            )
        )
    return regions


def find_cfg_backedges(context: BpfProgramContext) -> set[tuple[str, str]]:
    """Detects all back-edges in the CFG using 3-color DFS.

    Returns a set of directed edges (u, v) where v is an ancestor of u on the current DFS path.
    """
    back_edges: set[tuple[str, str]] = set()
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {bid: WHITE for bid in context.basic_blocks}

    entry_candidates = [bid for bid, bb in context.basic_blocks.items() if bb.start_pc == 0]
    if not entry_candidates:
        entry_candidates = sorted(context.basic_blocks.keys())

    def dfs(u: str) -> None:
        color[u] = GRAY
        bb = context.basic_blocks.get(u)
        if bb:
            for v in sorted(bb.successors):
                if v not in color:
                    continue
                if v == u or color[v] == GRAY:
                    back_edges.add((u, v))
                elif color[v] == WHITE:
                    dfs(v)
        color[u] = BLACK

    for entry in entry_candidates:
        if color.get(entry) == WHITE:
            dfs(entry)

    return back_edges


def _parse_immediate(text: str) -> int | None:
    m = re.search(r"(-?0x[0-9A-Fa-f]+|-?\d+)", text)
    if not m:
        return None
    val_str = m.group(1)
    return int(val_str, 16 if "0x" in val_str.lower() else 10)


def _eval_binary_op(
    dst: str,
    op: str,
    rhs: AbstractValue,
    regs: dict[str, AbstractValue],
    is_32bit: bool = False,
) -> None:
    cur = regs.get(dst, AbstractValue.unknown())
    if not cur.is_const() or not rhs.is_const():
        regs[dst] = AbstractValue.unknown()
        return
    x, y = cur.value, rhs.value
    try:
        if op == "+":
            res = x + y
        elif op == "-":
            res = x - y
        elif op == "*":
            res = x * y
        elif op == "&":
            res = x & y
        elif op == "|":
            res = x | y
        elif op == "^":
            res = x ^ y
        elif op == "<<":
            res = x << y
        elif op == ">>":
            res = x >> y
        else:
            regs[dst] = AbstractValue.unknown()
            return
        if is_32bit:
            res = res & 0xFFFFFFFF
        regs[dst] = AbstractValue.const(res)
    except Exception:
        regs[dst] = AbstractValue.unknown()


def _eval_branch_condition(ins: BpfInstruction, regs: Mapping[str, AbstractValue]) -> bool | None:
    m = re.search(r"if\s+([rw]\d+)\s*(==|!=|>|>=|<|<=)\s*([rw]\d+|0x[0-9A-Fa-f]+|-?\d+)\s+goto", ins.text)
    if not m:
        return None
    reg_a = "r" + m.group(1)[1:]
    a = regs.get(reg_a, AbstractValue.unknown())
    target_str = m.group(3)
    if target_str.startswith(("r", "w")):
        reg_b = "r" + target_str[1:]
        b = regs.get(reg_b, AbstractValue.unknown())
    else:
        imm = _parse_immediate(target_str)
        b = AbstractValue.const(imm) if imm is not None else AbstractValue.unknown()

    if not (a.is_const() and b.is_const()):
        return None
    x, y = a.value, b.value
    # If 32-bit compare, mask to 32 bits
    if m.group(1).startswith("w"):
        x = x & 0xFFFFFFFF
        y = y & 0xFFFFFFFF
    op = m.group(2)
    cmp_map = {
        "==": x == y,
        "!=": x != y,
        ">": x > y,
        ">=": x >= y,
        "<": x < y,
        "<=": x <= y,
    }
    return cmp_map.get(op)


def analyze_region(
    program: BpfProgramContext,
    region: RegionBoundary,
    incoming_state: IncomingAbstractState,
    policy: Mapping[str, Any] | None = None,
    path_constraints: Sequence[str] | None = None,
) -> RegionResult:
    """Performs abstract interpretation on a specific region under an explicit incoming state.

    Soundness invariants:
    - Never defaults uninitialized or missing state to SAFE.
    - Accurately tracks 64-bit and 32-bit registers, constants, helper calls, and returns.
    - Yields typed RegionResult (SAFE, VIOLATION, or UNKNOWN).
    - Scope strictly matches region.scope (never whole_program).
    """
    if incoming_state is None or not isinstance(incoming_state, IncomingAbstractState):
        raise ValueError("analyze_region requires an explicit IncomingAbstractState")
    if not incoming_state.is_explicit:
        raise ValueError("IncomingAbstractState cannot be implicit or uninitialized")

    if region.entry_block_id not in program.basic_blocks:
        return RegionResult(
            region_id=region.region_id,
            verdict=RegionVerdict.UNKNOWN,
            scope=region.scope,
            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
            entry_assumptions=incoming_state,
            unresolved_reason=f"Entry block '{region.entry_block_id}' not found in program CFG",
            backend_executor_scope=region.scope,
        )

    # Initialize 64-bit register map from incoming state
    regs: dict[str, AbstractValue] = {f"r{i}": incoming_state.registers.get(f"r{i}") for i in range(11)}
    stack_slots: dict[int, tuple[int, AbstractValue]] = dict(incoming_state.stack_assumptions or {})

    effective_policy = policy if policy is not None else program.policy
    allowed_helpers = program.allowed_helpers
    forbidden_helpers = program.forbidden_helpers
    has_return_rule, allowed_returns = program.has_return_rule, program.allowed_returns
    allowed_maps = program.allowed_maps

    exit_states: dict[str, IncomingAbstractState] = {}
    path_constraints_list = list(incoming_state.path_constraints) + list(path_constraints or [])

    # Process blocks in region sequentially
    for bid in region.blocks:
        bb = program.basic_blocks.get(bid)
        if not bb:
            return RegionResult(
                region_id=region.region_id,
                verdict=RegionVerdict.UNKNOWN,
                scope=region.scope,
                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                entry_assumptions=incoming_state,
                unresolved_reason=f"Missing basic block '{bid}' in region '{region.region_id}'",
                backend_executor_scope=region.scope,
            )

        for ins in bb.instructions:
            op = ins.opcode_name

            # Helper call
            if op == "call":
                hid = _parse_immediate(ins.args)
                if hid is None or hid not in BPF_HELPER_MAP:
                    return RegionResult(
                        region_id=region.region_id,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                        entry_assumptions=incoming_state,
                        unresolved_reason=f"Unknown or unmodeled helper id '{ins.args}' at pc {ins.pc}",
                        backend_executor_scope=region.scope,
                    )
                name = BPF_HELPER_MAP[hid]
                if name in forbidden_helpers:
                    return RegionResult(
                        region_id=region.region_id,
                        verdict=RegionVerdict.VIOLATION,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                        entry_assumptions=incoming_state,
                        violating_path_evidence=f"Call to forbidden helper '{name}' at pc {ins.pc}",
                        backend_executor_scope=region.scope,
                    )
                if allowed_helpers and "*" not in allowed_helpers and name not in allowed_helpers:
                    return RegionResult(
                        region_id=region.region_id,
                        verdict=RegionVerdict.VIOLATION,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                        entry_assumptions=incoming_state,
                        violating_path_evidence=f"Call to unauthorized helper '{name}' at pc {ins.pc}",
                        backend_executor_scope=region.scope,
                    )

                # Map helpers check
                if name in {"bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_map_delete_elem", "bpf_redirect_map"}:
                    map_name = program.relocations.get(ins.pc * 8) or program.relocations.get(ins.pc)
                    if not map_name:
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Unresolved map identity for '{name}' at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    if allowed_maps and map_name not in allowed_maps:
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.VIOLATION,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            violating_path_evidence=f"Access to unauthorized map '{map_name}' via '{name}' at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    if name != "bpf_map_lookup_elem":
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Map mutation/redirect semantics for '{map_name}' not supported at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )

                regs["r0"] = AbstractValue.symbolic(name)
                for r in ["r1", "r2", "r3", "r4", "r5"]:
                    regs[r] = AbstractValue.unknown()
                continue

            # Exit instruction
            if op == "exit":
                r0_val = regs.get("r0", AbstractValue.unknown())
                if has_return_rule:
                    if r0_val.is_const():
                        if r0_val.value not in allowed_returns:
                            return RegionResult(
                                region_id=region.region_id,
                                verdict=RegionVerdict.VIOLATION,
                                scope=region.scope,
                                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                                entry_assumptions=incoming_state,
                                violating_path_evidence=f"Exit with forbidden return value {r0_val.value} at pc {ins.pc}",
                                backend_executor_scope=region.scope,
                            )
                    else:
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Exit with indeterminate return value '{r0_val.kind}' when return policy is active at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                # Terminal exit reached safely
                out_reg_state = AbstractRegisterState(registers=dict(regs))
                exit_states["terminal_exit"] = IncomingAbstractState(
                    registers=out_reg_state,
                    stack_assumptions=dict(stack_slots),
                    path_constraints=tuple(path_constraints_list),
                )
                return RegionResult(
                    region_id=region.region_id,
                    verdict=RegionVerdict.SAFE,
                    scope=region.scope,
                    analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                    entry_assumptions=incoming_state,
                    exit_states=exit_states,
                    backend_executor_scope=region.scope,
                )

            # Explicit Memory Load: [rw]X = *(u8|u16|u32|u64 *)(...)
            m_mem_load = re.match(
                r"^([rw](?:10|[0-9]))\s*=\s*\*\((u8|u16|u32|u64)\s*\*\)\(([rw](?:10|[0-9]))(?:\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+))?\)",
                ins.text,
            )
            if m_mem_load:
                dst_raw = m_mem_load.group(1)
                dst_reg = "r" + dst_raw[1:]
                is_32bit = dst_raw.startswith("w")
                width = WIDTH_MAP[m_mem_load.group(2)]
                base_reg = m_mem_load.group(3)
                sign = m_mem_load.group(4)
                off_str = m_mem_load.group(5) or "0"
                off_val = int(off_str, 16 if "0x" in off_str else 10)
                offset = -off_val if sign == "-" else off_val

                if base_reg in ("r10", "w10"):
                    # Stack read: validate bounds [-512, 0)
                    if offset < -512 or offset >= 0 or (offset + width) > 0:
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Invalid stack load out of bounds [{offset}, {offset+width}) at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    slot = stack_slots.get(offset)
                    if slot and slot[0] == width:
                        val = slot[1]
                        if is_32bit and val.is_const():
                            val = AbstractValue.const(val.value & 0xFFFFFFFF)
                        regs[dst_reg] = val
                    else:
                        regs[dst_reg] = AbstractValue.unknown()
                else:
                    # Non-stack (packet or map) load
                    regs[dst_reg] = AbstractValue.unknown()
                continue

            # Explicit Memory Store: *(u8|u16|u32|u64 *)(...) = src
            m_mem_store = re.match(
                r"^\*\((u8|u16|u32|u64)\s*\*\)\(([rw](?:10|[0-9]))(?:\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+))?\)\s*=\s*([rw](?:10|[0-9])|-?(?:0x[0-9A-Fa-f]+|\d+))",
                ins.text,
            )
            if m_mem_store:
                width = WIDTH_MAP[m_mem_store.group(1)]
                base_reg = m_mem_store.group(2)
                sign = m_mem_store.group(3)
                off_str = m_mem_store.group(4) or "0"
                off_val = int(off_str, 16 if "0x" in off_str else 10)
                offset = -off_val if sign == "-" else off_val
                rhs_val_str = m_mem_store.group(5)

                if re.fullmatch(r"[rw](?:10|[0-9])", rhs_val_str):
                    src_reg = "r" + rhs_val_str[1:]
                    val = regs.get(src_reg, AbstractValue.unknown())
                    if rhs_val_str.startswith("w") and val.is_const():
                        val = AbstractValue.const(val.value & 0xFFFFFFFF)
                else:
                    imm = _parse_immediate(rhs_val_str)
                    val = AbstractValue.const(imm) if imm is not None else AbstractValue.unknown()

                if base_reg in ("r10", "w10"):
                    # Stack store: validate bounds [-512, 0)
                    if offset < -512 or offset >= 0 or (offset + width) > 0:
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Invalid stack store out of bounds [{offset}, {offset+width}) at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    # Invalidate overlapping slots
                    overlapping = [
                        k for k, (w, _) in stack_slots.items()
                        if not (k + w <= offset or offset + width <= k)
                    ]
                    for k in overlapping:
                        del stack_slots[k]
                    stack_slots[offset] = (width, val)
                    continue
                else:
                    # Non-stack memory store (e.g. packet write)
                    if program._is_packet_write_forbidden():
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.VIOLATION,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            violating_path_evidence=f"Forbidden memory write via '{base_reg}' at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    if program._memory_policy_constrained():
                        return RegionResult(
                            region_id=region.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=region.scope,
                            analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                            entry_assumptions=incoming_state,
                            unresolved_reason=f"Memory store requires policy-aware proof at pc {ins.pc}",
                            backend_executor_scope=region.scope,
                        )
                    continue

            # Register assignment / ALU expressions: [rw]X = ...
            if " = " in ins.text and re.match(r"^[rw](?:10|[0-9])\s*=\s*", ins.text):
                lhs, rhs = ins.text.split(" = ", 1)
                lhs, rhs = lhs.strip(), rhs.strip()
                is_32bit = lhs.startswith("w")
                dst_reg = "r" + lhs[1:]

                # Direct register move: rX = rY or wX = wY
                if re.fullmatch(r"[rw](?:10|[0-9])", rhs):
                    src_reg = "r" + rhs[1:]
                    src_val = regs.get(src_reg, AbstractValue.unknown())
                    if is_32bit and src_val.is_const():
                        regs[dst_reg] = AbstractValue.const(src_val.value & 0xFFFFFFFF)
                    else:
                        regs[dst_reg] = src_val
                    continue

                # Immediate assignment: rX = imm or wX = imm
                if re.fullmatch(r"-?(?:0x[0-9A-Fa-f]+|\d+)(?:\s+ll)?", rhs):
                    rel_name = program.relocations.get(ins.pc * 8) or program.relocations.get(ins.pc)
                    if rel_name:
                        regs[dst_reg] = AbstractValue.symbolic(rel_name)
                    else:
                        imm = _parse_immediate(rhs)
                        if imm is not None:
                            val = (imm & 0xFFFFFFFF) if is_32bit else imm
                            regs[dst_reg] = AbstractValue.const(val)
                        else:
                            regs[dst_reg] = AbstractValue.unknown()
                    continue

                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*(?:\s+ll)?", rhs):
                    regs[dst_reg] = AbstractValue.symbolic(rhs.split()[0])
                    continue

                # Generic memory load fallback (if unhandled by explicit pattern above)
                if re.fullmatch(r"\*\([^)]*\)\([rw](?:10|[0-9])(?:\s*[+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\)", rhs):
                    regs[dst_reg] = AbstractValue.unknown()
                    continue

                # Binary expr with immediate: rX = rY <op> imm
                m_bin = re.fullmatch(r"([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\s*(-?(?:0x[0-9A-Fa-f]+|\d+))", rhs)
                if m_bin:
                    src_reg = "r" + m_bin.group(1)[1:]
                    imm = _parse_immediate(m_bin.group(3))
                    # Temporarily load src_reg value into dst_reg, then perform op
                    regs[dst_reg] = regs.get(src_reg, AbstractValue.unknown())
                    _eval_binary_op(
                        dst_reg,
                        m_bin.group(2),
                        AbstractValue.const(imm) if imm is not None else AbstractValue.unknown(),
                        regs,
                        is_32bit=is_32bit,
                    )
                    continue

                # Binary expr with register: rX = rY <op> rZ
                m_reg = re.fullmatch(r"([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\s*([rw](?:10|[0-9]))", rhs)
                if m_reg:
                    src1_reg = "r" + m_reg.group(1)[1:]
                    src2_reg = "r" + m_reg.group(3)[1:]
                    regs[dst_reg] = regs.get(src1_reg, AbstractValue.unknown())
                    _eval_binary_op(
                        dst_reg,
                        m_reg.group(2),
                        regs.get(src2_reg, AbstractValue.unknown()),
                        regs,
                        is_32bit=is_32bit,
                    )
                    continue

                return RegionResult(
                    region_id=region.region_id,
                    verdict=RegionVerdict.UNKNOWN,
                    scope=region.scope,
                    analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                    entry_assumptions=incoming_state,
                    unresolved_reason=f"Unsupported register assignment at pc {ins.pc}: '{ins.text}'",
                    backend_executor_scope=region.scope,
                )

            # In-place ALU: [rw]X += ...
            m_in_imm = re.fullmatch(r"([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\=\s*(-?(?:0x[0-9A-Fa-f]+|\d+))", ins.text)
            if m_in_imm:
                dst_reg = "r" + m_in_imm.group(1)[1:]
                is_32bit = m_in_imm.group(1).startswith("w")
                imm = _parse_immediate(m_in_imm.group(3))
                _eval_binary_op(
                    dst_reg,
                    m_in_imm.group(2),
                    AbstractValue.const(imm) if imm is not None else AbstractValue.unknown(),
                    regs,
                    is_32bit=is_32bit,
                )
                continue

            m_in_reg = re.fullmatch(r"([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\=\s*([rw](?:10|[0-9]))", ins.text)
            if m_in_reg:
                dst_reg = "r" + m_in_reg.group(1)[1:]
                src_reg = "r" + m_in_reg.group(3)[1:]
                is_32bit = m_in_reg.group(1).startswith("w")
                _eval_binary_op(
                    dst_reg,
                    m_in_reg.group(2),
                    regs.get(src_reg, AbstractValue.unknown()),
                    regs,
                    is_32bit=is_32bit,
                )
                continue

            # Fallback memory store pattern
            if re.match(r"^\*\([^)]*\)\([rw](?:10|[0-9])(?:\s*[+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\)\s*=", ins.text):
                if program._memory_policy_constrained():
                    return RegionResult(
                        region_id=region.region_id,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                        entry_assumptions=incoming_state,
                        unresolved_reason=f"Memory store requires policy-aware proof at pc {ins.pc}",
                        backend_executor_scope=region.scope,
                    )
                continue

            if op == "nop":
                continue

            # Branch instructions handled at block exit
            if op.startswith("if") or op == "goto":
                continue

            # Unmodeled instruction -> UNKNOWN
            return RegionResult(
                region_id=region.region_id,
                verdict=RegionVerdict.UNKNOWN,
                scope=region.scope,
                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                entry_assumptions=incoming_state,
                unresolved_reason=f"Unsupported instruction opcode '{op}' at pc {ins.pc}: '{ins.text}'",
                backend_executor_scope=region.scope,
            )

        # Region boundary transfer: compute exit states for block's successors
        last_ins = bb.instructions[-1] if bb.instructions else None
        out_reg_state = AbstractRegisterState(registers=dict(regs))
        out_stack_state = dict(stack_slots)

        if last_ins and last_ins.opcode_name.startswith("if"):
            cond = _eval_branch_condition(last_ins, regs)
            if cond is True:
                if bb.cond_target:
                    exit_states[bb.cond_target] = IncomingAbstractState(
                        registers=out_reg_state,
                        stack_assumptions=out_stack_state,
                        path_constraints=tuple(path_constraints_list + [f"TAKEN({last_ins.pc})"]),
                    )
            elif cond is False:
                if bb.fallthrough:
                    exit_states[bb.fallthrough] = IncomingAbstractState(
                        registers=out_reg_state,
                        stack_assumptions=out_stack_state,
                        path_constraints=tuple(path_constraints_list + [f"NOT_TAKEN({last_ins.pc})"]),
                    )
            else:
                if bb.cond_target:
                    exit_states[bb.cond_target] = IncomingAbstractState(
                        registers=out_reg_state,
                        stack_assumptions=out_stack_state,
                        path_constraints=tuple(path_constraints_list + [f"TAKEN({last_ins.pc})"]),
                    )
                if bb.fallthrough:
                    exit_states[bb.fallthrough] = IncomingAbstractState(
                        registers=out_reg_state,
                        stack_assumptions=out_stack_state,
                        path_constraints=tuple(path_constraints_list + [f"NOT_TAKEN({last_ins.pc})"]),
                    )
        elif last_ins and last_ins.opcode_name == "goto":
            for succ in bb.successors:
                exit_states[succ] = IncomingAbstractState(
                    registers=out_reg_state,
                    stack_assumptions=out_stack_state,
                    path_constraints=tuple(path_constraints_list),
                )
        else:
            for succ in bb.successors:
                exit_states[succ] = IncomingAbstractState(
                    registers=out_reg_state,
                    stack_assumptions=out_stack_state,
                    path_constraints=tuple(path_constraints_list),
                )

    return RegionResult(
        region_id=region.region_id,
        verdict=RegionVerdict.SAFE,
        scope=region.scope,
        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
        entry_assumptions=incoming_state,
        exit_states=exit_states,
        backend_executor_scope=region.scope,
    )


def propagate_and_analyze_program(
    program: BpfProgramContext,
    regions: Sequence[RegionBoundary] | None = None,
    initial_state: IncomingAbstractState | None = None,
    region_symbolic_executor: Any | None = None,
) -> tuple[dict[str, RegionResult], list[str], dict[str, Any]]:
    """Propagates abstract states through CFG regions, joining states at merge points,

    detecting cycles / back-edges, and composing the whole-program verdict.
    """
    if regions is None:
        regions = partition_basic_blocks(program)

    region_map: dict[str, RegionBoundary] = {r.region_id: r for r in regions}
    block_to_region: dict[str, str] = {}
    for r in regions:
        for b in r.blocks:
            block_to_region[b] = r.region_id

    # Detect back-edges in CFG
    cfg_backedges = find_cfg_backedges(program)
    # Map back-edges to region boundaries
    region_backedges: set[tuple[str, str]] = set()
    backedge_targets: set[str] = set()
    for u, v in cfg_backedges:
        r_u = block_to_region.get(u, u)
        r_v = block_to_region.get(v, v)
        region_backedges.add((r_u, r_v))
        backedge_targets.add(r_v)

    # Find entry region (starts with PC 0)
    entry_region: RegionBoundary | None = None
    for r in regions:
        bb = program.basic_blocks.get(r.entry_block_id)
        if bb and bb.start_pc == 0:
            entry_region = r
            break
    if not entry_region and regions:
        entry_region = regions[0]

    if not entry_region:
        raise ValueError("Cannot propagate program with no regions")

    if initial_state is None:
        initial_state = IncomingAbstractState(registers=AbstractRegisterState.default_entry())

    region_in_states: dict[str, IncomingAbstractState] = {entry_region.region_id: initial_state}
    region_results: dict[str, RegionResult] = {}
    reachable_region_ids: list[str] = []

    worklist: deque[str] = deque([entry_region.region_id])
    visited: set[str] = set()

    while worklist:
        rid = worklist.popleft()
        if rid not in region_map:
            continue

        region = region_map[rid]
        curr_in_state = region_in_states.get(rid)
        if curr_in_state is None:
            continue

        if rid not in reachable_region_ids:
            reachable_region_ids.append(rid)

        # Check if this region is the target of a CFG back-edge / loop
        if rid in backedge_targets:
            region_results[rid] = RegionResult(
                region_id=rid,
                verdict=RegionVerdict.UNKNOWN,
                scope=region.scope,
                analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                entry_assumptions=curr_in_state,
                unresolved_reason=f"CFG cycle / back-edge detected at region '{rid}'",
                backend_executor_scope=region.scope,
            )
            continue

        visited.add(rid)

        # Analyze region
        res = analyze_region(program, region, curr_in_state)
        region_results[rid] = res

        if res.verdict == RegionVerdict.VIOLATION:
            # Violation found; can continue or finish
            continue

        if res.verdict == RegionVerdict.UNKNOWN:
            if region_symbolic_executor is not None:
                # State-aware region-scoped symbolic fallback
                insns = tuple(ins for bid in region.blocks for ins in program.basic_blocks[bid].instructions)
                entry_bb = program.basic_blocks[region.entry_block_id]
                exit_pcs = tuple(
                    program.basic_blocks[eb].instructions[-1].pc
                    for eb in region.exit_blocks
                    if program.basic_blocks[eb].instructions
                )
                req = RegionSymbolicRequest(
                    region_id=rid,
                    scope=region.scope,
                    instructions=insns,
                    incoming_state=curr_in_state,
                    policy=program.policy,
                    entry_pc=entry_bb.start_pc,
                    exit_pcs=exit_pcs,
                )
                sym_res = region_symbolic_executor.execute_region(req)

                # Scope veracity enforcement: cannot claim region_scoped on WHOLE_PROGRAM backend
                if sym_res.is_genuinely_region_scoped and sym_res.backend_executor_scope == ScopeLevel.WHOLE_PROGRAM:
                    raise ValueError(
                        "Scope veracity violation: is_genuinely_region_scoped cannot be True "
                        "when backend_executor_scope is WHOLE_PROGRAM"
                    )

                if sym_res.verdict == RegionVerdict.SAFE:
                    # Map exit states to region's successors
                    mapped_exit_states: dict[str, Any] = {}
                    if sym_res.exit_states:
                        if "exit" in sym_res.exit_states:
                            out_st = sym_res.exit_states["exit"]
                            for eb in region.exit_blocks:
                                for succ in program.basic_blocks[eb].successors:
                                    mapped_exit_states[succ] = out_st
                        else:
                            mapped_exit_states = dict(sym_res.exit_states)

                    res = RegionResult(
                        region_id=rid,
                        verdict=RegionVerdict.SAFE,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
                        entry_assumptions=curr_in_state,
                        exit_states=mapped_exit_states if mapped_exit_states else res.exit_states,
                        backend_executor_scope=sym_res.backend_executor_scope,
                    )
                    region_results[rid] = res
                    # SAFE allows forward propagation to proceed below
                elif sym_res.verdict == RegionVerdict.VIOLATION:
                    res = RegionResult(
                        region_id=rid,
                        verdict=RegionVerdict.VIOLATION,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
                        entry_assumptions=curr_in_state,
                        violating_path_evidence=sym_res.witness_trace,
                        backend_executor_scope=sym_res.backend_executor_scope,
                    )
                    region_results[rid] = res
                    continue
                else:
                    res = RegionResult(
                        region_id=rid,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=region.scope,
                        analysis_method=AnalysisMethod.SYMBOLIC_EXECUTION,
                        entry_assumptions=curr_in_state,
                        unresolved_reason=sym_res.unresolved_reason or res.unresolved_reason,
                        backend_executor_scope=sym_res.backend_executor_scope,
                    )
                    region_results[rid] = res
                    continue
            else:
                continue

        # Propagate exit states to successors
        if res.exit_states:
            for target_id, out_state in res.exit_states.items():
                if target_id == "terminal_exit":
                    continue
                succ_rid = block_to_region.get(target_id, target_id)
                if succ_rid not in region_map:
                    continue

                # If this forward step traverses a back-edge, flag cycle and do not loop
                if (rid, succ_rid) in region_backedges or succ_rid in backedge_targets:
                    backedge_targets.add(succ_rid)
                    if succ_rid not in reachable_region_ids:
                        reachable_region_ids.append(succ_rid)
                    region_results[succ_rid] = RegionResult(
                        region_id=succ_rid,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=region_map[succ_rid].scope,
                        analysis_method=AnalysisMethod.ABSTRACT_INTERPRETATION,
                        entry_assumptions=out_state,
                        unresolved_reason=f"CFG cycle / back-edge detected entering region '{succ_rid}'",
                        backend_executor_scope=region_map[succ_rid].scope,
                    )
                    continue

                existing_in = region_in_states.get(succ_rid)
                if existing_in is None:
                    region_in_states[succ_rid] = out_state
                else:
                    # Sound Join across incoming states (least upper bound)
                    joined_regs = existing_in.registers.join(out_state.registers)
                    joined_constraints = tuple(sorted(set(existing_in.path_constraints) & set(out_state.path_constraints)))
                    # Sound Stack Join across predecessors
                    common_offsets = set(existing_in.stack_assumptions.keys()) & set(out_state.stack_assumptions.keys())
                    joined_stack: dict[int, tuple[int, AbstractValue]] = {}
                    for off in common_offsets:
                        w1, val1 = existing_in.stack_assumptions[off]
                        w2, val2 = out_state.stack_assumptions[off]
                        if w1 == w2:
                            joined_stack[off] = (w1, val1.join(val2))
                    region_in_states[succ_rid] = IncomingAbstractState(
                        registers=joined_regs,
                        stack_assumptions=joined_stack,
                        path_constraints=joined_constraints,
                    )

                if succ_rid not in visited and succ_rid not in worklist:
                    worklist.append(succ_rid)

    # Compose final whole-program verdict
    composition = ProgramVerdictComposer.compose(
        results=list(region_results.values()),
        reachable_region_ids=reachable_region_ids,
    )

    return region_results, reachable_region_ids, composition
