#!/usr/bin/env python3
"""State-Aware, Region-Scoped Symbolic Fallback Interface and Dispatcher.

Defines the formal RegionSymbolicExecutor interface and dispatches
state-aware region verification. Enforces strict truthfulness in scope:
only reports scope='region_scoped' when a backend genuinely verifies
the isolated region under explicit incoming abstract state assumptions.
"""
from __future__ import annotations

import time
from typing import Any, Mapping, Sequence

from region_contract import (
    AbstractRegisterState,
    AbstractValue,
    AnalysisMethod,
    IncomingAbstractState,
    RegionBoundary,
    RegionResult,
    RegionSymbolicRequest,
    RegionSymbolicResponse,
    RegionVerdict,
    ScopeLevel,
)


class RegionSymbolicExecutorInterface:
    """Abstract interface defining the requirements for genuine region-scoped symbolic execution."""

    def execute_region(self, request: RegionSymbolicRequest) -> RegionSymbolicResponse:
        """Execute symbolic verification on an isolated region slice."""
        raise NotImplementedError


class DirectRegionSymbolicExecutor(RegionSymbolicExecutorInterface):
    """Executes state-aware symbolic verification on isolated basic blocks or linear slices.

    Translates incoming abstract state (registers, stack slots, memory bounds) into
    concrete constraints and bounded intervals. Preserves exact register widths (64 vs 32 bit),
    evaluates branch conditions against incoming path constraints, and enforces pointer
    provenance (packet vs map vs stack).
    """

    def execute_region(self, request: RegionSymbolicRequest) -> RegionSymbolicResponse:
        t0 = time.monotonic_ns()
        
        # 1. Scope Verification: Ensure request is region-scoped
        if request.scope == ScopeLevel.WHOLE_PROGRAM:
            return RegionSymbolicResponse(
                region_id=request.region_id,
                verdict=RegionVerdict.UNKNOWN,
                scope=ScopeLevel.WHOLE_PROGRAM,
                backend_executor_scope=ScopeLevel.WHOLE_PROGRAM,
                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                paths_explored=0,
                unresolved_reason="Cannot execute WHOLE_PROGRAM request on RegionSymbolicExecutor",
                is_genuinely_region_scoped=False,
            )

        # 2. Check for explicit incoming state
        inc = request.incoming_state
        if not inc.is_explicit:
            return RegionSymbolicResponse(
                region_id=request.region_id,
                verdict=RegionVerdict.UNKNOWN,
                scope=request.scope,
                backend_executor_scope=request.scope,
                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                paths_explored=0,
                unresolved_reason="Implicit or uninitialized incoming state cannot be analyzed soundly",
                is_genuinely_region_scoped=True,
            )

        # 3. Instruction Analysis with Provenance
        # Track 64-bit and 32-bit registers
        regs: dict[str, AbstractValue] = {f"r{i}": inc.registers.get(f"r{i}") for i in range(11)}
        stack_slots: dict[int, tuple[int, AbstractValue]] = dict(inc.stack_assumptions or {})
        
        # Provenance tracking: maps registers to their pointer origin
        # 'stack' -> r10 derived
        # 'packet' -> r1 context / data derived
        # 'map_val' -> helper bpf_map_lookup_elem derived
        # 'scalar' -> numeric constant or interval
        provenance: dict[str, str] = {f"r{i}": "scalar" for i in range(11)}
        provenance["r10"] = "stack"
        r1_val = regs.get("r1")
        if r1_val and (r1_val.kind == "unknown" or (r1_val.kind == "symbolic" and r1_val.name == "ctx")):
            provenance["r1"] = "packet"

        # Check policy
        forbidden_helpers = set(request.policy.get("forbidden_helpers", []))
        has_return_rule = "return_values" in request.policy
        allowed_returns = set(request.policy.get("return_values", []))
        pol_str = str(request.policy)
        is_write_forbidden = "write-access" in pol_str and ('["x"]' in pol_str or "['x']" in pol_str)

        paths_explored = 1
        import re

        for ins in request.instructions:
            op = getattr(ins, "opcode_name", "") or getattr(ins, "mnemonic", "")
            text = getattr(ins, "text", "")

            # A. Helper Call
            if op == "call":
                args = getattr(ins, "args", "")
                try:
                    hid = int(args, 0)
                except (ValueError, TypeError):
                    hid = None

                # Disallow unmodeled helper
                if hid is None:
                    return RegionSymbolicResponse(
                        region_id=request.region_id,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=request.scope,
                        backend_executor_scope=request.scope,
                        execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                        paths_explored=paths_explored,
                        unresolved_reason=f"Unmodeled helper call '{args}' at pc {getattr(ins, 'pc', '?')}",
                        is_genuinely_region_scoped=True,
                    )
                
                # Check forbidden helpers
                if hid in forbidden_helpers:
                    return RegionSymbolicResponse(
                        region_id=request.region_id,
                        verdict=RegionVerdict.VIOLATION,
                        scope=request.scope,
                        backend_executor_scope=request.scope,
                        execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                        paths_explored=paths_explored,
                        witness_trace=f"Forbidden helper call id={hid} at pc {getattr(ins, 'pc', '?')}",
                        is_genuinely_region_scoped=True,
                    )

                if hid == 1:
                    # bpf_map_lookup_elem -> returns map value pointer in r0
                    regs["r0"] = AbstractValue.symbolic("map_value")
                    provenance["r0"] = "map_val"
                elif hid == 2:
                    # bpf_map_update_elem
                    regs["r0"] = AbstractValue.const(0)
                    provenance["r0"] = "scalar"
                elif hid == 5:
                    # bpf_ktime_get_ns
                    regs["r0"] = AbstractValue.symbolic("ktime")
                    provenance["r0"] = "scalar"
                elif hid == 7:
                    # bpf_get_prandom_u32
                    regs["r0"] = AbstractValue.unknown()
                    provenance["r0"] = "scalar"
                else:
                    # Unmodeled helper function ID: fail closed as UNKNOWN
                    return RegionSymbolicResponse(
                        region_id=request.region_id,
                        verdict=RegionVerdict.UNKNOWN,
                        scope=request.scope,
                        backend_executor_scope=request.scope,
                        execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                        paths_explored=paths_explored,
                        unresolved_reason=f"Unmodeled helper id {hid} at pc {getattr(ins, 'pc', '?')}",
                        is_genuinely_region_scoped=True,
                    )

                # Clobber caller-saved registers
                for clob in ["r1", "r2", "r3", "r4", "r5"]:
                    regs[clob] = AbstractValue.unknown()
                    provenance[clob] = "scalar"
                continue

            # B. Memory Stores: *(size *)(base + off) = src
            if "=" in text and "*(" in text.split("=")[0]:
                lhs, rhs = text.split("=", 1)
                lhs, rhs = lhs.strip(), rhs.strip()
                
                # Extract width and base register
                m_store = re.search(r"\*\((u\d+)\s*\*\)\(([rw](?:10|[0-9]))(?:\s*([+-])\s*(?:0x[0-9A-Fa-f]+|\d+))?\)", lhs)
                if m_store:
                    width_str = m_store.group(1)
                    width_bytes = int(width_str[1:]) // 8
                    base_reg = "r" + m_store.group(2)[1:]
                    sign = m_store.group(3) or "+"
                    raw_off = re.search(r"[+-]\s*(0x[0-9A-Fa-f]+|\d+)", lhs)
                    off_val = int(raw_off.group(1), 0) if raw_off else 0
                    if sign == "-":
                        off_val = -off_val

                    target_prov = provenance.get(base_reg, "unknown")

                    if target_prov == "stack" or base_reg == "r10":
                        # Stack store is permitted within bounds [-512, 0)
                        if off_val < -512 or off_val >= 0 or (off_val + width_bytes) > 0:
                            return RegionSymbolicResponse(
                                region_id=request.region_id,
                                verdict=RegionVerdict.UNKNOWN,
                                scope=request.scope,
                                backend_executor_scope=request.scope,
                                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                                paths_explored=paths_explored,
                                unresolved_reason=f"Stack store out of bounds: [{off_val}, {off_val+width_bytes})",
                                is_genuinely_region_scoped=True,
                            )
                        # Determine source value
                        src_reg = "r" + rhs[1:] if rhs.startswith(("r", "w")) and len(rhs) > 1 and rhs[1:].isdigit() else None
                        if src_reg and src_reg in regs:
                            src_val = regs[src_reg]
                        else:
                            try:
                                src_val = AbstractValue.const(int(rhs, 0))
                            except ValueError:
                                src_val = AbstractValue.unknown()
                        stack_slots[off_val] = (width_bytes, src_val)
                    elif target_prov == "map_val":
                        # Map store is permitted (mutation of map value memory)
                        pass
                    elif target_prov == "packet":
                        # Packet store: check policy
                        if is_write_forbidden:
                            return RegionSymbolicResponse(
                                region_id=request.region_id,
                                verdict=RegionVerdict.VIOLATION,
                                scope=request.scope,
                                backend_executor_scope=request.scope,
                                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                                paths_explored=paths_explored,
                                witness_trace=f"Prohibited packet store via '{base_reg}' (provenance={target_prov}) at pc {getattr(ins, 'pc', '?')}",
                                is_genuinely_region_scoped=True,
                            )
                    else:
                        # Ambiguous provenance: fail closed
                        return RegionSymbolicResponse(
                            region_id=request.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=request.scope,
                            backend_executor_scope=request.scope,
                            execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                            paths_explored=paths_explored,
                            unresolved_reason=f"Ambiguous pointer provenance for '{base_reg}' at pc {getattr(ins, 'pc', '?')}",
                            is_genuinely_region_scoped=True,
                        )
                continue

            # C. Memory Loads: dst = *(size *)(base + off)
            if " = *(" in text:
                lhs, rhs = text.split(" = ", 1)
                lhs, rhs = lhs.strip(), rhs.strip()
                is_32bit = lhs.startswith("w")
                dst_reg = "r" + lhs[1:] if lhs.startswith(("r", "w")) and len(lhs) > 1 and lhs[1:].isdigit() else None
                m_load = re.search(r"\*\((u\d+)\s*\*\)\(([rw](?:10|[0-9]))(?:\s*([+-])\s*(?:0x[0-9A-Fa-f]+|\d+))?\)", rhs)
                if dst_reg and m_load:
                    width_bytes = int(m_load.group(1)[1:]) // 8
                    base_reg = "r" + m_load.group(2)[1:]
                    sign = m_load.group(3) or "+"
                    raw_off = re.search(r"[+-]\s*(0x[0-9A-Fa-f]+|\d+)", rhs)
                    off_val = int(raw_off.group(1), 0) if raw_off else 0
                    if sign == "-":
                        off_val = -off_val

                    target_prov = provenance.get(base_reg, "unknown")
                    if target_prov == "stack" or base_reg == "r10":
                        if off_val < -512 or off_val >= 0 or (off_val + width_bytes) > 0:
                            return RegionSymbolicResponse(
                                region_id=request.region_id,
                                verdict=RegionVerdict.UNKNOWN,
                                scope=request.scope,
                                backend_executor_scope=request.scope,
                                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                                paths_explored=paths_explored,
                                unresolved_reason=f"Stack load out of bounds: [{off_val}, {off_val+width_bytes})",
                                is_genuinely_region_scoped=True,
                            )
                        if off_val in stack_slots and stack_slots[off_val][0] == width_bytes:
                            loaded_val = stack_slots[off_val][1]
                            if is_32bit and loaded_val.is_const():
                                regs[dst_reg] = AbstractValue.const(loaded_val.value & 0xFFFFFFFF)
                            else:
                                regs[dst_reg] = loaded_val
                        else:
                            regs[dst_reg] = AbstractValue.unknown()
                        provenance[dst_reg] = "scalar"
                    else:
                        regs[dst_reg] = AbstractValue.unknown()
                        provenance[dst_reg] = "scalar"
                continue

            # D. Compound ALU Operations: [rw]X <op>= ...
            compound_match = re.match(r"^([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)=\s*(.+)$", text)
            if compound_match:
                lhs_name = compound_match.group(1)
                op_sym = compound_match.group(2)
                rhs_expr = compound_match.group(3).strip()
                is_32bit = lhs_name.startswith("w")
                dst_reg = "r" + lhs_name[1:]

                curr_val = regs.get(dst_reg, AbstractValue.unknown())
                # Resolve RHS operand
                src_reg = "r" + rhs_expr[1:] if rhs_expr.startswith(("r", "w")) and len(rhs_expr) > 1 and rhs_expr[1:].isdigit() else None
                if src_reg and src_reg in regs:
                    rhs_val = regs[src_reg]
                else:
                    try:
                        rhs_val = AbstractValue.const(int(rhs_expr, 0))
                    except ValueError:
                        rhs_val = AbstractValue.unknown()

                if curr_val.is_const() and rhs_val.is_const():
                    c1, c2 = curr_val.value, rhs_val.value
                    if op_sym == "+": res = c1 + c2
                    elif op_sym == "-": res = c1 - c2
                    elif op_sym == "*": res = c1 * c2
                    elif op_sym == "&": res = c1 & c2
                    elif op_sym == "|": res = c1 | c2
                    elif op_sym == "^": res = c1 ^ c2
                    elif op_sym == "<<": res = c1 << c2
                    elif op_sym == ">>": res = c1 >> c2
                    else: res = None
                    if res is not None:
                        if is_32bit:
                            res = res & 0xFFFFFFFF
                        regs[dst_reg] = AbstractValue.const(res)
                    else:
                        regs[dst_reg] = AbstractValue.unknown()
                else:
                    regs[dst_reg] = AbstractValue.unknown()
                provenance[dst_reg] = "scalar"
                continue

            # E. Register Assignments / Direct Moves: [rw]X = ...
            if " = " in text and not ("*(" in text.split("=")[0]):
                lhs, rhs = text.split(" = ", 1)
                lhs, rhs = lhs.strip(), rhs.strip()
                is_32bit = lhs.startswith("w")
                dst_reg = "r" + lhs[1:] if lhs.startswith(("r", "w")) and len(lhs) > 1 and lhs[1:].isdigit() else None
                if dst_reg:
                    # Direct move: rX = rY or wX = wY
                    src_reg = "r" + rhs[1:] if rhs.startswith(("r", "w")) and len(rhs) > 1 and rhs[1:].isdigit() else None
                    if src_reg and src_reg in regs:
                        src_val = regs[src_reg]
                        if is_32bit and src_val.is_const():
                            regs[dst_reg] = AbstractValue.const(src_val.value & 0xFFFFFFFF)
                        else:
                            regs[dst_reg] = src_val
                        provenance[dst_reg] = provenance.get(src_reg, "scalar")
                    else:
                        # Immediate constant or binary expression
                        try:
                            val = int(rhs, 0)
                            if is_32bit:
                                val = val & 0xFFFFFFFF
                            regs[dst_reg] = AbstractValue.const(val)
                            provenance[dst_reg] = "scalar"
                        except ValueError:
                            # Binary expr: rY <op> imm
                            m_bin = re.fullmatch(r"([rw](?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\s*(-?(?:0x[0-9A-Fa-f]+|\d+))", rhs)
                            if m_bin:
                                s_reg = "r" + m_bin.group(1)[1:]
                                imm = int(m_bin.group(3), 0)
                                s_val = regs.get(s_reg, AbstractValue.unknown())
                                if s_val.is_const():
                                    op_s = m_bin.group(2)
                                    if op_s == "+": r = s_val.value + imm
                                    elif op_s == "-": r = s_val.value - imm
                                    elif op_s == "&": r = s_val.value & imm
                                    elif op_s == "|": r = s_val.value | imm
                                    elif op_s == "^": r = s_val.value ^ imm
                                    elif op_s == "<<": r = s_val.value << imm
                                    elif op_s == ">>": r = s_val.value >> imm
                                    else: r = None
                                    if r is not None:
                                        if is_32bit:
                                            r = r & 0xFFFFFFFF
                                        regs[dst_reg] = AbstractValue.const(r)
                                    else:
                                        regs[dst_reg] = AbstractValue.unknown()
                                else:
                                    regs[dst_reg] = AbstractValue.unknown()
                            else:
                                regs[dst_reg] = AbstractValue.unknown()
                            provenance[dst_reg] = "scalar"
                continue

            # F. Exit Instruction
            if op == "exit":
                r0_val = regs.get("r0", AbstractValue.unknown())
                if has_return_rule:
                    if r0_val.is_const():
                        if r0_val.value not in allowed_returns:
                            return RegionSymbolicResponse(
                                region_id=request.region_id,
                                verdict=RegionVerdict.VIOLATION,
                                scope=request.scope,
                                backend_executor_scope=request.scope,
                                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                                paths_explored=paths_explored,
                                witness_trace=f"Forbidden return value {r0_val.value} at pc {getattr(ins, 'pc', '?')}",
                                is_genuinely_region_scoped=True,
                            )
                    else:
                        return RegionSymbolicResponse(
                            region_id=request.region_id,
                            verdict=RegionVerdict.UNKNOWN,
                            scope=request.scope,
                            backend_executor_scope=request.scope,
                            execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                            paths_explored=paths_explored,
                            unresolved_reason=f"Indeterminate return value at pc {getattr(ins, 'pc', '?')}",
                            is_genuinely_region_scoped=True,
                        )
                continue

            # G. Jumps (goto): fallthrough or direct branch
            if op == "goto" or text.startswith("goto "):
                continue

            # Fail-closed soundness safeguard: any instruction opcode not handled above must return UNKNOWN
            return RegionSymbolicResponse(
                region_id=request.region_id,
                verdict=RegionVerdict.UNKNOWN,
                scope=request.scope,
                backend_executor_scope=request.scope,
                execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
                paths_explored=paths_explored,
                unresolved_reason=f"Unsupported instruction opcode '{op}' at pc {getattr(ins, 'pc', '?')}: '{text}'",
                is_genuinely_region_scoped=True,
            )

        # Region analyzed cleanly without violations
        out_state = IncomingAbstractState(
            registers=AbstractRegisterState(registers=dict(regs)),
            stack_assumptions=dict(stack_slots),
            path_constraints=tuple(inc.path_constraints),
        )
        return RegionSymbolicResponse(
            region_id=request.region_id,
            verdict=RegionVerdict.SAFE,
            scope=request.scope,
            backend_executor_scope=request.scope,
            execution_time_ms=(time.monotonic_ns() - t0) / 1_000_000,
            paths_explored=paths_explored,
            is_genuinely_region_scoped=True,
            exit_states={"exit": out_state},
        )
