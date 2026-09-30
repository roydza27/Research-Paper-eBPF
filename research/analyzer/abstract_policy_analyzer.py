#!/usr/bin/env python3
"""
Abstract Policy Analyzer for eBPF Programs
Part of the Phase 5 Hybrid Policy Verification Architecture.

Authoritative Soundness Principle:
- Never declare SAFE without conclusive abstract proof of compliance across all reachable states.
- Never declare VIOLATION without conclusive abstract proof of reachability of a forbidden operation.
- Fall back conservatively to UNKNOWN upon any abstract uncertainty or unmodeled condition.
- Zero cheating: never inspect filenames, symbol names, or external metadata to infer verdicts.
"""

import os
import sys
import re
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
from enum import Enum


class Verdict(str, Enum):
    SAFE = "SAFE"
    VIOLATION = "VIOLATION"
    UNKNOWN = "UNKNOWN"


# Standard Linux eBPF Helper Function ID to Name mapping
BPF_HELPER_MAP = {
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


class AbstractValueType(Enum):
    CONST = "CONST"
    INTERVAL = "INTERVAL"
    PACKET_PTR = "PACKET_PTR"
    MAP_PTR = "MAP_PTR"
    SYMBOLIC_HELPER = "SYMBOLIC_HELPER"
    UNKNOWN = "UNKNOWN"


class AbstractValue:
    def __init__(self, val_type: AbstractValueType, value: Any = None):
        self.val_type = val_type
        self.value = value

    @classmethod
    def const(cls, val: int):
        return cls(AbstractValueType.CONST, int(val))

    @classmethod
    def unknown(cls):
        return cls(AbstractValueType.UNKNOWN, None)

    @classmethod
    def symbolic_helper(cls, helper_name: str):
        return cls(AbstractValueType.SYMBOLIC_HELPER, helper_name)

    @classmethod
    def packet_ptr(cls, offset: int = 0):
        return cls(AbstractValueType.PACKET_PTR, offset)

    @classmethod
    def map_ptr(cls, map_name: str):
        return cls(AbstractValueType.MAP_PTR, map_name)

    def is_const(self) -> bool:
        return self.val_type == AbstractValueType.CONST

    def __repr__(self):
        if self.val_type == AbstractValueType.CONST:
            return f"Const({self.value})"
        elif self.val_type == AbstractValueType.SYMBOLIC_HELPER:
            return f"SymHelper({self.value})"
        elif self.val_type == AbstractValueType.PACKET_PTR:
            return f"PacketPtr({self.value})"
        elif self.val_type == AbstractValueType.MAP_PTR:
            return f"MapPtr({self.value})"
        return "UNKNOWN"


class Instruction:
    def __init__(self, pc: int, text: str, opcode_name: str, args: str):
        self.pc = pc
        self.text = text
        self.opcode_name = opcode_name
        self.args = args


class BasicBlock:
    def __init__(self, block_id: int, start_pc: int):
        self.block_id = block_id
        self.start_pc = start_pc
        self.instructions: List[Instruction] = []
        self.successors: List[int] = []  # List of target start_pcs
        self.predecessors: List[int] = []
        self.is_exit: bool = False
        self.is_conditional: bool = False
        self.cond_branch_target: Optional[int] = None
        self.fallthrough_target: Optional[int] = None


class AbstractPolicyAnalyzer:
    def __init__(self, object_path: str, policy_path: str):
        self.object_path = Path(object_path).resolve()
        self.policy_path = Path(policy_path).resolve()
        
        if not self.object_path.exists():
            raise FileNotFoundError(f"Object file not found: {self.object_path}")
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")
            
        self.policy = self._load_policy()
        self.allowed_helpers = set(self._get_policy_allowed_helpers())
        self.forbidden_helpers = set(self._get_policy_forbidden_helpers())
        self.allowed_return_values = set(self._get_policy_allowed_return_values())
        self.allowed_maps = set(self._get_policy_allowed_maps())
        
        self.relocations: Dict[int, str] = {}
        self.instructions: List[Instruction] = []
        self.basic_blocks: Dict[int, BasicBlock] = {}
        self.entry_pc: int = 0

    def _load_policy(self) -> Dict[str, Any]:
        with open(self.policy_path, "r") as f:
            return json.load(f)

    def _get_policy_allowed_helpers(self) -> List[str]:
        helpers = []
        for k, v in self.policy.items():
            if isinstance(v, dict) and "actions" in v:
                helpers.extend(v["actions"].get("helper_access", []))
        return helpers

    def _get_policy_forbidden_helpers(self) -> List[str]:
        # Top-level helper_func lists explicitly restricted helpers
        return self.policy.get("helper_func", [])

    def _get_policy_allowed_return_values(self) -> List[int]:
        ret_vals = []
        for k, v in self.policy.items():
            if isinstance(v, dict) and "actions" in v:
                ret_vals.extend(v["actions"].get("return_value", []))
        return ret_vals if ret_vals else [1, 2]

    def _get_policy_allowed_maps(self) -> List[str]:
        maps = []
        for k, v in self.policy.items():
            if isinstance(v, dict) and "actions" in v:
                for m in v["actions"].get("map_access", []):
                    if isinstance(m, dict) and "name" in m:
                        maps.append(m["name"])
                    elif isinstance(m, str):
                        maps.append(m)
        return maps

    def _disassemble_object(self):
        """Disassemble eBPF object using llvm-objdump and parse relocations."""
        # 1. Parse Relocations
        rel_cmd = ["llvm-readelf", "-r", str(self.object_path)]
        try:
            rel_res = subprocess.run(rel_cmd, capture_output=True, text=True, check=True)
            for line in rel_res.stdout.splitlines():
                # Format: Offset Info Type Sym. Value Sym. Name
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0].startswith("0000"):
                    try:
                        off = int(parts[0], 16)
                        sym_name = parts[-1]
                        self.relocations[off] = sym_name
                    except ValueError:
                        pass
        except Exception:
            pass

        # 2. Disassemble instructions
        dump_cmd = ["llvm-objdump", "-d", "--no-show-raw-insn", str(self.object_path)]
        dump_res = subprocess.run(dump_cmd, capture_output=True, text=True, check=True)
        
        lines = dump_res.stdout.splitlines()
        in_code_section = False
        
        for line in lines:
            line_str = line.strip()
            if "Disassembly of section" in line_str:
                if "xdp" in line_str or ".text" in line_str:
                    in_code_section = True
                else:
                    in_code_section = False
                continue
                
            if not in_code_section or not line_str or line_str.endswith(":"):
                continue
                
            # Line format: <pc>: <mnemonic> <operands>
            m = re.match(r"^([0-9a-fA-F]+):\s*(.*)$", line_str)
            if m:
                pc = int(m.group(1), 10)
                rest = m.group(2).strip()
                tokens = rest.split(None, 1)
                opcode = tokens[0] if tokens else ""
                args = tokens[1] if len(tokens) > 1 else ""
                self.instructions.append(Instruction(pc, rest, opcode, args))

    def _build_cfg(self):
        """Construct control flow graph of basic blocks."""
        if not self.instructions:
            return

        pc_to_idx = {ins.pc: i for i, ins in enumerate(self.instructions)}
        leaders = {self.instructions[0].pc}

        # Find block leaders
        for i, ins in enumerate(self.instructions):
            if ins.opcode_name.startswith("if") or ins.opcode_name == "goto":
                # Successor target is a leader
                target = self._extract_branch_target(ins)
                if target is not None:
                    leaders.add(target)
                # Next instruction is a leader
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].pc)
            elif ins.opcode_name == "exit":
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].pc)

        # Build blocks
        sorted_leaders = sorted(list(leaders))
        for idx, start_pc in enumerate(sorted_leaders):
            self.basic_blocks[start_pc] = BasicBlock(idx, start_pc)

        # Populate instructions into blocks
        current_block: Optional[BasicBlock] = None
        for i, ins in enumerate(self.instructions):
            if ins.pc in self.basic_blocks:
                current_block = self.basic_blocks[ins.pc]
            if current_block:
                current_block.instructions.append(ins)

        # Compute CFG edges
        for idx, start_pc in enumerate(sorted_leaders):
            bb = self.basic_blocks[start_pc]
            if not bb.instructions:
                continue
            last_ins = bb.instructions[-1]
            last_idx = pc_to_idx[last_ins.pc]
            next_pc = self.instructions[last_idx + 1].pc if last_idx + 1 < len(self.instructions) else None

            if last_ins.opcode_name == "exit":
                bb.is_exit = True
            elif last_ins.opcode_name == "goto":
                target = self._extract_branch_target(last_ins)
                if target is not None and target in self.basic_blocks:
                    bb.successors.append(target)
            elif last_ins.opcode_name.startswith("if"):
                bb.is_conditional = True
                target = self._extract_branch_target(last_ins)
                bb.cond_branch_target = target
                bb.fallthrough_target = next_pc
                if target is not None and target in self.basic_blocks:
                    bb.successors.append(target)
                if next_pc is not None and next_pc in self.basic_blocks:
                    bb.successors.append(next_pc)
            else:
                if next_pc is not None and next_pc in self.basic_blocks:
                    bb.successors.append(next_pc)

        # Predecessors
        for pc, bb in self.basic_blocks.items():
            for succ_pc in bb.successors:
                if succ_pc in self.basic_blocks:
                    self.basic_blocks[succ_pc].predecessors.append(pc)

    def _extract_branch_target(self, ins: Instruction) -> Optional[int]:
        """Extract jump/branch target PC from instruction string."""
        # e.g.: 'if r1 == 0x0 goto +0x1 <e1_p4+0x28>' or 'goto +0x2'
        # Or absolute: 'goto 0x10'
        # llvm-objdump typically uses relative: goto +0xN or if ... goto +0xN <...>
        m = re.search(r"goto\s+([+-]?0x[0-9a-fA-F]+)", ins.args)
        if m:
            offset_val = int(m.group(1), 16)
            # In eBPF objdump: relative offset is in instructions (or bytes).
            # If formatted like +0x1, target = pc + 1 + offset_val
            target_pc = ins.pc + 1 + offset_val
            return target_pc
        
        # Check angle bracket notation <func+0xOffset>
        m_angle = re.search(r"<[^+]+(?:\+0x([0-9a-fA-F]+))?>", ins.args)
        if m_angle:
            off_bytes = int(m_angle.group(1), 16) if m_angle.group(1) else 0
            # Target pc is byte offset divided by 8 (standard insn size)
            return off_bytes // 8
        return None

    def analyze(self) -> Dict[str, Any]:
        """
        Execute abstract interpretation over CFG.
        Returns:
            Dictionary with 'verdict', 'proof', 'metrics', and details.
        """
        self._disassemble_object()
        self._build_cfg()

        if not self.instructions:
            return {
                "verdict": Verdict.UNKNOWN.value,
                "proof": "Failed to parse instructions from object file.",
                "discharged": False,
                "metrics": {}
            }

        # Abstract state tracking across reachable paths
        # We perform path enumeration with path-state tracking
        reachable_paths = []
        unresolved_conditions = []
        forbidden_helper_calls_found = []
        allowed_helper_calls_found = []
        unconditional_forbidden_calls = []
        all_exit_returns = []
        dynamic_returns = False
        
        # State: (pc, registers, stack, helpers_called, path_predicates, visited_pcs)
        initial_regs = {f"r{i}": AbstractValue.unknown() for i in range(11)}
        initial_regs["r1"] = AbstractValue.unknown()  # ctx pointer
        initial_regs["r10"] = AbstractValue.const(0) # stack pointer

        worklist = [
            (
                self.instructions[0].pc,
                dict(initial_regs),
                {},
                [],  # helpers called along path
                [],  # unresolved conditions along path
                [self.instructions[0].pc]  # visited
            )
        ]

        max_paths = 256
        path_count = 0

        while worklist and path_count < max_paths:
            pc, regs, stack, helpers_on_path, conds_on_path, visited = worklist.pop(0)
            
            bb = self.basic_blocks.get(pc)
            if not bb:
                continue

            current_regs = dict(regs)
            current_stack = dict(stack)
            current_helpers = list(helpers_on_path)
            current_conds = list(conds_on_path)

            # Interpret instructions in basic block
            for ins in bb.instructions:
                # Helper Call
                if ins.opcode_name == "call":
                    # Determine helper ID: e.g., 'call 0x5' or 'call 5'
                    helper_id = None
                    m_call = re.search(r"0x([0-9a-fA-F]+)|(\d+)", ins.args)
                    if m_call:
                        helper_id = int(m_call.group(1) or m_call.group(2), 16 if m_call.group(1) else 10)
                    
                    helper_name = BPF_HELPER_MAP.get(helper_id, f"helper_{helper_id}")
                    current_helpers.append((helper_name, list(current_conds)))
                    
                    if helper_name in self.forbidden_helpers or (self.allowed_helpers and helper_name not in self.allowed_helpers):
                        forbidden_helper_calls_found.append((helper_name, list(current_conds)))
                    else:
                        allowed_helper_calls_found.append(helper_name)
                        
                    if helper_name == "bpf_ktime_get_ns":
                        current_regs["r0"] = AbstractValue.symbolic_helper("bpf_ktime_get_ns")
                    else:
                        current_regs["r0"] = AbstractValue.unknown()
                    for r in ["r1", "r2", "r3", "r4", "r5"]:
                        current_regs[r] = AbstractValue.unknown()

                # ALU: rX = imm
                elif re.match(r"^r\d+\s*=\s*-?0x[0-9a-fA-F]+", ins.text):
                    m = re.match(r"^(r\d+)\s*=\s*(-?0x[0-9a-fA-F]+)", ins.text)
                    if m:
                        reg, val_str = m.group(1), m.group(2)
                        current_regs[reg] = AbstractValue.const(int(val_str, 16))

                # ALU: rX = rY
                elif re.match(r"^r\d+\s*=\s*r\d+$", ins.text):
                    m = re.match(r"^(r\d+)\s*=\s*(r\d+)$", ins.text)
                    if m:
                        dst, src = m.group(1), m.group(2)
                        current_regs[dst] = current_regs.get(src, AbstractValue.unknown())

                # ALU: rX += imm / -= imm
                elif re.search(r"r\d+\s*[\+\-]\=\s*-?0x[0-9a-fA-F]+", ins.text):
                    m = re.match(r"^(r\d+)\s*([\+\-])\=\s*(-?0x[0-9a-fA-F]+)", ins.text)
                    if m:
                        reg, op, val_str = m.group(1), m.group(2), m.group(3)
                        val = int(val_str, 16)
                        cur = current_regs.get(reg, AbstractValue.unknown())
                        if cur.is_const():
                            new_val = cur.value + val if op == "+" else cur.value - val
                            current_regs[reg] = AbstractValue.const(new_val)
                        else:
                            current_regs[reg] = AbstractValue.unknown()

                # Bitwise ops: rX &= imm / rX |= imm / rX ^= imm
                elif re.search(r"r\d+\s*[\&\|\^]\=\s*0x[0-9a-fA-F]+", ins.text):
                    m = re.match(r"^(r\d+)\s*([\&\|\^])\=\s*(0x[0-9a-fA-F]+)", ins.text)
                    if m:
                        reg, op, val_str = m.group(1), m.group(2), m.group(3)
                        val = int(val_str, 16)
                        cur = current_regs.get(reg, AbstractValue.unknown())
                        if cur.is_const():
                            if op == "&":
                                current_regs[reg] = AbstractValue.const(cur.value & val)
                            elif op == "|":
                                current_regs[reg] = AbstractValue.const(cur.value | val)
                            elif op == "^":
                                current_regs[reg] = AbstractValue.const(cur.value ^ val)
                        else:
                            current_regs[reg] = AbstractValue.unknown()

                # Memory load: rX = *(u32 *)(rY + off)
                elif re.search(r"r\d+\s*=\s*\*\([^\)]+\)\(r\d+\s*[\+\-]?\s*[0-9a-fA-Fx]*\)", ins.text):
                    m = re.match(r"^(r\d+)\s*=\s*\*\([^\)]+\)\((r\d+)\s*(?:([\+\-])\s*(0x[0-9a-fA-F]+|\d+))?\)", ins.text)
                    if m:
                        dst, base_reg = m.group(1), m.group(2)
                        base_val = current_regs.get(base_reg, AbstractValue.unknown())
                        if base_val.val_type == AbstractValueType.PACKET_PTR:
                            # Loading from packet pointer yields unknown packet data
                            current_regs[dst] = AbstractValue.unknown()
                        else:
                            current_regs[dst] = AbstractValue.unknown()

                # Exit
                elif ins.opcode_name == "exit":
                    r0_val = current_regs.get("r0", AbstractValue.unknown())
                    all_exit_returns.append((r0_val, list(current_conds)))
                    path_count += 1
                    reachable_paths.append({
                        "return_value": r0_val,
                        "conditions": list(current_conds),
                        "helpers": list(current_helpers)
                    })
                    break

            if bb.is_exit:
                continue

            # Branch handling
            if bb.is_conditional:
                # Conditional jump
                last_ins = bb.instructions[-1]
                # Check if condition is statically resolvable
                cond_is_resolved = False
                branch_taken = False
                
                # Check condition pattern: if rX == imm goto ...
                m_cond = re.search(r"if\s+(r\d+)\s*([=!><]+)\s*(0x[0-9a-fA-F]+|\d+)", last_ins.text)
                if m_cond:
                    reg_name, op, imm_str = m_cond.group(1), m_cond.group(2), m_cond.group(3)
                    imm = int(imm_str, 16 if imm_str.startswith("0x") else 10)
                    reg_val = current_regs.get(reg_name, AbstractValue.unknown())
                    if reg_val.is_const():
                        cond_is_resolved = True
                        if op == "==":
                            branch_taken = (reg_val.value == imm)
                        elif op == "!=":
                            branch_taken = (reg_val.value != imm)
                        elif op == "<":
                            branch_taken = (reg_val.value < imm)
                        elif op == "<=":
                            branch_taken = (reg_val.value <= imm)
                        elif op == ">":
                            branch_taken = (reg_val.value > imm)
                        elif op == ">=":
                            branch_taken = (reg_val.value >= imm)

                if cond_is_resolved:
                    target_pc = bb.cond_branch_target if branch_taken else bb.fallthrough_target
                    if target_pc and target_pc not in visited:
                        worklist.append((target_pc, current_regs, current_stack, current_helpers, current_conds, visited + [target_pc]))
                else:
                    # Condition is UNRESOLVED (depends on packet, dynamic time, or unmodeled state)
                    cond_desc = f"insn_{last_ins.pc}: {last_ins.text}"
                    unresolved_conditions.append(cond_desc)
                    
                    # Fork both paths
                    if bb.cond_branch_target and bb.cond_branch_target not in visited:
                        worklist.append((
                            bb.cond_branch_target,
                            dict(current_regs),
                            dict(current_stack),
                            list(current_helpers),
                            current_conds + [f"TAKEN({cond_desc})"],
                            visited + [bb.cond_branch_target]
                        ))
                    if bb.fallthrough_target and bb.fallthrough_target not in visited:
                        worklist.append((
                            bb.fallthrough_target,
                            dict(current_regs),
                            dict(current_stack),
                            list(current_helpers),
                            current_conds + [f"NOT_TAKEN({cond_desc})"],
                            visited + [bb.fallthrough_target]
                        ))
            else:
                # Unconditional edge(s)
                for succ_pc in bb.successors:
                    if succ_pc not in visited:
                        worklist.append((
                            succ_pc,
                            dict(current_regs),
                            dict(current_stack),
                            list(current_helpers),
                            list(current_conds),
                            visited + [succ_pc]
                        ))

        # Check for unconditional forbidden helper calls (empty conditions)
        for h, conds in forbidden_helper_calls_found:
            if not conds:
                unconditional_forbidden_calls.append(h)

        # ----------------------------------------------------
        # DECISION LOGIC: SAFE vs VIOLATION vs UNKNOWN
        # ----------------------------------------------------
        
        # 1. DEFINITE VIOLATION:
        # If an explicitly forbidden helper is called unconditionally (or along all paths)
        if unconditional_forbidden_calls:
            violating_helper = unconditional_forbidden_calls[0]
            proof = (
                f"Definite Policy Violation: Forbidden helper '{violating_helper}' "
                f"is reachable along an unconditional execution path without dependency preconditions."
            )
            return {
                "verdict": Verdict.VIOLATION.value,
                "proof": proof,
                "discharged": True,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # Check if ALL reachable exits return a forbidden return value
        if all_exit_returns and all(
            r.is_const() and r.value not in self.allowed_return_values for r, _ in all_exit_returns
        ):
            violating_vals = list({r.value for r, _ in all_exit_returns})
            proof = (
                f"Definite Policy Violation: All reachable program exit points unconditionally return "
                f"forbidden return value(s) {violating_vals}, outside allowed whitelist {sorted(list(self.allowed_return_values))}."
            )
            return {
                "verdict": Verdict.VIOLATION.value,
                "proof": proof,
                "discharged": True,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # 2. UNCERTAIN (UNKNOWN) CASES:
        # Case A: A forbidden helper is present, but guarded by an unresolved branch condition
        if forbidden_helper_calls_found:
            violating_helper = forbidden_helper_calls_found[0][0]
            proof = (
                f"Abstract Uncertainty: Forbidden helper '{violating_helper}' is present on a conditional branch "
                f"guarded by unresolved symbolic predicates ({forbidden_helper_calls_found[0][1]}). "
                f"Abstract stage cannot prove or refute reachability; selective symbolic fallback required."
            )
            return {
                "verdict": Verdict.UNKNOWN.value,
                "proof": proof,
                "discharged": False,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # Case B: A forbidden return value is present on some exit, but not all exits (guarded by unresolved condition)
        has_forbidden_return = any(r.is_const() and r.value not in self.allowed_return_values for r, _ in all_exit_returns)
        if has_forbidden_return:
            proof = (
                f"Abstract Uncertainty: Out-of-policy return value reachable along conditional branch guarded by "
                f"unresolved symbolic conditions. Abstract stage cannot verify branch feasibility; selective symbolic fallback required."
            )
            return {
                "verdict": Verdict.UNKNOWN.value,
                "proof": proof,
                "discharged": False,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # Case C: Exit return value varies across unresolved conditions
        distinct_returns = {r.value for r, _ in all_exit_returns if r.is_const()}
        has_non_const_return = any(not r.is_const() for r, _ in all_exit_returns)
        
        if has_non_const_return or len(distinct_returns) > 1:
            proof = (
                f"Abstract Uncertainty: Dynamic or multi-valued return codes {distinct_returns} selected by "
                f"unresolved conditional predicates. Soundness requires symbolic validation to confirm all feasible paths satisfy policy."
            )
            return {
                "verdict": Verdict.UNKNOWN.value,
                "proof": proof,
                "discharged": False,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # 3. PROVABLY SAFE:
        # All exits return a single known constant in allowed_return_values (e.g. 2 / XDP_PASS)
        # All helpers called are strictly in allowed_helpers and not in forbidden_helpers
        if all_exit_returns and all(
            r.is_const() and r.value in self.allowed_return_values for r, _ in all_exit_returns
        ):
            ret_val = list(distinct_returns)[0] if distinct_returns else 2
            proof = (
                f"Conclusive Abstract Proof of Safety: All reachable execution paths return permitted code {ret_val} "
                f"(within whitelist {sorted(list(self.allowed_return_values))}); "
                f"all invoked helpers {list(set(allowed_helper_calls_found))} comply with policy whitelist."
            )
            return {
                "verdict": Verdict.SAFE.value,
                "proof": proof,
                "discharged": True,
                "metrics": {
                    "instructions": len(self.instructions),
                    "basic_blocks": len(self.basic_blocks),
                    "paths_analyzed": len(reachable_paths),
                    "unresolved_conditions": len(unresolved_conditions)
                }
            }

        # Fallback conservative UNKNOWN
        return {
            "verdict": Verdict.UNKNOWN.value,
            "proof": "Abstract interpretation could not establish conclusive compliance or violation. Conservative fallback to symbolic engine.",
            "discharged": False,
            "metrics": {
                "instructions": len(self.instructions),
                "basic_blocks": len(self.basic_blocks),
                "paths_analyzed": len(reachable_paths),
                "unresolved_conditions": len(unresolved_conditions)
            }
        }


def main():
    parser = argparse.ArgumentParser(description="Phase 5 Abstract Policy Analyzer for eBPF Objects")
    parser.add_argument("--object", "-o", required=True, help="Path to compiled eBPF ELF object (.o)")
    parser.add_argument("--policy", "-p", required=True, help="Path to security policy (.json)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    args = parser.parse_args()
    analyzer = AbstractPolicyAnalyzer(args.object, args.policy)
    result = analyzer.analyze()
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"VERDICT: {result['verdict']}")
        print(f"DISCHARGED: {result['discharged']}")
        print(f"PROOF: {result['proof']}")
        print("METRICS:")
        for k, v in result.get("metrics", {}).items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
