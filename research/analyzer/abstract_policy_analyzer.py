#!/usr/bin/env python3
"""Conservative Phase 5 abstract policy analyzer.

Soundness boundary:
- SAFE only when every reachable abstract path is proven compliant.
- VIOLATION only when every reachable terminal path is proven violating,
  or a forbidden action is proven unconditionally reachable.
- Unsupported/insufficiently modeled behavior is UNKNOWN.
- The analyzer never consults corpus labels, filenames, or expected results.
"""
import json, re, subprocess
from pathlib import Path
from enum import Enum
from typing import Any, Dict, List, Optional

class Verdict(str, Enum):
    SAFE = "SAFE"
    VIOLATION = "VIOLATION"
    UNKNOWN = "UNKNOWN"

BPF_HELPER_MAP = {
    1:"bpf_map_lookup_elem",2:"bpf_map_update_elem",3:"bpf_map_delete_elem",
    4:"bpf_probe_read",5:"bpf_ktime_get_ns",6:"bpf_trace_printk",
    7:"bpf_get_prandom_u32",8:"bpf_get_smp_processor_id",9:"bpf_skb_store_bytes",
    10:"bpf_l3_csum_replace",11:"bpf_l4_csum_replace",12:"bpf_tail_call",
    13:"bpf_clone_redirect",14:"bpf_get_current_pid_tgid",15:"bpf_get_current_uid_gid",
    16:"bpf_get_current_comm",25:"bpf_perf_event_output",26:"bpf_redirect",
    43:"bpf_xdp_adjust_head",51:"bpf_redirect_map",
}

class AbstractValue:
    def __init__(self, kind="unknown", value=None): self.kind,self.value=kind,value
    @classmethod
    def const(cls,v): return cls("const",int(v))
    @classmethod
    def symbolic(cls,name="symbolic"): return cls("symbolic",name)
    @classmethod
    def unknown(cls): return cls("unknown")
    def is_const(self): return self.kind=="const"

class Instruction:
    def __init__(self,pc:int,text:str,opcode_name:str,args:str):
        self.pc,self.text,self.opcode_name,self.args=pc,text,opcode_name,args

class BasicBlock:
    def __init__(self,start_pc:int):
        self.start_pc=start_pc; self.instructions=[]; self.successors=[]
        self.cond_target=None; self.fallthrough=None; self.is_exit=False

class AbstractPolicyAnalyzer:
    def __init__(self,object_path:str,policy_path:str):
        self.object_path=Path(object_path).resolve()
        self.policy_path=Path(policy_path).resolve()
        if not self.object_path.exists(): raise FileNotFoundError(self.object_path)
        if not self.policy_path.exists(): raise FileNotFoundError(self.policy_path)
        with open(self.policy_path) as f: self.policy=json.load(f)
        self.allowed_helpers=self._allowed_helpers()
        self.forbidden_helpers=set(self.policy.get("helper_func",[]))
        self.allowed_returns=self._allowed_returns()
        self.allowed_maps=self._allowed_maps()
        self.instructions=[]; self.basic_blocks={}; self.relocations={}

    def _allowed_helpers(self):
        out=[]
        for v in self.policy.values():
            if isinstance(v,dict) and isinstance(v.get("actions"),dict):
                out += v["actions"].get("helper_access",[])
        return set(out)

    def _allowed_returns(self):
        out=[]
        for v in self.policy.values():
            if isinstance(v,dict) and isinstance(v.get("actions"),dict):
                out += v["actions"].get("return_value",[])
        return set(out or [1,2])

    def _allowed_maps(self):
        out=[]
        for v in self.policy.values():
            if isinstance(v,dict) and isinstance(v.get("actions"),dict):
                for m in v["actions"].get("map_access",[]):
                    out.append(m.get("name") if isinstance(m,dict) else m)
        return {x for x in out if x}

    def _memory_policy_constrained(self):
        for v in self.policy.values():
            if isinstance(v,dict):
                deps=v.get("dependencies")
                if isinstance(deps,dict) and deps.get("memory"):
                    return True
                actions=v.get("actions")
                if isinstance(actions,dict) and actions.get("memory_access"):
                    return True
        return False

    def _disassemble_object(self):
        rel=subprocess.run(["llvm-readelf","-r",str(self.object_path)],capture_output=True,text=True)
        if rel.returncode!=0: raise RuntimeError("failed to read ELF relocations")
        for line in rel.stdout.splitlines():
            parts=line.strip().split()
            if len(parts)>=5 and re.fullmatch(r"[0-9A-Fa-f]+",parts[0]):
                try: self.relocations[int(parts[0],16)]=parts[-1]
                except ValueError as e: raise RuntimeError("invalid relocation offset") from e

        dump=subprocess.run(["llvm-objdump","-d","--no-show-raw-insn",str(self.object_path)],capture_output=True,text=True)
        if dump.returncode!=0: raise RuntimeError("failed to disassemble object")
        active=False
        for line in dump.stdout.splitlines():
            s=line.strip()
            if "Disassembly of section" in s:
                active=("xdp" in s or ".text" in s); continue
            if not active or not s or s.endswith(":"): continue
            m=re.match(r"^([0-9A-Fa-f]+):\s*(.*)$",s)
            if not m: raise RuntimeError(f"unparsed disassembly line: {s}")
            pc=int(m.group(1),16); rest=m.group(2).strip(); toks=rest.split(None,1)
            self.instructions.append(Instruction(pc,rest,toks[0] if toks else "",toks[1] if len(toks)>1 else ""))
        if not self.instructions: raise RuntimeError("no executable instructions parsed")

    def _branch_target(self,ins):
        m=re.search(r"goto\s+([+-]?0x[0-9A-Fa-f]+)",ins.args)
        if not m: return None
        return ins.pc+1+int(m.group(1),16)

    def _build_cfg(self):
        pcs=[x.pc for x in self.instructions]; leaders={pcs[0]}; idx={p:i for i,p in enumerate(pcs)}
        for i,ins in enumerate(self.instructions):
            if ins.opcode_name.startswith("if") or ins.opcode_name=="goto":
                t=self._branch_target(ins)
                if t is not None: leaders.add(t)
                if i+1<len(self.instructions): leaders.add(self.instructions[i+1].pc)
            elif ins.opcode_name=="exit" and i+1<len(self.instructions):
                leaders.add(self.instructions[i+1].pc)
        for p in sorted(leaders): self.basic_blocks[p]=BasicBlock(p)
        cur=None
        for ins in self.instructions:
            if ins.pc in self.basic_blocks: cur=self.basic_blocks[ins.pc]
            if cur: cur.instructions.append(ins)
        for p,bb in self.basic_blocks.items():
            if not bb.instructions: continue
            last=bb.instructions[-1]; i=idx[last.pc]
            nxt=self.instructions[i+1].pc if i+1<len(self.instructions) else None
            if last.opcode_name=="exit": bb.is_exit=True
            elif last.opcode_name=="goto":
                t=self._branch_target(last)
                if t not in self.basic_blocks: raise RuntimeError(f"branch target {t} missing")
                bb.successors=[t]
            elif last.opcode_name.startswith("if"):
                t=self._branch_target(last)
                if t not in self.basic_blocks or nxt not in self.basic_blocks:
                    raise RuntimeError("incomplete conditional CFG")
                bb.cond_target=t; bb.fallthrough=nxt; bb.successors=[t,nxt]
            elif nxt is not None:
                if nxt not in self.basic_blocks: raise RuntimeError("invalid fallthrough CFG")
                bb.successors=[nxt]

    @staticmethod
    def _imm(text):
        m=re.search(r"(-?0x[0-9A-Fa-f]+|-?\d+)",text)
        if not m: return None
        return int(m.group(1),16 if "0x" in m.group(1).lower() else 10)

    def _eval_binary(self,dst,op,rhs,regs):
        cur=regs.get(dst,AbstractValue.unknown())
        if not cur.is_const() or not rhs.is_const():
            regs[dst]=AbstractValue.unknown(); return
        x,y=cur.value,rhs.value
        try:
            vals={"+":x+y,"-":x-y,"*":x*y,"&":x&y,"|":x|y,"^":x^y,"<<":x<<y,">>":x>>y}
            regs[dst]=AbstractValue.const(vals[op]) if op in vals else AbstractValue.unknown()
        except Exception:
            regs[dst]=AbstractValue.unknown()

    def _semantics(self,ins,regs,unknowns,path_helpers):
        op=ins.opcode_name
        if op=="call":
            hid=self._imm(ins.args)
            if hid is None or hid not in BPF_HELPER_MAP:
                unknowns.append(f"unknown helper id at {ins.pc}")
                regs["r0"]=AbstractValue.unknown()
                return "UNKNOWN"
            name=BPF_HELPER_MAP[hid]; path_helpers.append(name)
            if name in self.forbidden_helpers: return "VIOLATION"
            if self.allowed_helpers and name not in self.allowed_helpers: return "VIOLATION"

            # Map semantics are policy-sensitive. Do not silently treat an
            # allowed helper as an allowed map operation.
            if name in {"bpf_map_lookup_elem","bpf_map_update_elem","bpf_map_delete_elem","bpf_redirect_map"}:
                map_name = self.relocations.get(ins.pc * 8) or self.relocations.get(ins.pc)
                if not map_name:
                    unknowns.append(f"unresolved map identity for {name} at {ins.pc}")
                    return "UNKNOWN"
                if map_name not in self.allowed_maps:
                    return "VIOLATION"
                if name != "bpf_map_lookup_elem":
                    unknowns.append(f"map write/redirect semantics not supported for {map_name} at {ins.pc}")
                    return "UNKNOWN"

            regs["r0"]=AbstractValue.symbolic(name)
            for r in ["r1","r2","r3","r4","r5"]: regs[r]=AbstractValue.unknown()
            return "OK"

        if op=="exit": return "EXIT"
        if op.startswith("if") or op=="goto": return "BRANCH"

        # Register assignment and simple ALU expressions.
        if " = " in ins.text and re.match(r"^r(?:10|[0-9])\s*=\s*",ins.text):
            lhs,rhs=ins.text.split(" = ",1); lhs=lhs.strip(); rhs=rhs.strip()
            if re.fullmatch(r"r(?:10|[0-9])",rhs):
                regs[lhs]=regs.get(rhs,AbstractValue.unknown()); return "OK"
            if re.fullmatch(r"-?(?:0x[0-9A-Fa-f]+|\d+)",rhs):
                regs[lhs]=AbstractValue.const(self._imm(rhs)); return "OK"
            # Memory load: result is unknown, but the load is modeled.
            if re.fullmatch(r"\*\([^)]*\)\(r(?:10|[0-9])(?:\s*[+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\)",rhs):
                regs[lhs]=AbstractValue.unknown(); return "OK"
            m=re.fullmatch(r"(r(?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\s*(-?(?:0x[0-9A-Fa-f]+|\d+))",rhs)
            if m:
                self._eval_binary(lhs,m.group(2),AbstractValue.const(self._imm(m.group(3))),regs); return "OK"
            m=re.fullmatch(r"(r(?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\s*(r(?:10|[0-9]))",rhs)
            if m:
                self._eval_binary(lhs,m.group(2),regs.get(m.group(3),AbstractValue.unknown()),regs); return "OK"
            unknowns.append(f"unsupported register expression at {ins.pc}: {ins.text}"); return "UNKNOWN"

        # In-place ALU.
        m=re.fullmatch(r"(r(?:10|[0-9]))\s*([+\-*/&|^]|<<|>>)\=\s*(-?(?:0x[0-9A-Fa-f]+|\d+))",ins.text)
        if m:
            self._eval_binary(m.group(1),m.group(2),AbstractValue.const(self._imm(m.group(3))),regs); return "OK"

        # Memory stores are policy-neutral only because the frozen Phase 5
        # policy has no memory predicates. If memory policy becomes constrained,
        # these stores must move to UNKNOWN until range/provenance proofs exist.
        if re.match(r"^\*\([^)]*\)\(r(?:10|[0-9])(?:\s*[+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\)\s*=",ins.text):
            if self._memory_policy_constrained():
                unknowns.append(f"memory store requires policy-aware proof at {ins.pc}")
                return "UNKNOWN"
            return "OK"

        if op=="nop": return "OK"
        unknowns.append(f"unsupported instruction at {ins.pc}: {ins.text}")
        return "UNKNOWN"

    def _branch_constant(self,ins,regs):
        m=re.search(r"if\s+(r\d+)\s*(==|!=|>|>=|<|<=)\s*(r\d+|0x[0-9A-Fa-f]+|-?\d+)\s+goto",ins.text)
        if not m: return None
        a=regs.get(m.group(1),AbstractValue.unknown())
        b=regs.get(m.group(3),AbstractValue.unknown()) if m.group(3).startswith("r") else AbstractValue.const(self._imm(m.group(3)))
        if not (a.is_const() and b.is_const()): return None
        x,y=a.value,b.value; op=m.group(2)
        return {"==":x==y,"!=":x!=y,">":x>y,">=":x>=y,"<":x<y,"<=":x<=y}[op]

    def _unknown(self,reasons,steps):
        return {"verdict":"UNKNOWN","proof":"Conservative UNKNOWN: "+"; ".join(dict.fromkeys(reasons))[:4000],
                "discharged":False,"metrics":{"abstract_states":steps}}

    def analyze(self):
        try:
            self._disassemble_object()
            self._build_cfg()
            initial={f"r{i}":AbstractValue.unknown() for i in range(11)}
            initial["r10"]=AbstractValue.const(0)
            work=[(self.instructions[0].pc,initial,[],[],set())]
            exits=[]; reasons=[]; steps=0; max_states=4096
            while work:
                pc,regs,preds,helpers,visited=work.pop(0); steps+=1
                if steps>max_states: return self._unknown(reasons+["abstract state limit exceeded"],steps)
                if pc in visited: return self._unknown(reasons+[f"loop/revisit at {pc}"],steps)
                bb=self.basic_blocks.get(pc)
                if not bb: return self._unknown(reasons+[f"missing block {pc}"],steps)
                regs=dict(regs); preds=list(preds); helpers=list(helpers); visited=set(visited); visited.add(pc)
                terminal=None
                for ins in bb.instructions:
                    status=self._semantics(ins,regs,reasons,helpers)
                    if status=="UNKNOWN": return self._unknown(reasons,steps)
                    if status=="VIOLATION":
                        exits.append(("VIOLATION",preds,ins.pc)); terminal=True; break
                    if status=="EXIT":
                        rv=regs.get("r0",AbstractValue.unknown())
                        exits.append(("SAFE" if rv.is_const() and rv.value in self.allowed_returns else
                                      "VIOLATION" if rv.is_const() else "UNKNOWN",preds,ins.pc))
                        terminal=True; break
                if terminal: continue
                last=bb.instructions[-1]
                if last.opcode_name=="goto":
                    work.append((bb.successors[0],regs,preds,helpers,visited)); continue
                if last.opcode_name.startswith("if"):
                    c=self._branch_constant(last,regs)
                    if c is True:
                        work.append((bb.cond_target,regs,preds+[f"TAKEN({last.pc})"],helpers,visited))
                    elif c is False:
                        work.append((bb.fallthrough,regs,preds+[f"NOT_TAKEN({last.pc})"],helpers,visited))
                    else:
                        work.append((bb.cond_target,regs,preds+[f"TAKEN({last.pc})"],helpers,visited))
                        work.append((bb.fallthrough,regs,preds+[f"NOT_TAKEN({last.pc})"],helpers,visited))
                    continue
                if bb.successors:
                    work.append((bb.successors[0],regs,preds,helpers,visited))
                else:
                    return self._unknown(reasons+[f"block {bb.start_pc} has no terminal instruction"],steps)

            if not exits: return self._unknown(reasons+["no reachable exit"],steps)
            kinds={x[0] for x in exits}
            if kinds=={"SAFE"}:
                return {"verdict":"SAFE","proof":f"All {len(exits)} reachable exits return policy-allowed values and all modeled reachable operations are supported.",
                        "discharged":True,"metrics":{"instructions":len(self.instructions),"basic_blocks":len(self.basic_blocks),"paths_analyzed":len(exits),"abstract_states":steps}}
            if kinds=={"VIOLATION"}:
                return {"verdict":"VIOLATION","proof":f"All {len(exits)} reachable terminal paths establish a policy violation.",
                        "discharged":True,"metrics":{"instructions":len(self.instructions),"basic_blocks":len(self.basic_blocks),"paths_analyzed":len(exits),"abstract_states":steps}}
            return self._unknown(reasons+["mixed or unresolved reachable outcomes"],steps)
        except Exception as e:
            return self._unknown([f"analysis failure: {e}"],0)

def main():
    p=__import__("argparse").ArgumentParser(description="Phase 5 conservative abstract policy analyzer")
    p.add_argument("--object","-o",required=True); p.add_argument("--policy","-p",required=True); p.add_argument("--json",action="store_true")
    a=p.parse_args(); result=AbstractPolicyAnalyzer(a.object,a.policy).analyze()
    if a.json: print(json.dumps(result,indent=2))
    else:
        print(f"VERDICT: {result['verdict']}"); print(f"DISCHARGED: {result['discharged']}"); print(f"PROOF: {result['proof']}")
        for k,v in result.get("metrics",{}).items(): print(f"  {k}: {v}")
if __name__=="__main__": main()
