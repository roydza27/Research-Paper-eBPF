#!/usr/bin/env python3
"""Generate a controlled eBPF corpus and record build provenance.

This script never assigns a reference verdict. Oracle labels remain pending until
the configured reference verifier has actually been run and its raw response saved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "research/experiments/split_bypass"
PROGRAMS = BASE / "programs"
POLICIES = BASE / "policies"
MANIFESTS = BASE / "manifests"

HEADER = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

"""

SOURCES: dict[str, dict[str, Any]] = {
    "A01_straight_small": {
        "family": "A_straight_line", "hypothesis": "small straight-line arithmetic",
        "source": HEADER + """SEC("xdp")
int A01_straight_small(struct xdp_md *ctx)
{
    __u32 n = ctx->data_end - ctx->data;
    n += 1;
    n ^= 3;
    return (n & 1) ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "A02_straight_medium": {
        "family": "A_straight_line", "hypothesis": "larger source-level arithmetic sequence; compiler may simplify it",
        "source": HEADER + """SEC("xdp")
int A02_straight_medium(struct xdp_md *ctx)
{
    volatile __u32 n = ctx->data_end - ctx->data;
""" + "".join(f"    n = (n * {i % 5 + 2}) + {i % 7};\n" for i in range(1, 25)) + """    return n & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "A03_helper_clock": {
        "family": "A_straight_line", "hypothesis": "straight-line helper interaction",
        "source": HEADER + """SEC("xdp")
int A03_helper_clock(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 len = ctx->data_end - ctx->data;
    return ((now ^ len) & 1) ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "A04_map_lookup": {
        "family": "A_straight_line", "hypothesis": "straight-line map lookup; map identity and policy rule must be checked",
        "source": HEADER + """struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} e1_map SEC(".maps");

SEC("xdp")
int A04_map_lookup(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&e1_map, &key);
    return value ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "B01_branch_safe": {
        "family": "B_branching", "hypothesis": "unresolved condition with safe alternatives",
        "source": HEADER + """SEC("xdp")
int B01_branch_safe(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    volatile __u64 stamp = 0;
    if (len & 1)
        stamp = bpf_ktime_get_ns();
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "B02_branch_policy_sensitive": {
        "family": "B_branching", "hypothesis": "reachable DROP alternative; semantic policy outcome must come from oracle",
        "source": HEADER + """SEC("xdp")
int B02_branch_policy_sensitive(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    if (now & 1)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "B03_branch_depth": {
        "family": "B_branching", "hypothesis": "multiple unresolved conditions and several source-level paths",
        "source": HEADER + """SEC("xdp")
int B03_branch_depth(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    volatile __u64 stamp = 0;
    if (ctx->ingress_ifindex & 1) {
        stamp = bpf_ktime_get_ns();
        if (len & 1)
            stamp ^= bpf_ktime_get_ns();
    } else if (len > 128) {
        stamp = bpf_ktime_get_ns();
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "C01_join_different_values": {
        "family": "C_join_points", "hypothesis": "two predecessors assign different values before a shared comparison",
        "source": HEADER + """SEC("xdp")
int C01_join_different_values(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if ((ctx->data_end - ctx->data) & 1)
        joined = 1;
    else
        joined = 2;
    if (joined == 1)
        return XDP_PASS;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "C02_join_policy_sensitive": {
        "family": "C_join_points", "hypothesis": "joined state influences a downstream policy-sensitive return",
        "source": HEADER + """SEC("xdp")
int C02_join_policy_sensitive(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if (ctx->ingress_ifindex & 1)
        joined = 0;
    else
        joined = 1;
    if (joined)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "C03_join_violation_candidate": {
        "family": "C_join_points", "hypothesis": "one join predecessor can produce a policy-sensitive DROP",
        "source": HEADER + """SEC("xdp")
int C03_join_violation_candidate(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if (ctx->ingress_ifindex & 1)
        joined = 0;
    else
        joined = 1;
    if (joined == 1)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "D01_helper_unknown_candidate": {
        "family": "D_unknown_fallback", "hypothesis": "helper-derived unresolved value; UNKNOWN is a hypothesis, not an assigned outcome",
        "source": HEADER + """SEC("xdp")
int D01_helper_unknown_candidate(struct xdp_md *ctx)
{
    __u32 value = bpf_get_prandom_u32();
    if (value == 0x13579)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "D02_packet_memory_candidate": {
        "family": "D_unknown_fallback", "hypothesis": "bounded packet access and memory-state candidate; compile/verifier acceptance must be recorded",
        "source": HEADER + """SEC("xdp")
int D02_packet_memory_candidate(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;
    volatile unsigned char value = *(unsigned char *)data;
    if (value == 0x7f)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "E01_bounded_loop": {
        "family": "E_loops", "hypothesis": "bounded loop; emitted loop structure depends on compiler and flags",
        "source": HEADER + """SEC("xdp")
int E01_bounded_loop(struct xdp_md *ctx)
{
    volatile __u32 acc = ctx->ingress_ifindex;
    __u32 i = 0;
#pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++)
        acc = (acc * 3) ^ i;
    return acc & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
    "E02_nested_bounded_loop": {
        "family": "E_loops", "hypothesis": "nested bounded loops; verifier acceptance and emitted back-edges must be measured",
        "source": HEADER + """SEC("xdp")
int E02_nested_bounded_loop(struct xdp_md *ctx)
{
    volatile __u32 acc = ctx->ingress_ifindex;
    __u32 i = 0;
    __u32 j = 0;
#pragma clang loop unroll(disable)
    for (i = 0; i < 3; i++) {
#pragma clang loop unroll(disable)
        for (j = 0; j < 4; j++)
            acc = (acc + i) ^ j;
    }
    return acc & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
""",
    },
}

def sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run(command: list[str], timeout: int = 60) -> dict[str, Any]:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": None, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "timed_out": True}

def disassembly_metrics(obj: Path, objdump: str) -> dict[str, Any]:
    proc = run([objdump, "-d", str(obj)], timeout=30)
    if proc["returncode"] != 0:
        return {"status": "unavailable", "error": proc["stderr"][-2000:], "instruction_count": None,
                "branch_count": None, "basic_block_count": None}
    lines = proc["stdout"].splitlines()
    instructions = []
    for line in lines:
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
        if match and re.search(r"\b(r[0-9]+|call|exit|goto|ldx|stx|mov|add|sub|and|or|xor|j[a-z]+)\b", match.group(2)):
            instructions.append((int(match.group(1), 16), match.group(2).strip()))
    branches = [(pc, text) for pc, text in instructions if re.search(r"\b(if|goto|ja|j[a-z]+)\b", text)]
    # A CFG count requires reliable jump-target parsing. Only count leaders when
    # objdump exposes a parseable target; otherwise report null rather than guess.
    pcs = {pc for pc, _ in instructions}
    leaders: set[int] = {instructions[0][0]} if instructions else set()
    targets_complete = True
    for idx, (pc, text) in enumerate(instructions):
        if not re.search(r"\b(if|goto|ja|j[a-z]+)\b", text):
            continue
        target = re.search(r"(?:goto\s+\+?0x?([0-9a-fA-F]+)|goto\s+(-?\d+)|\bja\s+(-?\d+))", text)
        if not target:
            targets_complete = False
            continue
        raw = next(g for g in target.groups() if g is not None)
        try:
            offset = int(raw, 16) if target.group(1) is not None else int(raw, 10)
            leaders.add(pc + offset)
        except ValueError:
            targets_complete = False
        if idx + 1 < len(instructions):
            leaders.add(instructions[idx + 1][0])
    return {
        "status": "parsed" if targets_complete else "partial_parse",
        "instruction_count": len(instructions),
        "branch_count": len(branches),
        "basic_block_count": len(leaders & pcs) if targets_complete else None,
        "disassembly_sha256": hashlib.sha256(proc["stdout"].encode()).hexdigest(),
        "note": "Objdump-derived counts are provisional; compare with analyzer CFG before treating as canonical."
    }

def prepare(policy_path: Path, clang: str, objdump: str, compile_objects: bool,
            target_arch: str, include_dir: str, manifest_output: Path | None = None) -> dict[str, Any]:
    for directory in (PROGRAMS, POLICIES, MANIFESTS, BASE / "results/raw", BASE / "results/summary", BASE / "tests", BASE / "design"):
        directory.mkdir(parents=True, exist_ok=True)
    if not policy_path.is_file():
        raise FileNotFoundError(f"policy does not exist: {policy_path}")
    policy_copy = POLICIES / f"policy-{sha256(policy_path)[:12]}{policy_path.suffix or '.json'}"
    if not policy_copy.exists():
        shutil.copy2(policy_path, policy_copy)
    rows = []
    for program_id, spec in SOURCES.items():
        source_path = PROGRAMS / f"{program_id}.c"
        source_path.write_text(spec["source"])
        obj_path = PROGRAMS / f"{program_id}.o"
        command = [clang, "-target", "bpf", f"-D__TARGET_ARCH_{target_arch}", "-O2", "-g",
                   f"-I{include_dir}", "-c", str(source_path), "-o", str(obj_path)]
        build = {"status": "not_attempted", "command": command, "returncode": None, "stdout": "", "stderr": ""}
        metrics = {"instruction_count": None, "branch_count": None, "basic_block_count": None,
                   "status": "not_measured"}
        object_hash = None
        if compile_objects:
            result = run(command, timeout=60)
            build = {"status": "timeout" if result["timed_out"] else ("compiled" if result["returncode"] == 0 else "failed"),
                     "command": command, **result}
            if result["returncode"] == 0 and not result["timed_out"] and obj_path.is_file():
                object_hash = sha256(obj_path)
                metrics = disassembly_metrics(obj_path, objdump)
            else:
                obj_path = None
        rows.append({
            "program_id": program_id, "family": spec["family"], "hypothesis": spec["hypothesis"],
            "source_path": str(source_path.relative_to(ROOT)), "source_sha256": sha256(source_path),
            "compile_command": command, "build": build,
            "elf_path": str(obj_path.relative_to(ROOT)) if obj_path else None, "elf_sha256": object_hash,
            "structure": metrics, "policy_path": str(policy_copy.relative_to(ROOT)),
            "policy_sha256": sha256(policy_copy),
            "reference_oracle": {"input_policy": str(policy_copy.relative_to(ROOT)),
                                 "status": "not_run", "raw_response_path": None,
                                 "expected_semantic_verdict": None, "provenance": None},
            "region_verdicts": {"available": False, "reason": "no region analysis API is implemented"},
        })
    manifest = {
        "schema": "split-bypass-corpus-manifest/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])["stdout"].strip() or None,
        "environment": {"python": sys.version, "platform": platform.platform(), "clang": shutil.which(clang),
                        "objdump": shutil.which(objdump), "target_arch": target_arch, "include_dir": include_dir},
        "policy_source": str(policy_path.resolve()), "policy_source_sha256": sha256(policy_path),
        "programs": rows,
        "warning": "No semantic verdicts are prefilled. Compiler success is not reference-verifier success."
    }
    output = manifest_output or (MANIFESTS / "corpus-manifest.json")
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite manifest: {output}; archive it and choose a new run directory")
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path, help="existing policy file used for every initial fixture")
    parser.add_argument("--compile", action="store_true", help="compile using the existing project clang convention")
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--objdump", default=os.environ.get("LLVM_OBJDUMP", "llvm-objdump"))
    parser.add_argument("--target-arch", default=os.environ.get("BPF_ARCH", "x86"))
    parser.add_argument("--include-dir", default=os.environ.get("BPF_INCLUDE_DIR", "/usr/include"))
    parser.add_argument("--manifest-output", type=Path, help="new manifest path; existing files are refused")
    args = parser.parse_args()
    manifest_path = args.manifest_output or (MANIFESTS / "corpus-manifest.json")
    manifest = prepare(args.policy, args.clang, args.objdump, args.compile, args.target_arch, args.include_dir, manifest_path)
    print(json.dumps({"manifest": str(manifest_path),
                      "program_count": len(manifest["programs"]),
                      "compiled_count": sum(p["build"]["status"] == "compiled" for p in manifest["programs"]),
                      "verdicts_assigned": sum(p["reference_oracle"]["expected_semantic_verdict"] is not None for p in manifest["programs"])}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
