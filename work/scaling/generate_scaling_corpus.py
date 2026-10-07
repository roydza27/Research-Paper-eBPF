#!/usr/bin/env python3
"""Generate a parameterized eBPF corpus for controlled scaling experiments."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "work" / "scaling" / "runtime" / "corpus"
POLICY = ROOT / "research" / "experiments" / "corpus" / "phase5" / "policies" / "phase5_policy.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def emit_header(fn: str) -> str:
    return f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int {fn}(struct xdp_md *ctx)
{{
    /*
     * Keep one small volatile scalar on the BPF stack. Each generated
     * update must survive -O2, while the stack footprint stays constant.
     * This gives us straight-line instruction growth without introducing
     * extra symbolic branches, packet-data loads, or helper calls.
     */
    /*
     * Seed the volatile stack slot from a context field so initialization is
     * represented as a normal register-to-stack store. The accumulator is
     * intentionally independent of the final return value: size scaling must
     * increase straight-line verifier work without turning the fast-path
     * verdict into UNKNOWN merely because stack contents are not abstractly
     * value-precise.
     */
    volatile __u64 x = 0;

"""

def emit_packet_header(fn: str) -> str:
    return f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int {fn}(struct xdp_md *ctx)
{{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

"""

def emit_close() -> str:
    return """}

char LICENSE[] SEC("license") = "GPL";
"""

def size_source(fn: str, padding: int, violation: bool) -> str:
    lines = [emit_header(fn)]
    # Volatile stack updates are retained by the compiler and reuse the same
    # fixed stack slot, so compiled straight-line work can grow without
    # growing the stack frame itself.
    for i in range(padding):
        lines.append(f"    x ^= (__u64){i + 1};\n")
    if violation:
        lines.append('    bpf_trace_printk("scaling", 7);\n')
    lines.append("    (void)x;\n")
    lines.append("    return XDP_PASS;\n")
    lines.append(emit_close())
    return "".join(lines)

def path_source(fn: str, predicates: int, violation: bool) -> str:
    lines = [emit_packet_header(fn)]
    lines.append("    __u64 t = bpf_ktime_get_ns();\n")
    lines.append("    volatile __u8 *p = (volatile __u8 *)data;\n")
    for bit in range(predicates):
        mask = 1 << bit
        lines.extend([
            f"    if (t & (1ULL << {bit})) {{\n",
            f"        *p ^= (__u8){mask};\n",
        ])
        if violation and bit == 0:
            lines.append('        bpf_trace_printk("scaling", 7);\n')
        lines.append("    }\n")
    lines.append("    return XDP_PASS;\n")
    lines.append(emit_close())
    return "".join(lines)


def compile_one(src: Path, obj: Path, clang: str) -> Dict[str, str]:
    cmd = [
        clang, "-target", "bpf", "-mcpu=v1", "-D__TARGET_ARCH_x86",
        "-O2", "-g", "-I/usr/include", "-c", str(src), "-o", str(obj)
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    (src.parent / (src.stem + ".compile.log")).write_text(
        "Command: " + " ".join(cmd) + "\n"
        + f"Exit code: {proc.returncode}\n"
        + "--- stdout ---\n" + proc.stdout
        + "\n--- stderr ---\n" + proc.stderr,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"clang failed for {src.name}: {proc.stderr.strip()}")
    return {"command": " ".join(cmd), "clang": clang, "object_sha256": sha256(obj)}


def inspect_object(obj: Path) -> Dict[str, int]:
    p = subprocess.run(
        ["llvm-objdump", "-d", "--no-show-raw-insn", str(obj)],
        text=True, capture_output=True, check=True
    )
    lines = [x for x in p.stdout.splitlines() if x.lstrip().startswith(tuple("0123456789abcdef")) and ":" in x]
    branches = sum("if " in x or "goto" in x for x in lines)
    calls = sum("call" in x for x in lines)
    return {"instructions": len(lines), "branches": branches, "helpers": calls}


def build_corpus(out: Path, padding: List[int], max_bits: int, clang: str) -> List[Dict]:
    out.mkdir(parents=True, exist_ok=True)
    rows: List[Dict] = []
    # Size families intentionally use two semantic classes.
    for kind, violation in (("A-size", False), ("C-size", True)):
        for n in padding:
            pid = f"{kind.lower().replace('-', '')}-{n:04d}"
            fn = pid.replace("-", "_")
            src = out / f"{pid}.c"
            obj = out / f"{pid}.o"
            src.write_text(size_source(fn, n, violation), encoding="utf-8")
            comp = compile_one(src, obj, clang)
            static = inspect_object(obj)
            rows.append({
                "program_id": pid,
                "family": kind,
                "scale": n,
                "target_paths": 1,
                "expected_verdict": "POLICY VIOLATION" if violation else "COMPLIANT",
                "expected_abstract_verdict": "VIOLATION" if violation else "SAFE",
                "source_file": str(src.relative_to(ROOT)),
                "object_file": str(obj.relative_to(ROOT)),
                "source_sha256": sha256(src),
                "object_sha256": sha256(obj),
                **static,
                **comp,
            })

    # Path families mirror the validated E2 construction.
    for kind, violation in (("B-path", False), ("D-path", True)):
        # A fallback path family starts at one predicate (2 feasible paths).\n    # A zero-predicate program has no unresolved branch and therefore should\n    # not be labeled UNKNOWN merely to manufacture a 1-path fallback point.\n    for k in range(1, max_bits + 1):
            target = 1 << k
            pid = f"{kind.lower().replace('-', '')}-p{target:03d}"
            fn = pid.replace("-", "_")
            src = out / f"{pid}.c"
            obj = out / f"{pid}.o"
            src.write_text(path_source(fn, k, violation), encoding="utf-8")
            comp = compile_one(src, obj, clang)
            static = inspect_object(obj)
            rows.append({
                "program_id": pid,
                "family": kind,
                "scale": k,
                "target_paths": target,
                "expected_verdict": "POLICY VIOLATION" if violation else "COMPLIANT",
                "expected_abstract_verdict": "UNKNOWN",
                "source_file": str(src.relative_to(ROOT)),
                "object_file": str(obj.relative_to(ROOT)),
                "source_sha256": sha256(src),
                "object_sha256": sha256(obj),
                **static,
                **comp,
            })

    return rows


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--padding", default="0,16,32,64,128")
    p.add_argument("--max-bits", type=int, default=6, help="1..6 => 2..64 target paths")
    p.add_argument("--clang", default="clang")
    args = p.parse_args()

    if not POLICY.exists():
        raise SystemExit(f"missing policy: {POLICY}")

    padding = [int(x) for x in args.padding.split(",") if x.strip()]
    if any(x < 0 for x in padding):
        raise SystemExit("padding values must be non-negative")
    if not 0 <= args.max_bits <= 6:
        raise SystemExit("--max-bits must be in 0..6 for the default validated path regime")

    rows = build_corpus(args.out, padding, args.max_bits, args.clang)
    metadata = args.out / "metadata.csv"
    fields = [
        "program_id","family","scale","target_paths","expected_verdict",
        "expected_abstract_verdict","source_file","object_file",
        "source_sha256","object_sha256","instructions","branches","helpers","command","clang"
    ]
    with metadata.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    manifest = {
        "schema": "scaling-corpus/v1",
        "policy": str(POLICY.relative_to(ROOT)),
        "program_count": len(rows),
        "families": {f: sum(r["family"] == f for r in rows) for f in sorted({r["family"] for r in rows})},
        "rows": rows,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": "generated",
        "programs": len(rows),
        "metadata": str(metadata.relative_to(ROOT)),
        "manifest": str((args.out / "manifest.json").relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
