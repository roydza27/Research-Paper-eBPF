#!/usr/bin/env python3
"""Analyze scaling-campaign raw observations without modifying them."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "work" / "scaling" / "runtime" / "time-results"


def read_rows(path: Path) -> List[Dict]:
    out=[]
    raw_dir = path.parent / "raw"
    info_re = re.compile(r"^KLEE: done: completed paths = (\d+)\s*$")
    with path.open(newline="",encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            r["scale"]=int(r["scale"]); r["target_paths"]=int(r["target_paths"])
            r["instructions"]=int(r["instructions"])
            r["wall_time_ms"]=float(r["wall_time_ms"])

            raw_value = r.get("klee_completed_paths")
            if raw_value not in (None, "", "None"):
                r["klee_completed_paths"] = int(raw_value)
            else:
                # The original timing runner attempted an unprefixed regex,
                # while KRAKENGUARD emits lines such as
                # "KLEE: done: completed paths = N". Recover the observed
                # count from the archived raw info file rather than rerunning
                # the verifier.
                info_file = raw_dir / r["run_id"] / "info"
                recovered = None
                if info_file.exists():
                    for line in info_file.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines():
                        m = info_re.match(line.strip())
                        if m:
                            recovered = int(m.group(1))
                            break
                r["klee_completed_paths"] = recovered

            r["fallback_invoked"]=r["fallback_invoked"]=="True"
            r["verdict_correct"]=None if r["verdict_correct"] in ("","None") else r["verdict_correct"]=="True"
            out.append(r)
    return out


def median_table(rows: List[Dict], mode: str) -> Dict[str, Dict]:
    grouped=defaultdict(list)
    for r in rows:
        if r["mode"]==mode and r["repetition_type"]=="measured" and r["status"]=="ok":
            grouped[r["program_id"]].append(r)
    result={}
    for pid,rs in grouped.items():
        result[pid]={
            "program_id":pid,"family":rs[0]["family"],"scale":rs[0]["scale"],
            "target_paths":rs[0]["target_paths"],"instructions":rs[0]["instructions"],
            "observed_klee_completed_paths":statistics.median(
                x["klee_completed_paths"] for x in rs
                if x["klee_completed_paths"] is not None
            ) if any(x["klee_completed_paths"] is not None for x in rs) else None,
            "median_ms":statistics.median(x["wall_time_ms"] for x in rs),
            "mean_ms":statistics.fmean(x["wall_time_ms"] for x in rs),
            "min_ms":min(x["wall_time_ms"] for x in rs),
            "max_ms":max(x["wall_time_ms"] for x in rs),
            "fallback_fraction":statistics.fmean(x["fallback_invoked"] for x in rs),
            "correct":all(x["verdict_correct"] for x in rs if x["verdict_correct"] is not None),
        }
    return result


def fit(xs:List[float],ys:List[float])->Dict:
    if len(xs)<2:return {"n":len(xs),"slope":None,"intercept":None,"r2":None}
    xb,yb=statistics.fmean(xs),statistics.fmean(ys)
    den=sum((x-xb)**2 for x in xs)
    if den==0:return {"n":len(xs),"slope":None,"intercept":yb,"r2":None}
    slope=sum((x-xb)*(y-yb) for x,y in zip(xs,ys))/den
    intercept=yb-slope*xb
    sst=sum((y-yb)**2 for y in ys)
    ssr=sum((y-(intercept+slope*x))**2 for x,y in zip(xs,ys))
    return {"n":len(xs),"slope":slope,"intercept":intercept,"r2":1-ssr/sst if sst else 1}


def summarize(rows:List[Dict])->Dict:
    tabs={m:median_table(rows,m) for m in ("symbolic_only","abstract_only","hybrid")}
    by_family=defaultdict(list)
    for pid,v in tabs["hybrid"].items():
        by_family[v["family"]].append(v)

    family=[]
    for fam,items in sorted(by_family.items()):
        # Pair by program with symbolic-only.
        ps=[]
        for v in items:
            s=tabs["symbolic_only"].get(v["program_id"])
            if not s: continue
            ps.append({
                **v,
                "symbolic_median_ms":s["median_ms"],
                "absolute_saving_ms":s["median_ms"]-v["median_ms"],
                "saving_pct":((s["median_ms"]-v["median_ms"])/s["median_ms"]*100) if s["median_ms"] else None
            })
        family.append({
            "family":fam,
            "program_count":len(ps),
            "paired_median_saving_ms":statistics.median([x["absolute_saving_ms"] for x in ps]) if ps else None,
            "paired_median_saving_pct":statistics.median([x["saving_pct"] for x in ps]) if ps else None,
            "rows":ps,
        })

    scaling={}
    # Size axis uses compiled instructions; path axis uses observed KLEE
    # completed paths recovered from the captured KRAKENGUARD info files.
    # Never substitute target paths for the primary path coordinate.
    for fam in sorted({v["family"] for v in tabs["symbolic_only"].values()}):
        pts=[]
        for pid,s in tabs["symbolic_only"].items():
            if s["family"]!=fam: continue
            h=tabs["hybrid"].get(pid)
            if not h: continue
            if "size" in fam.lower():
                x=s["instructions"]
            else:
                x=s.get("observed_klee_completed_paths")
                if x is None:
                    raise RuntimeError(
                        f"missing observed KLEE completed-path count for {pid}; "
                        "refusing to substitute target_paths"
                    )
            pts.append((float(x),s["median_ms"],h["median_ms"]))
        if pts:
            scaling[fam]={
                "x_axis":"compiled_instructions" if "size" in fam.lower() else "observed_klee_completed_paths",
                "symbolic_fit":fit([p[0] for p in pts],[p[1] for p in pts]),
                "hybrid_fit":fit([p[0] for p in pts],[p[2] for p in pts]),
                "points":pts,
                "note":"Descriptive scaling fit; not an asymptotic complexity proof."
            }

    correctness=[r for r in rows if r["repetition_type"]=="measured" and r["status"]=="ok" and r["verdict_correct"] is not None]
    unknown_hybrid=[r for r in rows if r["repetition_type"]=="measured" and r["mode"]=="hybrid" and r["route"]=="FALLBACK_SYMBOLIC"]
    discharged=[r for r in rows if r["repetition_type"]=="measured" and r["mode"]=="hybrid" and r["route"].startswith("FAST_PATH")]

    return {
        "schema":"scaling-analysis/v1",
        "raw_runs":len(rows),
        "successful_measured_runs":sum(r["repetition_type"]=="measured" and r["status"]=="ok" for r in rows),
        "correctness":{
            "checked":len(correctness),
            "all_agree":all(r["verdict_correct"] for r in correctness) if correctness else None,
            "false_concrete":sum(not r["verdict_correct"] for r in correctness),
        },
        "coverage":{
            "hybrid_measured":sum(r["mode"]=="hybrid" and r["repetition_type"]=="measured" for r in rows),
            "fallback_fraction":len(unknown_hybrid) / (
                len(unknown_hybrid) + len(discharged)
            ) if (unknown_hybrid or discharged) else None,
            "fast_path_fraction":len(discharged) / (
                len(unknown_hybrid) + len(discharged)
            ) if (unknown_hybrid or discharged) else None,
        },
        "family_summary":family,
        "scaling":scaling,
        "break_even":{
            "interpretation":"For a fast-path program, a first-order break-even condition is T_abstract < T_symbolic. Using measured medians, abstract/symbolic is the approximate discharge-cost threshold.",
            "per_program":{
                pid:{
                    "abstract_only_median_ms":tabs["abstract_only"][pid]["median_ms"] if pid in tabs["abstract_only"] else None,
                    "symbolic_only_median_ms":tabs["symbolic_only"][pid]["median_ms"] if pid in tabs["symbolic_only"] else None,
                    "approx_break_even_discharge_fraction":(
                        tabs["abstract_only"][pid]["median_ms"]/tabs["symbolic_only"][pid]["median_ms"]
                        if pid in tabs["abstract_only"] and pid in tabs["symbolic_only"] and tabs["symbolic_only"][pid]["median_ms"] else None
                    )
                } for pid in sorted(tabs["hybrid"])
            }
        }
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,default=RESULTS/"runs.csv")
    args=p.parse_args()
    summary=summarize(read_rows(args.input))
    (RESULTS/"analysis.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    (RESULTS/"analysis.md").write_text(
        "# Scaling Analysis\n\n"
        "Descriptive analysis generated from raw scaling observations. "
        "No asymptotic complexity claim is inferred from linear fits.\n\n"
        + json.dumps(summary["coverage"],indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status":"analysis_complete","analysis":str((RESULTS/"analysis.json").relative_to(ROOT))},indent=2))


if __name__=="__main__":
    main()
