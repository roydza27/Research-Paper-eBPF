#!/usr/bin/env python3
"""Fetch pinned public eBPF/XDP sources and optionally build benchmark objects."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "real-world"
RUNTIME = WORK / "runtime"
SOURCES = RUNTIME / "sources"
CORPUS = WORK / "corpus.json"
PREPARED = RUNTIME / "prepared-corpus.json"


def run(cmd: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def load() -> dict[str, Any]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def clone_pinned(name: str, repository: str, revision: str, recursive: bool = True) -> Path:
    destination = SOURCES / name
    RUNTIME.mkdir(parents=True, exist_ok=True)
    SOURCES.mkdir(parents=True, exist_ok=True)

    if destination.exists():
        observed = run(["git", "rev-parse", "HEAD"], cwd=destination)
        if observed == revision:
            return destination
        shutil.rmtree(destination)

    cmd = ["git", "clone"]
    if recursive:
        cmd.append("--recurse-submodules")
    cmd += [repository, str(destination)]
    run(cmd)
    run(["git", "checkout", "--detach", revision], cwd=destination)
    if recursive:
        run(["git", "submodule", "update", "--init", "--recursive"], cwd=destination)
    observed = run(["git", "rev-parse", "HEAD"], cwd=destination)
    if observed != revision:
        raise RuntimeError(f"{name}: checkout mismatch: expected {revision}, got {observed}")
    return destination


def prepare_sources(spec: dict[str, Any]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for name, src in spec["source_sets"].items():
        result[name] = clone_pinned(name, src["repository"], src["revision"], recursive=True)
    return result


def candidate_objects(root: Path) -> list[Path]:
    seen: set[Path] = set()
    for pattern in ("*.o", "**/*.o"):
        for p in root.glob(pattern):
            if p.is_file():
                seen.add(p.resolve())
    return sorted(seen)


def build_program(program: dict[str, Any], source_root: Path) -> tuple[str | None, str | None]:
    strategy = program["build"]["strategy"]
    if strategy == "ebpf_se_xdp_target":
        workdir = source_root / program["source_path"]
        run(["make", "xdp-target"], cwd=workdir)
        objects = candidate_objects(workdir)
    elif strategy == "project_makefile":
        source = source_root / program["source_path"]
        workdir = source if source.is_dir() else source.parent
        run(["make"], cwd=workdir)
        objects = candidate_objects(workdir)
    else:
        return None, f"unsupported build strategy: {strategy}"

    if not objects:
        return None, "build completed but no ELF object (*.o) was discovered"

    pid = program["id"].lower().replace("-", "_")
    ranked = sorted(objects, key=lambda p: (pid not in p.stem.lower(), len(p.parts)))
    return str(ranked[0]), None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()

    spec = load()
    roots = prepare_sources(spec)
    source_revisions = {
        name: run(["git", "rev-parse", "HEAD"], cwd=root)
        for name, root in roots.items()
    }
    if "ebpf_se" in roots and args.build:
        run(["make", "libbpf"], cwd=roots["ebpf_se"])
    prepared: list[dict[str, Any]] = []

    for program in spec["programs"]:
        source_root = roots[program["source_set"]]
        item = dict(program)
        item["source_root"] = str(source_root)
        item["source_set_revision"] = source_revisions[program["source_set"]]
        item["object_file"] = None
        item["prepare_status"] = "ready"
        item["prepare_error"] = None

        if args.build:
            try:
                obj, error = build_program(program, source_root)
                item["object_file"] = obj
                if obj is None:
                    item["prepare_status"] = "incompatible"
                    item["prepare_error"] = error
            except Exception as exc:
                item["prepare_status"] = "build_error"
                item["prepare_error"] = f"{type(exc).__name__}: {exc}"

        prepared.append(item)

    PREPARED.parent.mkdir(parents=True, exist_ok=True)
    PREPARED.write_text(
        json.dumps(
            {
                "schema": "prepared-real-world-corpus/v1",
                "source_revisions": source_revisions,
                "programs": prepared,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "prepared",
        "source_sets": len(roots),
        "programs": len(prepared),
        "build": args.build,
        "manifest": str(PREPARED.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
