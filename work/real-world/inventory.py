#!/usr/bin/env python3
"""Inventory real-world source/object complexity without modifying workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "real-world"
RUNTIME = WORK / "runtime"
INPUT = RUNTIME / "prepared-corpus.json"
OUTPUT = RUNTIME / "inventory.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_files(root: Path, source_path: str) -> list[Path]:
    selected = root / source_path
    if selected.is_file():
        return [selected]
    if selected.is_dir():
        return sorted(p for p in selected.rglob("*") if p.suffix in {".c", ".h"})
    return []


def source_metrics(files: list[Path]) -> dict[str, Any]:
    loc = 0
    nonempty = 0
    functions: set[str] = set()
    helper_refs: set[str] = set()
    map_refs: set[str] = set()
    branch_count = 0

    function_re = re.compile(
        r"\b(?:static\s+)?(?:inline\s+)?(?:__attribute__\([^)]*\)\s*)?"
        r"[A-Za-z_][\w\s\*]*\s+([A-Za-z_]\w*)\s*\("
    )
    helper_re = re.compile(r"\bbpf_[A-Za-z0-9_]+\s*\(")
    map_re = re.compile(r"\bbpf_map_(?:lookup|update|delete|push|pop|peek)_elem\b")

    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        loc += len(lines)
        nonempty += sum(bool(line.strip()) for line in lines)
        functions.update(m.group(1) for m in function_re.finditer(text))
        helper_refs.update(m.group(0).rstrip("(") for m in helper_re.finditer(text))
        map_refs.update(m.group(0) for m in map_re.finditer(text))
        branch_count += sum(
            1 for line in lines
            if re.search(r"\b(if|else if|switch|case|for|while)\b", line)
        )

    return {
        "source_files": len(files),
        "loc": loc,
        "nonempty_loc": nonempty,
        "functions": len(functions),
        "function_names": sorted(functions),
        "map_operation_kinds": sorted(map_refs),
        "helper_references": sorted(helper_refs),
        "source_branch_constructs": branch_count,
    }


def disassembly_metrics(object_file: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["llvm-objdump", "-d", str(object_file)],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return {"disassembly_status": "error", "disassembly_error": proc.stderr.strip()}

    instruction_re = re.compile(r"^\s*[0-9a-f]+:\s+")
    rows = [line for line in proc.stdout.splitlines() if instruction_re.match(line)]
    branch_re = re.compile(r"\b(if|goto)\b")
    return {
        "disassembly_status": "ok",
        "compiled_instructions": len(rows),
        "compiled_branch_instructions": sum(1 for line in rows if branch_re.search(line)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=INPUT)
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    inventory: list[dict[str, Any]] = []

    for program in payload["programs"]:
        root = Path(program["source_root"])
        files = source_files(root, program["source_path"])
        item: dict[str, Any] = {
            "id": program["id"],
            "application": program["application"],
            "role": program["role"],
            "program_type": program["program_type"],
            "source_set": program["source_set"],
            "source_revision": program.get("upstream", {}).get("revision"),
            "source_files": [str(p.relative_to(root)) for p in files],
            "prepare_status": program.get("prepare_status"),
            "prepare_error": program.get("prepare_error"),
            "object_file": program.get("object_file"),
            "object_sha256": None,
            "static": source_metrics(files),
        }

        if program.get("object_file"):
            object_file = Path(program["object_file"])
            if object_file.exists():
                item["object_sha256"] = sha256_file(object_file)
                item["static"].update(disassembly_metrics(object_file))
            else:
                item["static"]["object_status"] = "missing"

        inventory.append(item)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(
            {"schema": "real-world-inventory/v1", "programs": inventory},
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "inventoried",
        "programs": len(inventory),
        "output": str(OUTPUT.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
