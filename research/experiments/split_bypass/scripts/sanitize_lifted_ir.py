#!/usr/bin/env python3
"""Sanitize ALU32 typed pointer mismatches in raw lifted LLVM IR.

In legacy bpflifter_cli outputs, registers %r0..%r10 are allocated as i64*, but
ALU32 destination loads and JMP32 operand reads erroneously emit:
  %var = load i32, i64* %rX
In typed LLVM IR (LLVM 13), this violates operand pointee typing and fails in opt.
This module normalizes the instruction to:
  %alu32_load_{var} = load i64, i64* %rX
  %{var} = trunc i64 %alu32_load_{var} to i32
preserving valid LLVM typing, SSA ordering, and eBPF 32-bit semantics.
"""
from __future__ import annotations

import re

# Strict pattern: matches only eBPF register alloca slots (%r0 through %r10)
# loaded directly as i32 from i64*
REG_LOAD_I32_FROM_I64_PATTERN = re.compile(
    r"^([ \t]*)%(\w+)\s*=\s*load\s+i32,\s*i64\*\s*%(r(?:10|[0-9]))(.*?)(?=\r?\n|$)",
    re.MULTILINE,
)


def sanitize_lifted_ir(ir_text: str) -> tuple[str, int]:
    """Sanitize invalid 32-bit loads from 64-bit register pointers.

    Returns:
        (sanitized_ir, replacements_count)
    """
    if not isinstance(ir_text, str):
        raise TypeError("ir_text must be a string")

    matches = list(REG_LOAD_I32_FROM_I64_PATTERN.finditer(ir_text))
    if not matches:
        return ir_text, 0

    def _replace(match: re.Match[str]) -> str:
        indent = match.group(1)
        var = match.group(2)
        reg = match.group(3)
        rest = match.group(4)
        # Emit load i64 with named temporary, followed by trunc to original var
        return (
            f"{indent}%alu32_load_{var} = load i64, i64* %{reg}{rest}\n"
            f"{indent}%{var} = trunc i64 %alu32_load_{var} to i32"
        )

    sanitized = REG_LOAD_I32_FROM_I64_PATTERN.sub(_replace, ir_text)

    # Sanity check: Ensure no invalid load i32, i64* %rX remains
    remaining = REG_LOAD_I32_FROM_I64_PATTERN.findall(sanitized)
    if remaining:
        raise RuntimeError(f"Sanitization incomplete: unhandled matches remain: {remaining}")

    return sanitized, len(matches)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        path = sys.argv[1]
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        fixed, count = sanitize_lifted_ir(content)
        if count > 0:
            with open(path, "w", encoding="utf-8") as f:
                f.write(fixed)
            print(f"Sanitized {count} ALU32 register loads in {path}")
        else:
            print(f"No ALU32 register mismatches found in {path}")
    else:
        print("Usage: python3 sanitize_lifted_ir.py <path_to_ll_file>")
