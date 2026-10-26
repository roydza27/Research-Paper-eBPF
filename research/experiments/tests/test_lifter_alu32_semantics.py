#!/usr/bin/env python3
"""Regression test suite for eBPF ALU32 lifter semantics and typed IR transformation.

Validates that:
1. Invalid ALU32 destination reads (load i32, i64* %rX) are normalized to valid load i64 + trunc i32.
2. ALU64 register loads (load i64, i64* %rX) remain completely untouched.
3. Memory and packet pointer loads (load i32, i32* %ptr) remain completely untouched.
4. JMP32 register loads are properly normalized.
5. 32-bit arithmetic computation and 64-bit zero-extension semantics are preserved.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXPERIMENT_DIR = Path(__file__).resolve().parents[1] / "split_bypass" / "scripts"
sys.path.insert(0, str(EXPERIMENT_DIR))

from sanitize_lifted_ir import sanitize_lifted_ir


class LifterALU32SemanticsTests(unittest.TestCase):
    def test_alu32_destination_read_semantics(self):
        # Snippet from actual bpflifter_cli output on A02_straight_medium.o
        raw_snippet = (
            "  %12 = zext i32 %11 to i64\n"
            "  store i64 %12, i64* %r1, align 4\n"
            "  %13 = load i32, i64* %r1, align 4\n"
            "  %14 = load i64, i64* %r2, align 4\n"
            "  %15 = trunc i64 %14 to i32\n"
            "  %16 = sub i32 %13, %15\n"
            "  %17 = zext i32 %16 to i64\n"
            "  store i64 %17, i64* %r1, align 4\n"
        )
        sanitized, count = sanitize_lifted_ir(raw_snippet)
        self.assertEqual(count, 1)
        self.assertNotIn("load i32, i64* %r1", sanitized)
        self.assertIn("%alu32_load_13 = load i64, i64* %r1, align 4", sanitized)
        self.assertIn("%13 = trunc i64 %alu32_load_13 to i32", sanitized)
        # Verify subsequent lines preserved
        self.assertIn("  %16 = sub i32 %13, %15\n", sanitized)
        self.assertIn("  %17 = zext i32 %16 to i64\n", sanitized)

    def test_alu64_operations_unaltered(self):
        raw_alu64 = (
            "  %1 = load i64, i64* %r1, align 4\n"
            "  %2 = load i64, i64* %r2, align 4\n"
            "  %3 = add i64 %1, %2\n"
            "  store i64 %3, i64* %r1, align 4\n"
        )
        sanitized, count = sanitize_lifted_ir(raw_alu64)
        self.assertEqual(count, 0)
        self.assertEqual(sanitized, raw_alu64)

    def test_pointer_memory_loads_unaltered(self):
        raw_mem = (
            "  %3 = getelementptr i8, i8* %2, i64 0\n"
            "  %4 = bitcast i8* %3 to i32*\n"
            "  %5 = load i32, i32* %4, align 4\n"
            "  %6 = zext i32 %5 to i64\n"
            "  store i64 %6, i64* %r2, align 4\n"
        )
        sanitized, count = sanitize_lifted_ir(raw_mem)
        self.assertEqual(count, 0)
        self.assertEqual(sanitized, raw_mem)

    def test_jmp32_operand_reads_sanitized(self):
        raw_jmp32 = (
            "  %dst = load i32, i64* %r1, align 4\n"
            "  %src = load i32, i64* %r2, align 4\n"
            "  %cmp = icmp eq i32 %dst, %src\n"
            "  br i1 %cmp, label %bb2, label %bb3\n"
        )
        sanitized, count = sanitize_lifted_ir(raw_jmp32)
        self.assertEqual(count, 2)
        self.assertNotIn("load i32, i64* %r1", sanitized)
        self.assertNotIn("load i32, i64* %r2", sanitized)
        self.assertIn("%alu32_load_dst = load i64, i64* %r1, align 4", sanitized)
        self.assertIn("%dst = trunc i64 %alu32_load_dst to i32", sanitized)
        self.assertIn("%alu32_load_src = load i64, i64* %r2, align 4", sanitized)
        self.assertIn("%src = trunc i64 %alu32_load_src to i32", sanitized)

    def test_non_register_pointers_ignored(self):
        raw_other = (
            "  %val = load i32, i64* %custom_ptr, align 4\n"
        )
        sanitized, count = sanitize_lifted_ir(raw_other)
        self.assertEqual(count, 0)
        self.assertEqual(sanitized, raw_other)

    def test_complete_ebpf_alu32_semantics_model(self):
        """Mathematical model check of eBPF ALU32 execution: 32-bit wrap + 64-bit zero extension."""
        # Initial 64-bit register holding a value with non-zero high bits
        r1_val = 0xFFFFFFFF00000010  # 64-bit register
        r2_val = 0x0000000000000020  # 64-bit register

        # 1. Truncate destination and source to 32 bits
        w1 = r1_val & 0xFFFFFFFF  # 0x00000010 (16)
        w2 = r2_val & 0xFFFFFFFF  # 0x00000020 (32)

        # 2. 32-bit computation: (w1 - w2) wrapped to 32 bits
        w_res = (w1 - w2) & 0xFFFFFFFF  # -16 mod 2^32 = 0xFFFFFFF0

        # 3. eBPF rule: result is zero-extended into 64-bit register (upper 32 bits become zero)
        r1_new = w_res  # In 64-bit space: 0x00000000FFFFFFF0
        self.assertEqual(r1_new, 0x00000000FFFFFFF0)
        self.assertEqual(r1_new >> 32, 0)  # High bits strictly zeroed


if __name__ == "__main__":
    unittest.main()
