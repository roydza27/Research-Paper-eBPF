#!/usr/bin/env python3
"""Region-level verification API contract and typed definitions.

Defines the mathematical and data-structure boundary for region-level verification,
including region boundaries, incoming abstract states, typed results, and sound
composition rules. Prevents mislabeling whole-program fallback as region-scoped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class RegionVerdict(str, Enum):
    SAFE = "SAFE"
    VIOLATION = "VIOLATION"
    UNKNOWN = "UNKNOWN"


class ScopeLevel(str, Enum):
    BASIC_BLOCK = "BASIC_BLOCK"
    MULTI_BLOCK_REGION = "MULTI_BLOCK_REGION"
    WHOLE_PROGRAM = "WHOLE_PROGRAM"


class AnalysisMethod(str, Enum):
    ABSTRACT_INTERPRETATION = "ABSTRACT_INTERPRETATION"
    SYMBOLIC_EXECUTION = "SYMBOLIC_EXECUTION"
    HYBRID_COMPOSITE = "HYBRID_COMPOSITE"


@dataclass(frozen=True)
class AbstractValue:
    kind: str  # "const", "symbolic", "interval", "unknown"
    value: Any = None

    @classmethod
    def const(cls, v: int) -> AbstractValue:
        return cls("const", int(v))

    @classmethod
    def symbolic(cls, name: str = "symbolic") -> AbstractValue:
        return cls("symbolic", str(name))

    @classmethod
    def unknown(cls) -> AbstractValue:
        return cls("unknown", None)

    @classmethod
    def interval(cls, low: int, high: int) -> AbstractValue:
        if low > high:
            raise ValueError(f"Invalid interval: low ({low}) > high ({high})")
        return cls("interval", (low, high))

    def is_const(self) -> bool:
        return self.kind == "const"

    def is_unknown(self) -> bool:
        return self.kind == "unknown"

    def join(self, other: AbstractValue) -> AbstractValue:
        """Sound least upper bound (join) operation between two abstract values."""
        if self == other:
            return self
        if self.is_unknown() or other.is_unknown():
            return AbstractValue.unknown()
        if self.is_const() and other.is_const():
            if self.value == other.value:
                return self
            # Fallback to bounded interval or unknown
            low = min(self.value, other.value)
            high = max(self.value, other.value)
            return AbstractValue.interval(low, high)
        if self.kind == "interval" and other.is_const():
            low = min(self.value[0], other.value)
            high = max(self.value[1], other.value)
            return AbstractValue.interval(low, high)
        if other.kind == "interval" and self.is_const():
            low = min(other.value[0], self.value)
            high = max(other.value[1], self.value)
            return AbstractValue.interval(low, high)
        if self.kind == "interval" and other.kind == "interval":
            low = min(self.value[0], other.value[0])
            high = max(self.value[1], other.value[1])
            return AbstractValue.interval(low, high)
        return AbstractValue.unknown()


@dataclass(frozen=True)
class AbstractRegisterState:
    registers: Mapping[str, AbstractValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.registers:
            raise ValueError("AbstractRegisterState must have explicit register mappings")
        for reg in self.registers:
            if not (reg.startswith("r") and reg[1:].isdigit() and 0 <= int(reg[1:]) <= 10):
                raise ValueError(f"Invalid register identifier: {reg}")

    @classmethod
    def default_entry(cls) -> AbstractRegisterState:
        regs = {f"r{i}": AbstractValue.unknown() for i in range(10)}
        regs["r10"] = AbstractValue.const(0)  # r10 is frame pointer
        return cls(registers=regs)

    def get(self, reg: str) -> AbstractValue:
        return self.registers.get(reg, AbstractValue.unknown())

    def join(self, other: AbstractRegisterState) -> AbstractRegisterState:
        """Sound join across all registers."""
        all_keys = set(self.registers.keys()) | set(other.registers.keys())
        joined = {}
        for k in all_keys:
            v1 = self.registers.get(k, AbstractValue.unknown())
            v2 = other.registers.get(k, AbstractValue.unknown())
            joined[k] = v1.join(v2)
        return AbstractRegisterState(registers=joined)


@dataclass(frozen=True)
class RegionBoundary:
    region_id: str
    entry_block_id: str
    blocks: tuple[str, ...]
    predecessors: tuple[str, ...] = field(default_factory=tuple)
    successors: tuple[str, ...] = field(default_factory=tuple)
    exit_blocks: tuple[str, ...] = field(default_factory=tuple)
    scope: ScopeLevel = ScopeLevel.BASIC_BLOCK
    has_backedge: bool = False
    is_function_boundary: bool = False

    def __post_init__(self) -> None:
        if not self.region_id or not self.region_id.strip():
            raise ValueError("RegionBoundary requires a non-empty region_id")
        if not self.blocks:
            raise ValueError(f"Region {self.region_id} must have at least one basic block")
        if self.entry_block_id not in self.blocks:
            raise ValueError(
                f"Entry block '{self.entry_block_id}' must belong to constituent blocks in region {self.region_id}"
            )
        for eb in self.exit_blocks:
            if eb not in self.blocks:
                raise ValueError(
                    f"Exit block '{eb}' must belong to constituent blocks in region {self.region_id}"
                )
        if self.scope == ScopeLevel.BASIC_BLOCK and len(self.blocks) > 1:
            raise ValueError(
                f"Scope BASIC_BLOCK cannot contain multiple blocks ({len(self.blocks)} blocks found)"
            )


@dataclass(frozen=True)
class IncomingAbstractState:
    registers: AbstractRegisterState
    stack_assumptions: Mapping[str, Any] = field(default_factory=dict)
    memory_assumptions: Mapping[str, Any] = field(default_factory=dict)
    path_constraints: tuple[str, ...] = field(default_factory=tuple)
    is_explicit: bool = True

    def __post_init__(self) -> None:
        if not self.is_explicit:
            raise ValueError("Incoming state cannot be uninitialized or implicit")
        if self.registers is None:
            raise ValueError("Incoming state must contain non-null registers")


@dataclass(frozen=True)
class RegionResult:
    region_id: str
    verdict: RegionVerdict
    scope: ScopeLevel
    analysis_method: AnalysisMethod
    entry_assumptions: IncomingAbstractState
    exit_states: Mapping[str, Any] | None = None
    violating_path_evidence: str | None = None
    unresolved_reason: str | None = None
    backend_executor_scope: ScopeLevel = ScopeLevel.BASIC_BLOCK

    def __post_init__(self) -> None:
        if not self.region_id:
            raise ValueError("RegionResult requires a non-empty region_id")
        if not self.entry_assumptions or not isinstance(self.entry_assumptions, IncomingAbstractState):
            raise ValueError("RegionResult must have explicit IncomingAbstractState entry assumptions")

        # Contract Rule: Whole-program fallback cannot be mislabeled as region-scoped
        if self.backend_executor_scope == ScopeLevel.WHOLE_PROGRAM and self.scope != ScopeLevel.WHOLE_PROGRAM:
            raise ValueError(
                f"Whole-program execution backend cannot emit region-scoped verdict ({self.scope.value})"
            )

        # Contract Rule: Fail-closed handling for UNKNOWN verdicts
        if self.verdict == RegionVerdict.UNKNOWN and not self.unresolved_reason:
            raise ValueError("UNKNOWN verdict requires a documented unresolved_reason")

        # Contract Rule: SAFE requires that it does not carry an unresolved reason
        if self.verdict == RegionVerdict.SAFE and self.unresolved_reason:
            raise ValueError(
                f"Contradictory result: verdict is SAFE but carries unresolved_reason: '{self.unresolved_reason}'"
            )


@dataclass(frozen=True)
class RegionSymbolicRequest:
    """Formal contract request for state-aware, region-scoped symbolic fallback."""
    region_id: str
    scope: ScopeLevel
    instructions: tuple[Any, ...]
    incoming_state: IncomingAbstractState
    policy: Mapping[str, Any]
    entry_pc: int
    exit_pcs: tuple[int, ...]
    timeout_seconds: int = 30

    def __post_init__(self):
        if self.scope == ScopeLevel.WHOLE_PROGRAM:
            raise ValueError("RegionSymbolicRequest cannot have WHOLE_PROGRAM scope")
        if not self.instructions:
            raise ValueError("RegionSymbolicRequest instructions cannot be empty")
        if not self.incoming_state.is_explicit:
            raise ValueError("RegionSymbolicRequest requires an explicit incoming abstract state")


@dataclass(frozen=True)
class RegionSymbolicResponse:
    """Formal contract response from state-aware, region-scoped symbolic fallback."""
    region_id: str
    verdict: RegionVerdict
    scope: ScopeLevel
    backend_executor_scope: ScopeLevel
    execution_time_ms: float
    paths_explored: int
    unresolved_reason: str | None = None
    witness_trace: str | None = None
    is_genuinely_region_scoped: bool = True
    exit_states: Mapping[str, IncomingAbstractState] | None = None

    def __post_init__(self):
        if self.is_genuinely_region_scoped and self.backend_executor_scope == ScopeLevel.WHOLE_PROGRAM:
            raise ValueError(
                "Scope veracity violation: is_genuinely_region_scoped cannot be True "
                "when backend_executor_scope is WHOLE_PROGRAM"
            )
        if self.verdict == RegionVerdict.UNKNOWN and not self.unresolved_reason:
            raise ValueError("UNKNOWN response requires an unresolved_reason")
        if self.verdict == RegionVerdict.SAFE and self.unresolved_reason:
            raise ValueError("SAFE response cannot carry an unresolved_reason")


class ProgramVerdictComposer:
    """Soundly composes region results into a whole-program verdict."""

    @staticmethod
    def compose(
        results: Sequence[RegionResult],
        reachable_region_ids: Sequence[str],
    ) -> dict[str, Any]:
        if not results:
            raise ValueError("Cannot compose verdict from empty results")
        if not reachable_region_ids:
            raise ValueError("Cannot compose verdict without reachable region IDs")

        results_by_id = {r.region_id: r for r in results}
        missing_regions = [rid for rid in reachable_region_ids if rid not in results_by_id]
        if missing_regions:
            return {
                "overall_verdict": RegionVerdict.UNKNOWN.value,
                "disposition": "unresolved",
                "reason": f"Missing results for reachable regions: {missing_regions}",
                "soundly_discharged": False,
                "violating_region": None,
            }

        # 1. Early Termination on Confirmed Reachable Violation
        for rid in reachable_region_ids:
            res = results_by_id[rid]
            if res.verdict == RegionVerdict.VIOLATION:
                return {
                    "overall_verdict": RegionVerdict.VIOLATION.value,
                    "disposition": "violation",
                    "reason": f"Confirmed reachable violation in region '{rid}'",
                    "soundly_discharged": True,
                    "violating_region": rid,
                    "violating_evidence": res.violating_path_evidence,
                }

        # 2. Check for Unresolved / Unknown Reachable Regions
        unresolved = [
            rid for rid in reachable_region_ids
            if results_by_id[rid].verdict == RegionVerdict.UNKNOWN
        ]
        if unresolved:
            reasons = [results_by_id[rid].unresolved_reason for rid in unresolved]
            return {
                "overall_verdict": RegionVerdict.UNKNOWN.value,
                "disposition": "unresolved",
                "reason": f"Reachable regions unresolved: {dict(zip(unresolved, reasons))}",
                "soundly_discharged": False,
                "violating_region": None,
            }

        # 3. Sound SAFE: All reachable regions proven SAFE under explicit assumptions
        all_safe = all(results_by_id[rid].verdict == RegionVerdict.SAFE for rid in reachable_region_ids)
        if all_safe:
            return {
                "overall_verdict": RegionVerdict.SAFE.value,
                "disposition": "pass",
                "reason": f"All {len(reachable_region_ids)} reachable regions proven compliant under valid assumptions",
                "soundly_discharged": True,
                "violating_region": None,
            }

        return {
            "overall_verdict": RegionVerdict.UNKNOWN.value,
            "disposition": "unresolved",
            "reason": "Mixed or unverified reachable state",
            "soundly_discharged": False,
            "violating_region": None,
        }
