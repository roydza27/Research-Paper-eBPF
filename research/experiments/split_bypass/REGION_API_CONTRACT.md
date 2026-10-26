# Region-Level Verification API Contract

> **Document Status:** Active Specification  
> **Date:** 2026-10-22  
> **Target Architecture:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
> **Repository:** `Research-Paper-eBPF` | **Reference Implementation:** `research/experiments/split_bypass/scripts/region_contract.py`

---

## 1. Purpose and Soundness Boundary

The objective of the hybrid verification architecture is to decompose large eBPF programs into verified regions, discharging simple regions through low-cost abstract interpretation and routing only complex, unresolved regions to heavy symbolic execution:

$$\text{Compiled eBPF ELF} \longrightarrow \text{CFG Extraction} \longrightarrow \text{Region Abstract Interpretation} \longrightarrow \text{Scoped Symbolic Fallback} \longrightarrow \text{Sound Program Verdict Composition}$$

### Foundational Soundness Principle
**A region cannot be analyzed soundly in isolation using arbitrary or default input states.**  
Unlike pure functional units, eBPF basic blocks depend strictly on the register values, stack contents, memory allocations, and path conditions established by predecessor execution paths. Therefore:
1. Region verification is conditioned entirely on explicit, validated **incoming abstract states** and **entry path constraints**.
2. A program-level `SAFE` verdict requires proof that **all reachable regions are compliant** under incoming states soundly propagated across the control-flow graph.
3. Whole-program symbolic verification must never be mislabeled as region-scoped verification.

---

## 2. Section A: Region Identity and Boundaries

### A.1 Entity Definitions
To prevent architectural ambiguity, the following structural tiers are strictly distinguished:

| Level | Definition | Mathematical Invariants |
|---|---|---|
| **Basic Block ($B_i$)** | A maximal sequence of consecutive eBPF instructions with a single entry and single exit. | Exactly one entry instruction ($pc_{start}$); at most one branch, jump, or exit at terminator ($pc_{end}$). No internal branch targets. |
| **Multi-Block Region ($R_k$)** | A connected subgraph of basic blocks with a single designated entry block ($B_{entry} \in R_k$) and one or more explicit exit blocks ($E_k \subseteq R_k$). | $B_{entry}$ dominates all blocks in $R_k$ for forward edges. All internal control flow originates within $R_k$. |
| **Function / Program ($P$)** | The complete compiled ELF bytecode section containing the entry point (PC 0) and all transitively reachable basic blocks terminating at `BPF_EXIT`. | Contains entry basic block $B_0$ with global program entry assumptions ($r10 = \text{const}(0)$, $r1 = \text{ctx}$). |

### A.2 Structural Schema (`RegionBoundary`)
Every region must be identifiable by an immutable boundary definition:

```python
class RegionBoundary:
    region_id: str                      # Stable, deterministic identifier (e.g. "R_0x00_0x18")
    entry_block_id: str                 # Dominating entry basic block ID (e.g. "bb_0")
    blocks: tuple[str, ...]             # Constituent basic block IDs
    predecessors: tuple[str, ...]       # Predecessor region or block IDs entering entry_block_id
    successors: tuple[str, ...]         # Successor region or block IDs leaving exit_blocks
    exit_blocks: tuple[str, ...]        # Terminal basic blocks within the region
    scope: ScopeLevel                   # BASIC_BLOCK, MULTI_BLOCK_REGION, or WHOLE_PROGRAM
    has_backedge: bool                  # True if region contains an internal loop or back-edge
    is_function_boundary: bool          # True if region represents a complete function
```

### A.3 Structural Invariants
1. **Non-Empty Constituents:** $\text{blocks} \neq \emptyset$.
2. **Entry Membership:** $\text{entry\_block\_id} \in \text{blocks}$.
3. **Exit Membership:** $\forall eb \in \text{exit\_blocks}, eb \in \text{blocks}$.
4. **Scope Integrity:** If $\text{scope} == \text{BASIC\_BLOCK}$, then $|\text{blocks}| = 1$. Multiple blocks strictly require $\text{scope} == \text{MULTI\_BLOCK\_REGION}$ or $\text{WHOLE\_PROGRAM}$.
5. **Back-Edges & Loops:** Regions containing internal cycle edges ($\text{has\_backedge} = \text{True}$) must either establish an inductive loop invariant or conservatively return `UNKNOWN`.

---

## 3. Section B: Incoming Abstract State Contract

### B.1 Interface Specification
Region analysis is invoked through the canonical interface:

$$\text{analyze\_region}(P, R, \sigma_{in}, \Pi, \Phi_{path}) \longrightarrow \text{RegionResult}$$

Where:
- $P$: The compiled eBPF object context and relocation mappings.
- $R$: The target `RegionBoundary`.
- $\sigma_{in}$: The `IncomingAbstractState` at region entry.
- $\Pi$: The security policy (allowed helpers, return bounds, memory intervals).
- $\Phi_{path}$: Path predicates accumulated along the execution history reaching $R$.

### B.2 Abstract Register Domain
Abstract values $\hat{v} \in \mathcal{V}$ are defined over a bounded lattice:

$$\hat{v} ::= \bot \mid \text{const}(k) \mid \text{interval}([l, u]) \mid \text{symbolic}(id) \mid \top \text{ (unknown)}$$

The `AbstractRegisterState` maps registers $r0$ through $r10$ to $\mathcal{V}$:
- $r10$: Read-only stack frame pointer, initialized to $\text{const}(0)$ at program entry.
- $r1$: Initialized to symbolic packet/context pointer $\text{symbolic}(\text{"ctx"})$ at program entry.
- $r0, r2\dots r9$: Initialized to $\top$ (unknown) at program entry.

### B.3 Multi-Predecessor State Join ($\sqcup$)
When a region has multiple incoming execution paths (e.g. at join nodes following conditional branches), the incoming state must be computed using the sound least upper bound:

$$\sigma_{in} = \bigsqcup_{p \in \text{preds}(R)} \sigma_{exit}(p)$$

Join rules for register values:
$$\hat{v}_1 \sqcup \hat{v}_2 = \begin{cases}
\hat{v}_1 & \text{if } \hat{v}_1 = \hat{v}_2 \\
\text{interval}([\min(k_1, k_2), \max(k_1, k_2)]) & \text{if } \hat{v}_1 = \text{const}(k_1) \land \hat{v}_2 = \text{const}(k_2) \\
\text{interval}([\min(l_1, l_2), \max(u_1, u_2)]) & \text{if intervals} \\
\top & \text{otherwise (sound loss of precision)}
\end{cases}$$

### B.4 Invariant: Prohibition of Default Safe States
- **Forbidden:** Initializing an intermediate region with default safe assumptions (such as assuming registers contain zeroes or empty stack allocations).
- **Rule:** If $\sigma_{in}$ is missing, unmodeled, or uncomputable, the analyzer **must fail closed** and return `UNKNOWN`.

---

## 4. Section C: Region Result Contract

### C.1 Typed Result Schema (`RegionResult`)
Every region analysis evaluation emits a validated `RegionResult`:

```python
class RegionResult:
    region_id: str                      # Identifier of analyzed region
    verdict: RegionVerdict              # SAFE, VIOLATION, or UNKNOWN
    scope: ScopeLevel                   # Scope of the analysis (BASIC_BLOCK, MULTI_BLOCK, WHOLE_PROGRAM)
    analysis_method: AnalysisMethod     # ABSTRACT_INTERPRETATION, SYMBOLIC_EXECUTION, HYBRID_COMPOSITE
    entry_assumptions: IncomingAbstractState  # Provenance of assumptions under which verdict holds
    exit_states: Mapping[str, Any] | None    # Abstract states at each exit block (for successor propagation)
    violating_path_evidence: str | None      # Witness or counterexample trace if VIOLATION
    unresolved_reason: str | None            # Mandatory explanation if UNKNOWN
    backend_executor_scope: ScopeLevel       # Scope of the underlying tool that executed the analysis
```

### C.2 Semantic Veracity Invariants
1. **Scope Truthfulness:** A region result must not claim a fine-grained scope if the underlying tool executed at whole-program scope:
   $$\text{backend\_executor\_scope} = \text{WHOLE\_PROGRAM} \implies \text{scope} = \text{WHOLE\_PROGRAM}$$
2. **Fail-Closed Accounting:**
   - Any runtime exception, unsupported bytecode instruction (e.g. unmodeled packet store, ALU32 mismatch), or analyzer timeout **must yield `UNKNOWN`**.
   - `UNKNOWN` verdicts must provide a non-empty `unresolved_reason`.
   - A result marked `SAFE` must have `unresolved_reason = None`.
3. **Local vs. Global Validity:**
   - A `RegionResult(verdict=SAFE)` proves only that the instructions within region $R$ do not violate policy $\Pi$ **under the specific assumptions $\sigma_{in}$ and $\Phi_{path}$**.
   - It does **not** assert that the entire eBPF program is safe.

---

## 5. Section D: Symbolic Fallback Contract

When abstract interpretation of a region $R_k$ returns `UNKNOWN`, the orchestration engine invokes symbolic verification fallback.

### D.1 Required Region-Level Symbolic Fallback Interface
A genuine region-level symbolic verifier must accept:
1. The extracted region bytecode slice (or basic block sequence with entry PC and exit PCs).
2. The incoming symbolic state $\sigma_{in}$ (symbolic variables for unconstrained registers and concrete values for known registers).
3. The entry path constraints $\Phi_{path}$ encoded as solver assertions (e.g. in SMT-LIB2 / KQuery format).
4. The policy assertions $\Pi$.

### D.2 Baseline Reality & Compatibility Boundary
- **Inspected Interface:** The baseline symbolic verifier (KRAKENGUARD daemon at `research/baselines/krakenguard/artifact`) accepts **only compiled ELF object files**:
  ```python
  client.verify(object_file=args.object, constraints_file=args.policy)
  ```
- **Architectural Consequence:** KRAKENGUARD has **no API** to verify sliced basic blocks, arbitrary entry PCs, or custom incoming register environments.
- **Contract Rule:**
  - Invoking KRAKENGUARD as fallback on an unresolved region executes at **whole-program scope**.
  - The orchestration runner must record `backend_executor_scope: WHOLE_PROGRAM` and `scope: WHOLE_PROGRAM`.
  - Claiming that KRAKENGUARD performs block-level fallback is scientifically false and rejected by contract validation.

---

## 6. Section E: Composition and Control-Flow Correctness

The `ProgramVerdictComposer` aggregates individual region results into the final program verdict:

$$\text{compose}(\{ \text{RegionResult}_k \}, \text{ReachableRegions}) \longrightarrow \text{OverallProgramVerdict}$$

```
                           CONTROL FLOW COMPOSITION RULES
                           
  All Reachable Regions Safe?                 Any Reachable Region Violated?
               |                                            |
               v                                            v
     [ Check Incoming States ]                     [ Confirmed Reachable? ]
      All Joins Sound & Valid?                              |
         /             \                                    v
       YES              NO                          OVERALL VIOLATION
        |                |                          (Early Termination)
        v                v
   OVERALL SAFE     OVERALL UNKNOWN
                     (Fail Closed)
```

### E.1 Composition Invariants
1. **Sound Program `SAFE`:**
   A program is proven `SAFE` if and only if:
   $$\forall R_i \in \text{ReachableRegions}: \text{verdict}(R_i) = \text{SAFE} \quad \land \quad \forall R_i, \sigma_{in}(R_i) \sqsupseteq \bigsqcup_{p \in \text{preds}(R_i)} \sigma_{exit}(p)$$
   If any reachable region is `UNKNOWN` or unanalyzed, the whole-program verdict **must be `UNKNOWN`**.
2. **Sound Early Termination on `VIOLATION`:**
   If any reachable region $R_v \in \text{ReachableRegions}$ establishes a verified policy violation under valid reachability constraints:
   $$\text{verdict}(R_v) = \text{VIOLATION} \implies \text{OverallVerdict} = \text{VIOLATION}$$
   The orchestrator may terminate immediately without analyzing remaining unexplored paths.
3. **Rejection of Unsound Independent Region Discharges:**
   It is strictly unsound to mark a program safe merely because every basic block in isolation contains safe instructions, if the incoming assumptions between blocks are incompatible or unverified.

---

## 7. Section F: Implementation Readiness Matrix

Every major architectural capability is classified below based on inspected codebase evidence:

| Capability | Status | Implementation Evidence (File & Symbol) | Limitations / Gaps |
|---|:---:|---|---|
| **CFG Extraction** | `EXISTS` | [`research/experiments/scripts/split_analyze_bypass.py:extract_cfg`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/scripts/split_analyze_bypass.py#L41) | Extracts block PCs, predecessors, successors, and reverse-postorder. Annotates block verdicts as `metadata_only`. |
| **Region Boundary Modeling** | `EXISTS` | [`research/experiments/split_bypass/scripts/region_contract.py:RegionBoundary`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py#L95) | Validates entry, constituents, exit blocks, cycle flags, and scope levels. Tested in `test_region_contract.py`. |
| **Abstract Register Domain** | `EXISTS` | [`research/analyzer/abstract_policy_analyzer.py:AbstractValue`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/analyzer/abstract_policy_analyzer.py#L31) | Supports const, symbolic, unknown. Register dictionary `r0`–`r10`. |
| **Incoming State Modeling** | `EXISTS` | [`research/experiments/split_bypass/scripts/region_contract.py:IncomingAbstractState`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py#L125) | Explicit register, stack, and path constraint representations. Enforces non-default entry assumptions. |
| **State Join Operator ($\sqcup$)** | `PARTIAL` | [`research/experiments/split_bypass/scripts/region_contract.py:AbstractValue.join`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py#L48) | Implemented for const/interval/unknown in contract module. Not yet wired into `AbstractPolicyAnalyzer.analyze()`. |
| **Region Abstract Analysis** | `NOT_IMPLEMENTED` | *None* | `AbstractPolicyAnalyzer.analyze()` evaluates whole program from PC 0. Has no `analyze_region(R, state)` API. |
| **Loop / Invariant Handling** | `NOT_IMPLEMENTED` | [`research/analyzer/abstract_policy_analyzer.py:278`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/analyzer/abstract_policy_analyzer.py#L278) | Abstained: detects visited PC and immediately emits conservative `UNKNOWN: loop/revisit`. No widening or fixpoints. |
| **Whole-Program Fallback** | `EXISTS` | [`research/experiments/scripts/split_analyze_bypass.py:_symbolic_worker`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/scripts/split_analyze_bypass.py#L168) | Successfully executes frozen KRAKENGUARD daemon on full ELF objects when abstract verifier returns `UNKNOWN`. |
| **Scoped Region Fallback** | `BLOCKED` | [`research/baselines/krakenguard/artifact/daemon`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/baselines/krakenguard/artifact/daemon) | KRAKENGUARD accepts only full ELF binaries; lifter has no interface to verify sliced basic blocks or custom entry registers. |
| **Lifter Type Compatibility** | `BLOCKED` | [`lifting_tools/generateIR.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/baselines/krakenguard/artifact/lifting_tools/generateIR.py) | `bpflifter_cli` emits LLVM pointer type mismatches on ALU32 sub-registers (`load i32, i64* %r1`), crashing `opt` on medium fixtures. |
| **Sound Verdict Composition** | `EXISTS` | [`research/experiments/split_bypass/scripts/region_contract.py:ProgramVerdictComposer`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py#L175) | Verified early-exit on violation, fail-closed on unreachable/unknown, all-safe requirement in `test_region_contract.py`. |
| **Provenance Logging** | `EXISTS` | [`research/experiments/split_bypass/scripts/run_smoke.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/run_smoke.py) | Captures 16 schema fields, tool versions, Git blobs, SHA256 manifest hashes, and wall-clock latencies. |

---

## 8. Summary & Road to Implementation

With the API contract formalized and contract tests passing, the requirements for subsequent development tasks are established:
1. **Task 5 (LLVM Lifter Remediation):** Patch or containerize the `bpflifter_cli` pipeline so symbolic fallback can process sub-register arithmetic and join blocks without crashing `opt`.
2. **Task 6 (Region Analyzer Implementation):** Refactor `AbstractPolicyAnalyzer` to expose `analyze_region(R, incoming_state)` accepting an explicit entry PC, incoming register environment, and propagating exit states.
3. **Task 7 (Controlled Evaluation Notebook):** Render the comparative evaluation visualizer over validated corpus benchmark records.
