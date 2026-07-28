# Master's Research Progress Dashboard

This dashboard tracks critical project deliverables and metrics.

---

## 1. Metrics & Core Counters

| Metric | Count | Details |
| :--- | :--- | :--- |
| **Papers Downloaded** | 8 | All stored under `papers/` with venue categories |
| **Papers Read** | 8 | All 8 core articles fully analyzed |
| **Papers Summarized** | 8 | Matching summaries written to `summaries/` |
| **Research Gaps Identified** | 3 | Segmented in `notes/research_gaps.md` |
| **Ideas Generated** | 2 | Cached in `MEMORY.md` |
| **Prototype Code Status** | 5% | Aya framework verification tests initiated |
| **Thesis Writing Status** | 10% | Chapter 1 (Introduction) outline finalized |

---

## 2. Milestone Deliverables Checklist

* [x] **Project Repository Refactoring**
  * Fully standardized folder hierarchy aligned with systems research guidelines.
* [x] **Audit and Inconsistency Checks**
  * Generated first-stage audit report and restructured path names.
* [x] **Excluded Hardware-Assisted Materials**
  * Cleansed the library of all CPU, TEE, and SGX papers in accordance with supervisor directives.
* [x] **Academic Metadata Extraction**
  * Synchronized `papers.json`, `papers.csv`, and BibTeX records.
* [ ] **Verifier Logic Verification**
  * Validate OSDI '24 range check fuzzing behaviors on test beds.
* [ ] **LSM Hook Policy Implementation**
  * Code BPF maps namespaces bounds filters.
* [ ] **Experimental Performance Benchmarks**
  * Benchmark throughput latency impact of dynamic isolation.
* [ ] **Thesis Draft Completion**
  * Write Chapters 2-5 and prepare the defense deck.

---

## 3. Top 5 Prioritized Items

1. Review **BPFContain cgroups binding methodology** to structure the dynamic hook design.
2. Read **OSDI '24 State Embedding register tracks** to trace verifier mathematical logic boundaries.
3. Establish a standard Ubuntu VM workspace with BPFLSM modules loaded.
4. Draft Chapter 2 (Literature Review) abstract patterns.
5. Create a prototype benchmark setup using standard Apache Bench testing routines.
