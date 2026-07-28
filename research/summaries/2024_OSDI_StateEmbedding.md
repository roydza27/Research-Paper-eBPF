# Paper Summary: Validating the eBPF Verifier via State Embedding

## Metadata
* **Title:** Validating the eBPF Verifier via State Embedding
* **Authors:** Hao Sun, Zhendong Su
* **Year:** 2024
* **Venue:** USENIX OSDI
* **URL:** https://www.usenix.org/conference/osdi24/presentation/sun-hao
* **Relevance Score:** 8.5/10
* **Tags:** eBPF, eBPF Verifier, Fuzzing, Linux, Security Verification

## Summary

### Research Problem
The Linux kernel relies completely on the eBPF verifier to filter out dangerous helper modifications, out-of-bounds pointer operations, and infinite loops. However, the verifier uses complex abstract interpretation routines (tracking ranges, sign bits, and alignment). Logic bugs in these routines result in incorrect safety declarations, leading to local privilege escalations.

### Motivation
Previous testing techniques (such as grammar fuzzing) struggled to test the correctness of the verifier's mathematical range updates because they only observed if the verifier accepted or rejected a program, rather than checking if the verifier's internal tracked states matched actual runtime values.

### Proposed Solution
The authors implement **State Embedding**, a testing paradigm that embeds assertions directly into generated BPF programs. The assertions test the verifier's internal range assumptions at verification time and runtime.

### Methodology
1. **Dynamic Program Generation:** Generates valid BPF instruction sequences.
2. **State-Checking Probe Injections:** Embeds comparison operations comparing registers with constant limits that test the exact boundaries tracked by the verifier (e.g. register sign, max/min bounds).
3. **Execution Analysis:** Feeds compiled bytecode to the verifier. A discrepancy between the verifier’s behavior (declaring a state impossible) and runtime execution (executing that state) flags a verifier logic bug.

### Experimental Setup
* Applied the state-embedding tool to test the Linux kernel verifier.
* Ran automated fuzzing sessions for several weeks on fresh mainline Linux kernels.

### Results
* Discovered **15 critical, previously unknown logic bugs** in the verifier.
* 10 bugs were fixed immediately by kernel developers.
* Discovered 2 exploitable privilege escalation bugs (CVE-2023-2163 and others).

### Limitations
* Only aids in testing/patching the verifier before kernel compilation; does not provide runtime isolation for systems running buggy kernels.
* Does not verify helper function behaviors.

### Future Work
* Extending state embedding to support verification loops and sub-register tracking models.