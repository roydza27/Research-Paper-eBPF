# Research Methodology

This document outlines the scientific methodology governing this Master's research project.

## 1. Domain Exploration
* Search for top-tier systems venues (USENIX ATC/Security, SOSP, OSDI, CCSW, NSDI) using targeted eBPF and runtime container confinement search queries.
* Screen papers using selection criteria.

## 2. Taxonomy Mapping
* Classify papers into core branches: Access Control, Isolation, Tracing/Observability, Verification.
* Synthesize findings into the central literature matrix database.

## 3. Vulnerability Analysis
* Study past verifier specifications, CVEs, and proof-of-concept container escapes.
* Map attack trees to identify current security enforcement deficiencies.

## 4. Solution Prototyping
* Design LSM-based eBPF policies using the Aya Rust framework to establish tenant isolation.