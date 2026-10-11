# IEEE Manuscript Draft

This directory contains the LaTeX manuscript for **Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**.

## Files

- `main.tex` — main IEEE conference-style manuscript.
- `extended_sections.tex` — formal model, cost analysis, algorithmic workflow, measurement interpretation, and deployment boundaries included by `main.tex`.
- `references.bib` — cited literature and technical documentation.
- `IEEEtran.cls` — bundled IEEEtran class file.

## Build

From this directory, run:

```bash
latexmk -pdf main.tex
```

Or, if `latexmk` is unavailable:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

The document uses IEEEtran's two-column conference layout, native typography, standard caption/table treatment, and a compact TikZ architecture/workflow illustration. `microtype` improves line fitting where supported, and `hyperref` adds unobtrusive links without colored boxes. The manuscript intentionally avoids manual margin changes, forced line spacing, and artificial font-size changes. Keep the target length around 10–13 pages by improving substantive technical explanation and figures, not by manipulating the template.

## Evidence boundary

The manuscript distinguishes:

- multi-tenant cloud/eBPF security as the broader application context;
- fine-grained eBPF policy verification as the technical problem;
- hybrid abstract analysis plus symbolic fallback as the evaluated contribution.

Quantitative claims are bounded to the recorded corpus, frozen verifier/policy, and execution environment:

- 50.0% is the abstract-discharge rate for the 24-program Phase 5 corpus.
- 45.53% is the reported E4 median end-to-end savings result; verify the aggregation against raw telemetry before submission.
- E2's path-scaling relationship is an empirical fit for the tested 1–64 path family, not a universal complexity result.
- E5 includes only observed reachable strata; the Phase 5 64-path stratum is not reported as an observed result.

## Before submission

1. Build the PDF and inspect all figures, table placement, overfull boxes, references, and page count.
2. Recompute all tables from raw experiment artifacts and confirm the E4 aggregation definition matches the reported 45.53% value.
3. Verify every bibliographic entry against the publisher or official project record.
4. Confirm author affiliation/contact details and the target venue's current page limit.
5. Keep the IEEE template settings intact unless the target venue explicitly requests a different format.
6. Cite sources for borrowed ideas, facts, and related systems. A larger bibliography does not itself prevent plagiarism; original wording, correct attribution, and quotation where needed do.
