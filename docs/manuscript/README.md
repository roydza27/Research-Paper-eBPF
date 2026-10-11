# IEEE Manuscript Draft

This directory contains the manuscript for **Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**.

## Files

- `main.tex` — IEEE conference-style entry point, author block, abstract, baseline tables, evidence-status table, and conclusion.
- `extended_sections.tex` — formal model, cost model, hybrid workflow, research history, threat model, implementation boundaries, measurement lessons, and future-work constraints.
- `references.bib` — bibliography.
- `IEEEtran.cls` — IEEEtran document class.

## Build and review

Run from this directory:

```bash
latexmk -pdf main.tex
```

If `latexmk` is not installed:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

Then check the generated PDF with:

```bash
pdfinfo main.pdf | grep Pages
```

A build is not considered complete until the PDF has been visually inspected for figure/table placement, missing glyphs, unresolved references, overfull boxes, and bibliography errors. The target is 10–13 pages, but the actual page count must be measured after compilation; it is not asserted by this source-only review.

## Page styling

The manuscript uses the IEEEtran conference layout and preserves the class's page geometry, two-column structure, heading styles, and caption conventions. Styling improvements are deliberately restrained:

- `microtype` improves line fitting where supported.
- `hyperref` uses hidden link borders for a clean print-ready appearance.
- `booktabs` and a slightly more generous row height improve table readability.
- TikZ figures are source-native and scale with the document, avoiding rasterized diagram text.
- Paragraph emergency stretch reduces avoidable overfull lines without forcing manual line breaks.
- The bibliography uses the IEEE style.

Do not add manual margin changes, oversized fonts, arbitrary line spacing, or blank pages just to meet a page target. If the PDF is shorter than the target, add meaningful analysis, methodology, evidence, or figures. If it is longer, tighten repetition and improve figure/table placement rather than shrinking the type.

## Research evidence boundary

The paper distinguishes baseline findings from Phase 5 evaluation plans and reported-but-unaudited figures.

- E1 passed an independent data-integrity audit with qualifications. In particular, source-level branch intent did not always match compiled control flow, and some instrumentation fields were heuristic or mislabeled.
- E2's recorded controlled path family reports increasing time over 1–64 paths. Interpret this as a result for that synthetic family, not a universal complexity theorem.
- The abstract analyzer, 24-program corpus, fail-closed handling, and E3–E5 protocol are project artifacts.
- The final independent results audit did **not** accept E3, E4, or E5 as completed experiments because the required execution commit and raw result sets were unavailable in the audited repository state.
- The frequently repeated 50% discharge and 45.53% savings figures are therefore marked as unverified report values and are not presented as established findings in the revised manuscript.
- The Katran run terminated before a valid policy verdict was produced; it is an unsuccessful compatibility attempt, not a successful real-world benchmark.
- ProcessScope is described as supporting instrumentation, not as the central research contribution.

## Before submission

1. Compile and inspect the actual PDF; confirm it is 10–13 pages if that remains the venue requirement.
2. Verify every reference's title, authors, venue, year, and URL against its publisher or official project page.
3. Recover the immutable Phase 5 execution artifacts or rerun the approved matrix under the frozen protocol.
4. Recompute all E3/E4/E5 tables from raw telemetry and validate the paired aggregation definition before restoring any performance claim.
5. Preserve the distinction between a protocol specifying 432 executions and evidence showing that 432 executions completed.
6. Add institutional details only after confirming their exact official form and the target venue's author requirements.
7. Follow the target venue's current page limit and template instructions; IEEE conference layouts commonly impose limits that may be shorter than a 10–13 page thesis-style manuscript.

A longer bibliography helps readers trace the work, but references do not make text non-plagiarized by themselves. Attribute ideas and claims precisely, quote only when needed, and write the analysis in the author's own technical voice.
