# Research Manuscript (Submission-Format Revision)

This directory contains the expanded LaTeX manuscript for **Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**.

## Submission-format changes

- A4 paper, 12-point text, and 1.5 line spacing.
- Times New Roman when built with XeLaTeX/LuaLaTeX on a system where the font is installed; pdfLaTeX uses the metrically compatible newtx Times family.
- Author details include fields for the institutional email and ORCID; replace the placeholders before submission.
- Abstract revised to 100–150 words and followed by 5–10 keywords.
- Sections aligned with the supplied format: Introduction, Review of Literature, Research Methodology, Results / Findings, Discussion, Conclusion, Recommendations / Implications, Limitations of the Study, and References.
- Author–date citations and APA-oriented bibliography style via apacite.
- Technical detail, experimental protocols, formal model, workflow, cost model, research history, and validity discussions are retained in extended_sections.tex.

## Files

- main.tex — manuscript entry point, main narrative, tables, results, recommendations, and conclusion.
- extended_sections.tex — formal model, cost model, algorithmic workflow, measurement protocol, related-system context, threat model, implementation boundaries, research history, and reproducibility discussion.
- references.bib — bibliography database.
- main.pdf — generated manuscript PDF (must be rebuilt after source changes).
- main.docx — generated Microsoft Word document with embedded high-resolution figures, native equations, and bibliography.
- build_docx.py — automated build script for rendering TikZ figures and generating main.docx via Pandoc.
- figures/ — compiled high-resolution (300 DPI) figure assets used in the Word document.

## Build

### PDF

From this directory, use:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

This uses pdfLaTeX and the metrically compatible Times family. For actual Times New Roman, use XeLaTeX/LuaLaTeX on a machine with that font installed and adjust the build command accordingly.

### Word Document (.docx)

To generate or update the Word document (`main.docx`) from `main.tex`:

```bash
python3 build_docx.py
```

This renders all TikZ diagrams to 300 DPI images in `figures/`, inlines extended sections, resolves citations via Pandoc citeproc, converts mathematical formulas into native Word equations, and writes `main.docx` while leaving `main.pdf` intact.

## Evidence and submission checks

- E1 is an audited baseline with qualifications; E2 is described as a recorded controlled baseline.
- E3/E4/E5 performance values remain unverified until raw execution artifacts are recovered or the experiments are rerun and independently recomputed.
- The supplied submission guide specifies a maximum of 10 pages. The manuscript's technical content has intentionally not been deleted to force a page count; check the rendered PDF and agree any required content prioritization before submission.
- Verify every citation against the bibliography, replace author-detail placeholders, compile the PDF, inspect figure/table placement, and confirm the final page count before submission.
