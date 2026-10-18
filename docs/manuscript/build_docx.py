#!/usr/bin/env python3
"""
build_docx.py - Convert LaTeX manuscript (main.tex) into a Microsoft Word (.docx) document.

This script:
1. Inlines extended_sections.tex into main.tex.
2. Extracts and compiles all 5 TikZ diagrams to high-resolution (300 DPI) PNG images in docs/manuscript/figures/.
3. Replaces TikZ blocks with \\includegraphics references.
4. Invokes pandoc with citeproc and references.bib to generate docs/manuscript/main.docx.
5. Preserves main.pdf untouched.
"""

import os
import sys
import re
import tempfile
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MANUSCRIPT_DIR = SCRIPT_DIR
FIGURES_DIR = MANUSCRIPT_DIR / "figures"
OUTPUT_DOCX = MANUSCRIPT_DIR / "main.docx"

TIKZ_PREAMBLE = r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{tikz}
\usepackage{xcolor}
\usetikzlibrary{arrows.meta,positioning,shapes.geometric}
\begin{document}
"""

TIKZ_POSTAMBLE = r"""
\end{document}
"""

def render_tikz_to_png(tikz_code: str, name: str, output_dir: Path, temp_dir: Path) -> Path:
    """Compile TikZ code to a high-resolution PNG image."""
    tex_path = temp_dir / f"{name}.tex"
    pdf_path = temp_dir / f"{name}.pdf"
    png_prefix = output_dir / name
    final_png = output_dir / f"{name}.png"

    with open(tex_path, "w", encoding="utf-8") as f:
        f.write(TIKZ_PREAMBLE + tikz_code + TIKZ_POSTAMBLE)

    # Compile with pdflatex
    res = subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", f"-output-directory={temp_dir}", str(tex_path)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"Error compiling TikZ figure {name}:", file=sys.stderr)
        print(res.stdout[-600:], file=sys.stderr)
        sys.exit(1)

    # Render PDF to 300 DPI PNG using pdftoppm
    subprocess.run(
        ["pdftoppm", "-png", "-r", "300", str(pdf_path), str(png_prefix)],
        check=True,
        capture_output=True,
    )

    # pdftoppm appends -1.png for single-page documents
    generated_png = output_dir / f"{name}-1.png"
    if generated_png.exists():
        if final_png.exists():
            final_png.unlink()
        generated_png.rename(final_png)

    return final_png

def build_docx():
    main_tex_path = MANUSCRIPT_DIR / "main.tex"
    extended_tex_path = MANUSCRIPT_DIR / "extended_sections.tex"
    bib_path = MANUSCRIPT_DIR / "references.bib"

    if not main_tex_path.exists():
        print(f"Error: {main_tex_path} not found.", file=sys.stderr)
        sys.exit(1)

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    print("Reading manuscript source files...")
    with open(main_tex_path, "r", encoding="utf-8") as f:
        main_content = f.read()

    with open(extended_tex_path, "r", encoding="utf-8") as f:
        extended_content = f.read()

    # Step 1: Inline extended_sections.tex
    combined_content = re.sub(
        r"\\input\{extended_sections\}",
        lambda _: extended_content,
        main_content,
    )

    tikz_pattern = re.compile(r"(\\begin\{tikzpicture\}.*?\\end\{tikzpicture\})", re.DOTALL)

    figure_names = [
        "fig1_architecture",
        "fig2_e1_time",
        "fig3_e2_scaling",
        "fig4_workflow",
        "fig5_research_evolution",
    ]

    print(f"Rendering TikZ diagrams to high-resolution PNGs (300 DPI) in {FIGURES_DIR}...")
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        fig_idx = [0]

        def replace_with_image(match):
            idx = fig_idx[0]
            fig_idx[0] += 1
            name = figure_names[idx] if idx < len(figure_names) else f"fig_{idx+1}"
            print(f"  Rendering [{idx+1}/5] {name}...")
            png_path = render_tikz_to_png(match.group(1), name, FIGURES_DIR, temp_dir)
            rel_path = png_path.relative_to(MANUSCRIPT_DIR)
            return f"\\includegraphics[width=0.95\\textwidth]{{{rel_path.as_posix()}}}"

        preprocessed_tex = tikz_pattern.sub(replace_with_image, combined_content)

        preprocessed_tex_path = temp_dir / "combined_manuscript.tex"
        with open(preprocessed_tex_path, "w", encoding="utf-8") as f:
            f.write(preprocessed_tex)

        print(f"Converting preprocessed LaTeX to Word document: {OUTPUT_DOCX}...")
        pandoc_cmd = [
            "pandoc",
            str(preprocessed_tex_path),
            "-o", str(OUTPUT_DOCX),
            f"--resource-path={MANUSCRIPT_DIR}",
            "--citeproc",
            f"--bibliography={bib_path}",
            "-M", "reference-section-title=References",
        ]

        res = subprocess.run(pandoc_cmd, cwd=str(MANUSCRIPT_DIR), capture_output=True, text=True)
        if res.returncode != 0:
            print("Pandoc conversion failed:", file=sys.stderr)
            print(res.stderr, file=sys.stderr)
            sys.exit(1)

    docx_size = OUTPUT_DOCX.stat().st_size
    print(f"Successfully generated {OUTPUT_DOCX.name} ({docx_size:,} bytes).")
    print(f"PDF manuscript ({MANUSCRIPT_DIR / 'main.pdf'}) was left untouched.")

if __name__ == "__main__":
    build_docx()
