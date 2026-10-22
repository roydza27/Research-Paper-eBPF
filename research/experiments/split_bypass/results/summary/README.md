# Derived summaries

Run `scripts/analyze_runs.py` against the raw directory and write the summary to a new path. Summaries are derived artifacts and must identify the exact raw inputs and analysis-script commit in the accompanying run notes. The script refuses to overwrite its output.

No summary or performance result is present in this initial scaffold. Missing oracle verdicts remain missing; they are not inferred from source names or hypotheses.