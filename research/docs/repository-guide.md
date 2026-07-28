# Repository Maintenance Guide

This document acts as an operations manual for researchers structure-syncing the workspace.

## 1. Codebase Sync
* Ensure that whenever a new paper PDF is downloaded, the metadata JSON and CSV indexes are updated in lock-step.
* Run linter checks on Markdown tables and reference links.

## 2. Citations Check
* The file `references/references.bib` is the canonical bibliography database. Verify that all keys are lowercase and unique.
* Keep individual `.bib` files stored in `metadata/bibtex/` for simple package exports.