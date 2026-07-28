# Repository Naming Conventions

This document establishes the standardized naming scheme for all literature and indexes in the research workspace.

## 1. PDF Publications
All collected research papers must be cataloged under their respective venue subfolder in `papers/` and named using the following pattern:
```
YYYY_<Venue>_<ShortTitle>.pdf
```
* **Rules:**
  * `YYYY`: Year of publication.
  * `<Venue>`: Uppercased venue abbreviation (e.g. `USENIX`, `OSDI`, `ACM`, `arXiv`, `LF`).
  * `<ShortTitle>`: PascalCase short title without spaces.
* **Examples:**
  * `2021_arXiv_BPFContain.pdf`
  * `2023_USENIX_CrossContainerAttacks.pdf`

## 2. Markdown Summaries
Summaries in `summaries/` must follow the exact same file name as their corresponding PDF (matching capitalization and spelling) but with the `.md` extension:
```
YYYY_<Venue>_<ShortTitle>.md
```
* **Example:** `2024_OSDI_StateEmbedding.md`

## 3. Metadata Keys
* Keys in `references.bib` and individual `.bib` files must use the lowercase citation key format: `authorYearshorttitle` (e.g. `findlay2021bpfcontain`).