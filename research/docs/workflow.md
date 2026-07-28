# Reading & Collection Workflow

This diagram outlines the sequential lifecycle of adding new research papers to this repository.

```
[New Paper Discovered]
        │
        ▼
[Perform First Pass Screen] (Meets Selection Criteria?)
        │
        ├── Yes ──> [Download PDF to papers/<venue>/]
        │           [Name file: YYYY_<Venue>_<ShortTitle>.pdf]
        │
        └── No ───> [Discard Paper]
        │
        ▼
[Extract Metadata] ──> [Append entry to metadata/papers.json & papers.csv]
        │
        ▼
[Generate Citation] ──> [Create metadata/bibtex/key.bib & append to references.bib]
        │
        ▼
[Draft Summary] ──> [Write summaries/YYYY_<Venue>_<ShortTitle>.md]
        │
        ▼
[Analyze Gaps] ──> [Update notes/research_gaps.md]
        │
        ▼
[Update Indexes] ──> [Re-sort chronology.md, citation_graph.md, indexes/index.md]
```