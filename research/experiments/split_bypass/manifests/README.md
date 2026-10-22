# Manifests

The generator writes `corpus-manifest.json` with stable program IDs, source hashes, compiler commands and statuses, ELF hashes where available, policy hashes, structural metrics, and reference-oracle provenance fields. Reference labels are null and oracle status is `not_run` until actual verifier evidence is recorded.

The generator refuses to overwrite an existing manifest. Archive the previous manifest and use a fresh branch/worktree or an explicitly versioned run directory before repeating generation.
