# Program sources and objects

Run `python3 research/experiments/split_bypass/scripts/prepare_corpus.py --policy PATH` from the repository root to materialize the deterministic C source fixtures here. Add `--compile` to compile them with the same clang target convention used by the existing corpus build script.

The generator records per-program compiler status, full command, stdout/stderr, source SHA-256, ELF SHA-256 when successful, and disassembly metrics when available. It refuses to overwrite an existing manifest. Compiler success is not equivalent to kernel verifier acceptance or reference policy compliance.

Do not hand-edit generated sources after recording the manifest. If a fixture changes, generate a new source commit and manifest. Do not commit compiled `.o` files from an undocumented host.
