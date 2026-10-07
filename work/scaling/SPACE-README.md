# Space Study

This is a separate resource campaign from the timing experiment.

## KRAKENGUARD

The runner discovers the running KRAKENGUARD container's cgroup-v2 path from its container PID, resets that cgroup's `memory.peak`, invokes exactly one verification request, and reads the resulting peak.

Reported values:

- `baseline_memory_current_bytes`
- `peak_kg_container_memory_bytes`
- `incremental_peak_kg_container_memory_bytes`

The Linux cgroup-v2 documentation defines `memory.peak` as a resettable maximum of memory usage for the cgroup and descendants. It therefore avoids periodic `docker stats` polling during the request. The measurement still covers the persistent KRAKENGUARD service state plus the request, so the incremental value is the preferred within-service resource metric. Do not compare it as though it were the memory of a standalone KLEE binary.

## Abstract analyzer

Each observation runs `work/abstract_worker.py` as a fresh process and records its `ru_maxrss`.

This intentionally measures the memory footprint of the deployed analyzer process, including interpreter/runtime/library overhead. It is suitable for comparing the analyzer with itself across scale and for establishing whether memory grows materially with program complexity.

## Hybrid

For a fast-path hybrid run only abstract RSS is present.

For a fallback run both metrics are present, but they are reported as separate resource domains. The campaign does not add host RSS and container cgroup memory into a synthetic “total memory” figure.

## Interpretation

Space scaling is descriptive unless the observed data supports a model. No `O(n)`, `O(p)`, or exponential class is asserted from regression alone.
