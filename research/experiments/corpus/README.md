# Controlled eBPF Benchmark Corpus

The corpus is deliberately small and transparent. It is designed to establish scaling trends and policy precision, not to mimic the entire Linux eBPF ecosystem.

## Classes

- **A / minimal:** one hook, minimal control flow, zero or one helper/map interaction.
- **B / moderate:** branches, helpers and map accesses.
- **C / complex:** multiple branches, nested conditions, multiple maps/helpers and state-dependent behavior.
- **D / policy-sensitive:** programs deliberately exercising helper, map, memory and return-value policy dimensions.
- **E / adversarial:** safe policy-violation cases and verifier-stress cases. These are synthetic policy tests, not exploit payloads.

## Expected labels

`compliant` means the program is expected to satisfy the selected policy.

`violating` means the program intentionally exercises a policy rule that should be rejected.

`unsupported` means the baseline cannot express or analyze the case; this is an experimental result, not a security verdict.

`timeout` and `unknown` are never converted to safe/unsafe.

## Source policy

Programs are ordinary benchmark sources. No real-world exploit code is included. Each program should be compiled to eBPF object code using the toolchain available on the experimental host, then analyzed by the selected baseline without modifying the baseline implementation.