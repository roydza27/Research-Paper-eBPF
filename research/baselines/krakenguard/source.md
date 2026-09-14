# KRAKENGUARD Source

## Authoritative artifact

- Repository: `krakenguard-ebpf/krakenguard`
- Frozen commit: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- Paper: *KRAKENGUARD: Towards Fine-Grained eBPF Isolation*, NSDI 2026
- Official paper page: https://www.usenix.org/conference/nsdi26/presentation/patel
- Official source: https://github.com/krakenguard-ebpf/krakenguard

## Pipeline observed at the frozen commit

The project README describes the verification path as:

1. lift compiled eBPF bytecode to LLVM IR with `bpflifter`;
2. transform the IR to resolve helpers, maps and symbols;
3. generate verification harnesses with Jinja2 and symbolic inputs;
4. execute the harness with KLEE;
5. check memory access, helper usage, map permissions and return values against policy constraints.

The artifact also contains a daemon/client path for verification and optional kernel loading. The Phase 3 reproduction uses verification-only mode; loading is not required for the baseline cost experiment.

## Supported experiment entry points

The frozen artifact exposes `daemon/test_client.py` with:

```text
python3 daemon/test_client.py health
python3 daemon/test_client.py verify <object_file> <constraints_file> [config_file] [--debug]
python3 daemon/test_client.py cross-program <obj1> <obj2> <constraints> <program_config.yaml> <prog1_func> <prog2_func> [--debug]
```

`examples/daemon_submit_one_example.py` adds named targets and compilation automation. The first smoke target selected for this reproduction is `fw:test-object`, because it is a documented single-program example and does not require cross-program setup.

## Baseline integrity rule

No KRAKENGUARD source modifications are part of the baseline. Any instrumentation needed later must be kept outside the baseline logic and compared separately with uninstrumented runs.
