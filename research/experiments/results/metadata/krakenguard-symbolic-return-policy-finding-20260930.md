# KRAKENGUARD Symbolic Return Policy Evaluation Finding

Date: 2026-09-30
Frozen upstream commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7

## Source-level mechanism

1. __record_ebpf_return_value captures only ConstantExpr return values.
2. state.ebpfReturnValueCaptured is therefore false for symbolic return expressions.
3. terminateStateOnExit gates conditional-policy evaluation on state.ebpfReturnValueCaptured.
4. Consequently, symbolic-return states can exit without evaluateConditionalPolicy() being invoked.

## Controlled behavioral evidence

Symbolic-return object: e_adversarial_helper.o
Policy: p2-helper-only.json
Request: d37a99a2-1e89-4893-b810-d43caaaf2253
Observed: is_constant=0; NOT_CAPTURED; no Conditional Policy Statistics; NO VIOLATIONS.

Constant-return control: e_ktime_constant_return.o
Policy: p2-helper-only.json
Request: b438fd9a-7e5f-4031-82d5-cad3608da0fa
Observed: is_constant=1; captured=2; Conditional Policy Statistics; policy failure.
Violation: Unauthorized helper 'bpf_ktime_get_ns'.

## Interpretation

The minimal pair isolates return-expression concreteness as the differentiating condition.
The unauthorized helper is recorded in both cases, but conditional-policy evaluation occurs only in the concrete-return case.

## Status

Confirmed implementation behavior for this reproduced helper-policy case.
No baseline source was modified for the finding.
Diagnostic instrumentation is not part of the frozen baseline.
