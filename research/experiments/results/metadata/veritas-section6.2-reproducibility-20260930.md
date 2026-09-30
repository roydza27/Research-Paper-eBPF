# Veritas Section 6.2 Reproduction Status — 2026-09-30

## Frozen artifact
- Repository: rs3lab/veritas
- Commit: 413f89bf69527f19a191ef663788202b26886298

## Reproduced
- Veritas Bullseye VM image extracted successfully.
- Supplied kernel `6.9.0-rc1+` booted successfully under KVM.
- VM identity confirmed as Debian 11 (Bullseye).
- Root login using the published credential succeeded.

## Section 6.2 evaluation
- Expected path: `/root/linux-bpfselftest/tools/testing/selftests/bpf/eval.sh`.
- `linux-bpfselftest` directory was absent from the supplied `bullseye.img`.
- No `eval.sh` was found under `/root`.
- Therefore Section 6.2 could not be executed from the extracted VM image.

## Remaining artifact
- Frozen `env.sh` references `vm.img.tar.gz` from Zenodo record 16885556.
- HTTP header reports 49,363,321,674 bytes (~49.36 GB) compressed.
- This artifact was not downloaded or extracted because the host had approximately 63 GB free and extraction requirements were not established.

## Methodological status
- Status: EXECUTION BLOCKED.
- This must not be reported as a reproduced Veritas Section 6.2 result.
- No source files or evaluation scripts were fabricated or copied into the VM.
