# 2026 Candidate Research Architectures

## Direction 1 — Hybrid Fine-Grained Policy Verification (Primary)

```text
                  +----------------------+
                  | Tenant eBPF Program   |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  | Linux BPF Verifier   |
                  +----------+-----------+
                             |
                  accepted program
                             |
                             v
              +-------------------------------+
              | Fine-Grained Policy Admission |
              +---------------+---------------+
                              |
                 +------------+------------+
                 |                         |
                 v                         v
       +------------------+      +-------------------+
       | Abstract Summary |      | Symbolic Analysis |
       | cheap/pruning    |      | unresolved paths  |
       +---------+--------+      +---------+---------+
                 |                         |
                 +------------+------------+
                              v
                    Policy decision
                 ALLOW / DENY / TIMEOUT
                              |
                              v
                       Hook attachment
```

### Design principle

Do not replace the Linux verifier. Add a security-policy analysis stage that uses the verifier-approved program as input.

### Initial scope

- XDP or TC programs first.
- Helper restrictions.
- Map-access restrictions.
- Packet write/redirect restrictions.
- Optional cross-program interference.

### Primary research variable

How much symbolic work is necessary after an abstract policy summary has already ruled out irrelevant paths?

---

## Direction 2 — Revocable Tenant Delegation

```text
Tenant
  |
  v
BPF Token + User Namespace
  |
  v
Tenant Object Registry
  |
  +--> Maps
  +--> Links
  +--> Programs
  +--> Pins
  |
  v
Authority Epoch
  |
  +--> active generation
  +--> revoked generation
  +--> teardown barrier
```

### Research question

Can revocation guarantee that no object created under an old authority generation can continue to provide the revoked capability beyond a bounded interval?

### Initial scope

One container runtime, one BPF object family and one revocation path. Do not attempt a general replacement for BPF Token.

---

## Direction 3 — Security + Resource Isolation

```text
                 Tenant
                   |
          +--------+--------+
          |                 |
          v                 v
   Security authority   Execution budget
   / policy checker     / scheduler
          |                 |
          +--------+--------+
                   v
             Tenant runtime
                   |
             Shared BPF hook
```

### Research question

What invariant guarantees that security authority and execution budget remain independent under contention?

### Initial scope

One hook class and a small number of tenants. Compare native contention, vBPF and a security-aware composition.

---

## Decision rule

Direction 1 should be selected unless baseline reproduction shows that KRAKENGUARD's artifact is too difficult to reproduce. In that case, switch to Direction 2 and restrict the contribution to BPF Token + BPF-LSM object lifecycle semantics.
