# zynko-oracle · `go-cwe90-ldap`

**A deterministic oracle for LDAP injection (CWE-90) in Go — the case no external tool covered.**

An **oracle** is a tool that *deterministically decides* the truth of a case — it doesn't guess, it decides.
This one decides, for a given piece of **Go** code, whether it carries an **unsanitized taint flow from
untrusted input into an LDAP filter** (CWE-90, LDAP injection).

## Why this exists
Existing static analyzers (semgrep, gosec, …) do **not** cover LDAP-injection taint in Go.
Where no oracle existed, we built one — and gave it to the commons.

## Proven
Measured on a **discriminating** probe set of **10 cases (5 vulnerable + 5 safe)** — verified by running
the oracle, not asserted:

| Metric | Value | Meaning |
|---|---|---|
| **Recall** | **1.0** | catches all 5 vulnerable cases |
| **False positives** | **0** | flags none of the 5 safe cases |
| **Byte-lock** | **✓** | deterministic — same input → same verdict, re-runnable anywhere |

**Scope (honest):** the corpus is small and the domain of applicability is **single-function, straight-line
Go handlers** (as stated in `oracle/go_cwe90_ldap.py`). "Proven" means *proven on this stated set within this
stated domain* — not a universal solver for all Go LDAP-injection. It is a real, re-runnable deterministic
decider for that domain, growable by adding probes (see below).

## What it decides
- **Source:** untrusted / user-controlled input
- **Sink:** LDAP filter / query construction (e.g. a `ldap.Search` filter)
- **Sanitizer:** `ldap.EscapeFilter` (and equivalents)
- **Verdict:** LDAP-injection **PRESENT** / **ABSENT**

## Run it yourself
Standard library only — no dependencies. From the repo root:
```
python3 oracle/go_cwe90_ldap.py probes/probes.jsonl
```
It prints a per-probe verdict line + `recall / false_positives`, and **exits 0 iff `recall==1.0` and `FP==0`**.
That exit code is the proof — CI-checkable, re-runnable anywhere.

## The probe set = the tests
`probes/probes.jsonl` holds **10 discriminating** cases: **5 vulnerable** (unsanitized taint → LDAP filter)
**and 5 safe** (escaped with `ldap.EscapeFilter` / constant / parameterized). Running the oracle over them
yields **recall 1.0, FP 0** — verified. Add your own probes (both kinds) and re-run to extend the domain.

## License
**Apache-2.0** — free to use, including commercially.

---
Part of **[Zynko](https://zynko.dev)** — deterministic, provable AI.
Zynko doesn't guess — it *establishes truth*. See the full set: **https://zynko.dev/oracles.html**
