# Documentation — `go-cwe90-ldap` oracle

## What an oracle is
A tool that **deterministically decides** the truth of a case — a test-runner, a static analysis,
a prover, a simulator, a domain checker, a derivator, or a human-written deterministic script.
**Its essence: it doesn't guess — it decides.**

## What this oracle decides
For a given piece of **Go** source, it decides whether an **unsanitized taint flow** reaches an
**LDAP filter** — i.e. whether the code is vulnerable to **LDAP injection (CWE-90)**.

- **Sources** — untrusted / user-controlled values (request params, form fields, env, etc.).
- **Sinks** — LDAP filter/query construction (e.g. the filter argument of an `ldap.Search`).
- **Sanitizers** — `ldap.EscapeFilter` and equivalents; a sanitized value is no longer tainted.
- **Verdict** — `PRESENT` (a source reaches a sink with no sanitizer on the path) or `ABSENT`.

## The proof
The oracle is validated against `probes/` — a **discriminating** set (both vulnerable and safe
cases; a constant/degenerate checker would fail it). On that set it achieves **recall 1.0**
(every vulnerable case flagged) and **0 false positives** (no safe case flagged). The verdicts are
**byte-locked**: run it again, anywhere, and you get the identical result.

## The probe format
Each probe is a Go snippet plus its ground-truth label (`PRESENT`/`ABSENT`). See `probes/`.

## Verdict semantics & honesty
The oracle is **sound on what it claims**: it decides LDAP-injection taint specifically, not all Go
security. Cases outside its scope are simply not its subject — it never guesses about them.

## Extending / contributing
Add probes (both vulnerable and safe, discriminating) and re-run — the oracle must keep recall 1.0
and FP 0. Contributions welcome under the repo's Apache-2.0 license.

---
Part of **Zynko** — deterministic, provable AI. https://zynko.dev/oracles.html
