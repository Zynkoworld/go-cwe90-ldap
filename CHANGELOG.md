# Changelog

All notable changes to this oracle are documented here. This oracle is deterministic
and byte-locked: a released version's verdicts are reproducible forever.

## [1.0.0] — 2026-08-07
### Added
- First release: `go-cwe90-ldap` — a deterministic LDAP-injection (CWE-90) taint oracle for Go.
- **Proven** on the full discriminating probe set: **recall 1.0 · false-positives 0 · byte-locked**.
- Covers the case **no external analyzer** (semgrep, gosec) decided.
