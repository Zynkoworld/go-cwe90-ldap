#!/usr/bin/env python3
"""go_cwe90_ldap — a deterministic oracle for LDAP injection (CWE-90) in Go.

An oracle *decides* the truth of a case; it does not guess. Given a piece of Go code, this decides whether it
carries an **unsanitized taint flow from untrusted input into an LDAP filter** (CWE-90):

  SOURCE     untrusted/user input (r.URL.Query().Get, r.FormValue, os.Args, os.Getenv, r.Header.Get, mux.Vars, ...)
  SINK       LDAP filter/query construction (ldap.NewSearchRequest, conn.Search, SearchWithPaging)
  SANITIZER  ldap.EscapeFilter(...) — the documented go-ldap escape
  VERDICT    "FLAG"  unsanitized taint reaches an LDAP filter sink  -> LDAP injection present
             "SAFE"  escaped / constant / parameterized             -> no injection

Deterministic, standard-library only, re-runnable (same input -> same verdict). Lightweight source-level taint:
a fixpoint over assignments (EscapeFilter sanitizes), string-literals excluded (taint follows code references,
not literal text), then a sink check. Public domain of applicability: single-function, straight-line Go handlers.

Usage (CI entrypoint):
    python3 go_cwe90_ldap.py ../probes/probes.jsonl      # runs the oracle on the labelled probe corpus
    -> prints per-probe results + recall / false-positives; exit 0 iff recall==1.0 and FP==0.
"""
import re
import sys

_SOURCES = [
    r"r\.URL\.Query\(\)\.Get\(", r"r\.FormValue\(", r"r\.PostFormValue\(", r"r\.PostForm\.Get\(",
    r"r\.Header\.Get\(", r"os\.Args\[", r"os\.Getenv\(", r"mux\.Vars\(", r"c\.Query\(", r"c\.Param\(",
    r"vars\[", r"ps\.ByName\(",
]
_SINK = [r"ldap\.NewSearchRequest\(", r"\bNewSearchRequest\(", r"\.Search\(", r"\.SearchWithPaging\("]
_ESCAPE_CALL = re.compile(r"ldap\.EscapeFilter\(\s*([A-Za-z_]\w*)\s*\)")
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:?=\s*(.+?)\s*$")
_STRLIT = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`')


def _code_only(s):
    """Drop string-literal contents so taint follows code references, not literal text
    (e.g. the attribute name in "(dept=%s)" must not collide with a variable named dept)."""
    return _STRLIT.sub(" ", s)


def _sanitized_rhs(rhs):
    """Values wrapped in ldap.EscapeFilter(x) are treated as clean; string-literals are excluded."""
    return _code_only(_ESCAPE_CALL.sub("__SAN__", rhs))


def analyze(code):
    """-> {"verdict": "FLAG"|"SAFE", "tainted": [...], "why": str}."""
    lines = code.split("\n")
    assigns = []
    for ln in lines:
        m = _ASSIGN.match(ln)
        if m and not m.group(2).startswith("=="):
            assigns.append((m.group(1), m.group(2)))

    tainted, why = set(), {}
    changed = True
    while changed:
        changed = False
        for lhs, rhs in assigns:
            if lhs in tainted:
                continue
            san = _sanitized_rhs(rhs)
            src = next((s for s in _SOURCES if re.search(s, rhs)), None)
            tvar = next((t for t in tainted if re.search(r"\b" + re.escape(t) + r"\b", san)), None)
            if src:
                tainted.add(lhs); why[lhs] = "SOURCE (%s)" % src; changed = True
            elif tvar:
                tainted.add(lhs); why[lhs] = "taint <- %s (unsanitized)" % tvar; changed = True

    for ln in lines:
        if any(re.search(sk, ln) for sk in _SINK):
            san = _sanitized_rhs(ln)
            hit = next((t for t in tainted if re.search(r"\b" + re.escape(t) + r"\b", san)), None)
            if hit:
                return {"verdict": "FLAG", "tainted": sorted(tainted),
                        "why": "unsanitized taint '%s' (%s) reaches LDAP sink" % (hit, why.get(hit, "?"))}
            inline = next((s for s in _SOURCES if re.search(s, san)), None)
            if inline:
                return {"verdict": "FLAG", "tainted": sorted(tainted),
                        "why": "inline unsanitized SOURCE (%s) at LDAP sink" % inline}
    return {"verdict": "SAFE", "tainted": sorted(tainted),
            "why": "no unsanitized taint at the LDAP filter sink (escaped / constant / parameterized)"}


def verdict(code):
    """Canonical one-word verdict: "FLAG" (injection present) | "SAFE" (absent)."""
    return analyze(code)["verdict"]


def _run_probes(path):
    import json
    probes = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    flags = [p for p in probes if p["expected_verdict"] == "FLAG"]
    safes = [p for p in probes if p["expected_verdict"] == "SAFE"]
    missed, false_pos = [], []
    for p in probes:
        got = verdict(p["code"])
        ok = got == p["expected_verdict"]
        if not ok and p["expected_verdict"] == "FLAG":
            missed.append(p)
        if not ok and p["expected_verdict"] == "SAFE":
            false_pos.append(p)
        print("  %-4s expected=%-4s %s  %s" % (got, p["expected_verdict"], "OK" if ok else "FAIL", p.get("note", "")))
    recall = 1.0 if not flags else 1.0 - len(missed) / len(flags)
    print("\nprobes=%d (FLAG=%d, SAFE=%d) | recall=%.3f | false_positives=%d"
          % (len(probes), len(flags), len(safes), recall, len(false_pos)))
    ok = recall == 1.0 and not false_pos and flags and safes
    print("RESULT: %s" % ("PROVEN (recall=1.0, FP0)" if ok else "NOT PROVEN"))
    return 0 if ok else 1


if __name__ == "__main__":
    probe_path = sys.argv[1] if len(sys.argv) > 1 else "probes/probes.jsonl"
    sys.exit(_run_probes(probe_path))
