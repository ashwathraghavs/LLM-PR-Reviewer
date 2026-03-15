# Scoring rubric

This document explains exactly how the LLM judge scores a PR and what each
score range means in practice. Share this with your team so developers know
what they're being evaluated on.

---

## Dimensions

### Security (40% of overall score)

Grounded entirely in bandit and safety tool output. The LLM explains findings
but cannot invent them.

| Score | Meaning |
|---|---|
| 0–40 | HIGH severity bandit finding present, or known CVE in dependencies |
| 41–65 | MEDIUM severity findings — hardcoded secrets, insecure random, etc. |
| 66–80 | LOW severity findings — minor best-practice deviations |
| 81–100 | No significant security findings |

**Hard rules that override the LLM:**
- Any HIGH bandit finding → security_score capped at 40, PR blocked
- Any known CVE → PR blocked regardless of other scores

### Code quality (35% of overall score)

Grounded in pylint output. The LLM contextualizes and explains.

| Score | Meaning |
|---|---|
| 0–40 | 4+ pylint FATAL/ERROR level findings |
| 41–65 | Many warnings — poor naming, high complexity, missing error handling |
| 66–80 | Some warnings, generally readable code |
| 81–100 | Clean, well-named, properly typed, good error handling |

**Hard rules:**
- 4+ pylint errors → quality_score capped at 50

### Test coverage (25% of overall score)

| Score | Meaning |
|---|---|
| 50 | Default — no test files in the diff |
| 0–40 | Changed logic has no corresponding test coverage |
| 41–65 | Tests exist but don't cover the changed paths |
| 66–80 | Reasonable coverage with some gaps |
| 81–100 | Good coverage of the changed code |

---

## Overall score and decisions

```
overall = security × 0.40 + quality × 0.35 + tests × 0.25
```

| Score | Confidence | Action |
|---|---|---|
| > 80 | HIGH or MEDIUM | Auto-approve |
| > 80 | LOW | Human review (COMMENT) |
| 65–80 | any | Human review (COMMENT) |
| < 65 | any | Block (REQUEST_CHANGES) |
| Any HIGH bandit | — | Block (deterministic override) |
| Any CVE | — | Block (deterministic override) |
| Injection detected | — | Block (never reaches LLM) |

---

## Confidence levels

The reviewer runs three independent LLM calls per dimension. Confidence reflects
how much they agreed with each other:

| Stddev of three scores | Confidence |
|---|---|
| < 5 points | HIGH |
| 5–12 points | MEDIUM |
| > 12 points | LOW |

LOW confidence means the three runs disagreed significantly — which usually
indicates the diff is ambiguous, the code is doing something unusual, or there
may be an injection attempt influencing individual runs. LOW confidence PRs
always go to human review regardless of score.

---

## What the reviewer cannot do

- Invent security findings not present in bandit output
- Raise a score above what tool findings permit
- Override a HIGH bandit finding or CVE block
- Be convinced by instructions embedded in code comments or docstrings
- Approve a PR that trips an injection detection rule

The deterministic override layer enforces these constraints regardless of
what the LLM produces.
