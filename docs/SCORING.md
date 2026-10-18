# How ChainSentry scores risk

ChainSentry gives every dependency a **risk score from 0 to 100** and the
whole project an overall score. The formula is deliberately simple and
additive, so you can explain any number by reading its breakdown (the JSON
report's `score_breakdown` field lists every component).

All weights live in [`src/chainsentry/config.py`](../src/chainsentry/config.py)
and are pinned by [`tests/test_scoring.py`](../tests/test_scoring.py).

## Package score

```
package_score = min(100, vulnerability_points + signal_points)
```

### 1. Vulnerability points (from OSV.dev)

| Worst known vulnerability | Points |
|---|---:|
| CRITICAL (CVSS ≥ 9.0) | 75 |
| HIGH (7.0 – 8.9) | 50 |
| MEDIUM (4.0 – 6.9) | 25 |
| LOW (0.1 – 3.9) | 5 |
| UNKNOWN (advisory without a rating) | 25 |

Plus **2 points for each additional vulnerability, capped at 10**.

Known malware (an OSV `MAL-…` advisory) is always **100**.

### 2. Signal points (parsers, typosquat and health checks)

Each finding *code* counts once per package.

| Code | Points | Source |
|---|---:|---|
| `TYPOSQUAT` (high confidence) | 50 | typosquat |
| `NOT_IN_REGISTRY` | 40 | health |
| `TYPOSQUAT` (medium confidence) | 30 | typosquat |
| `VERSION_NOT_IN_REGISTRY` | 25 | health |
| `NEW_PACKAGE` (< 30 days old) | 20 | health |
| `INSTALL_SCRIPT` | 15 | health |
| `NEW_VERSION` (< 7 days old) | 10 | health |
| `ABANDONED` (no release in 2 years) | 10 | health |
| `DEPRECATED` / `YANKED` | 10 | health |
| `NON_REGISTRY_SOURCE` (git / URL) | 10 | parser |
| `SINGLE_MAINTAINER` | 5 | health |
| `UNPINNED` | 5 | parser |
| `NO_REPOSITORY` | 5 | health |
| `NPM_ALIAS` | 5 | parser |
| `MISSING_INTEGRITY` | 5 | parser |

### 3. Bands

| Score | Band |
|---|---|
| 75 – 100 | CRITICAL |
| 50 – 74 | HIGH |
| 20 – 49 | MEDIUM |
| 0 – 19 | LOW |

The vulnerability points equal each band's lower bound, so **a package is
never rated below its worst vulnerability**: one critical CVE alone makes the
package CRITICAL.

## Project score

```
project_score = min(100, highest package score
                         + 2 × (number of OTHER packages rated HIGH or CRITICAL))
```

## Worked examples (from the demo project)

| Package | Breakdown | Score | Band |
|---|---|---:|---|
| `django@3.2.0` | worst CVE is CRITICAL **75** + 37 more vulns (capped) **10** | 85 | CRITICAL |
| `minimist@1.2.5` | CRITICAL CVE-2021-44906 **75** + `ABANDONED` **10** | 85 | CRITICAL |
| `colourama@0.1.6` | `TYPOSQUAT` medium **30** + `NOT_IN_REGISTRY` **40** | 70 | HIGH |
| `lodash@4.17.15` | worst CVE HIGH **50** + 5 more vulns **10** + `SINGLE_MAINTAINER` **5** | 65 | HIGH |
| `requests>=2.20` | `UNPINNED` **5** | 5 | LOW |

Project: the worst package scores 85, and five *other* packages are HIGH or
CRITICAL (minimist, pyyaml, colourama, lodash, urllib3), so
85 + 2 × 5 = **95 / 100 CRITICAL**.

## Why this design?

* **Worst vulnerability, not the sum.** Adding up every bug would rank a
  big, well-audited framework (many small reports) above a tiny library with
  one remote-code-execution bug. What matters most is the worst thing an
  attacker can do.
* **Maximum, not average, for the project.** Supply-chain security is a
  weakest-link problem. 499 clean packages don't make one compromised
  package safer, but an average would hide it.
* **Each code counts once.** This stops one problem from being counted twice
  just because it was reported in two ways.
* **Weights in one config file.** They're easy to tune, review and test.

## Limitations

* The weights are **expert judgement, not a statistical model**. Use the
  score to rank packages for human review. It is not a probability of
  compromise.
* CVSS base scores ignore whether the vulnerable code is actually *reachable*
  from your application, and whether it is being exploited right now.
  Natural extensions are **EPSS** (exploit prediction scores) and **CISA KEV**
  (known exploited vulnerabilities).
* Health signals are heuristics. An "abandoned" package may simply be
  finished (e.g. `left-pad`), and a single maintainer may be very careful.
