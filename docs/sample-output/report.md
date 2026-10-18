<!-- chainsentry-report -->
## 🔴 ChainSentry: project risk **95/100** (CRITICAL)

> [!CAUTION]
> **Check failed:** 3 package(s) rated CRITICAL or worse: minimist@&#8203;1.2.5, django@&#8203;3.2.0, pyyaml@&#8203;5.3.1

| Packages | Known vulnerabilities | Critical | High | Medium | Low | Other findings |
|---:|---:|---:|---:|---:|---:|---:|
| 13 | 60 | 8 | 24 | 23 | 5 | 10 |

### Riskiest packages

| | Package | Version | Score | Why |
|---|---|---|---:|---|
| 🔴 | `minimist` | 1.2.5 | 85 | 1 vuln(s), worst CRITICAL, ABANDONED |
| 🔴 | `django` | 3.2.0 | 85 | 38 vuln(s), worst CRITICAL |
| 🔴 | `pyyaml` | 5.3.1 | 75 | 1 vuln(s), worst CRITICAL |
| 🟠 | `colourama` | 0.1.6 | 70 | TYPOSQUAT, NOT_IN_REGISTRY |
| 🟠 | `lodash` | 4.17.15 | 65 | 6 vuln(s), worst HIGH, SINGLE_MAINTAINER |
| 🟠 | `urllib3` | 1.26.4 | 60 | 11 vuln(s), worst HIGH |
| 🟡 | `express` | 4.17.1 | 27 | 2 vuln(s), worst MEDIUM |
| 🟡 | `left-pad` | 1.3.0 | 25 | NPM_ALIAS, ABANDONED, DEPRECATED |
| 🟡 | `pytest` | 7.0.0 | 25 | 1 vuln(s), worst MEDIUM |
| 🟢 | `internal-lib` | 1.0.0 | 10 | NON_REGISTRY_SOURCE |
| 🟢 | `python-dateutil` | 2.8.2 | 10 | ABANDONED |
| 🟢 | `requests` | &gt;=2.20 | 5 | UNPINNED |

<details><summary><b>Top vulnerabilities</b></summary>

| Severity | Package | Advisory | Fixed in | Summary |
|---|---|---|---|---|
| 🔴 CRITICAL | `minimist@1.2.5` | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906) | 1.2.6, 0.2.4 | Prototype Pollution in minimist |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-2gwj-7jmv-h26r](https://osv.dev/vulnerability/GHSA-2gwj-7jmv-h26r) (CVE-2022-28346) | 2.2.28, 3.2.13, 4.0.4 | SQL Injection in Django |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-p64x-8rxx-wf6q](https://osv.dev/vulnerability/GHSA-p64x-8rxx-wf6q) (CVE-2022-34265) | 3.2.14, 4.0.6 | Django `Trunc()` and `Extract()` database functions vulnerable to SQL Injection |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-r3xc-prgr-mg9p](https://osv.dev/vulnerability/GHSA-r3xc-prgr-mg9p) (CVE-2023-31047) | 3.2.19, 4.1.9, 4.2.1 | Django bypasses validation when using one form field to upload multiple files |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-w24h-v9qh-8gxj](https://osv.dev/vulnerability/GHSA-w24h-v9qh-8gxj) (CVE-2022-28347) | 2.2.28, 3.2.13, 4.0.4 | SQL Injection in Django |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-xpfp-f569-q3p2](https://osv.dev/vulnerability/GHSA-xpfp-f569-q3p2) (CVE-2021-35042) | 3.2.5, 3.1.13 | SQL Injection in Django |
| 🔴 CRITICAL | `pyyaml@5.3.1` | [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) (CVE-2020-14343) | 5.4 | Improper Input Validation in PyYAML |
| 🔴 CRITICAL | `django@3.2.0` | [GHSA-frmv-pr5f-9mcr](https://osv.dev/vulnerability/GHSA-frmv-pr5f-9mcr) (CVE-2025-64459) | 5.2.8, 5.1.14, 4.2.26 | Django vulnerable to SQL injection via _connector keyword argument in QuerySet and Q objects. |
| 🟠 HIGH | `django@3.2.0` | [GHSA-8x94-hmjh-97hq](https://osv.dev/vulnerability/GHSA-8x94-hmjh-97hq) (CVE-2022-36359) | 3.2.15, 4.0.7 | Django vulnerable to Reflected File Download attack |
| 🟠 HIGH | `django@3.2.0` | [GHSA-wvqv-fj8w-qmhm](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm) (CVE-2026-15307) | 5.2.17, 6.0.8 | Django GeoDjango spatial lookups allow file writes and outbound requests through GDAL raster parsing |

</details>

<details><summary>Warnings and incomplete checks</summary>

- requirements.txt:5: --extra-index-url https://***@&#8203;pypi.internal.example.com/simple enables dependency confusion: pip will install whichever index offers the highest version

</details>

<sub>ChainSentry 0.1.0 · 3 manifest(s) · checks: osv, typosquat, health · 2026-10-18T20:15:13+00:00</sub>
