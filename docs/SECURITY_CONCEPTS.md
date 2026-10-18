# Security concepts behind ChainSentry

Study notes for the ideas this project is built on. Each section ends with
questions an interviewer might ask.

---

## 1. Software supply-chain attacks

Your application runs code that **you didn't write and mostly never read**.
A typical Node.js app has hundreds to thousands of transitive dependencies.
Attackers have learned it is easier to compromise one popular package than
thousands of applications.

Main attack classes:

| Class | How it works | Real incident |
|---|---|---|
| **Typosquatting** | Publish a look-alike name and wait for typos | `crossenv` (npm, 2017), `colourama` (PyPI, 2018), `jeIlyfish` (PyPI, 2019) |
| **Dependency confusion** | Register an internal package name on the public registry with a higher version | Alex Birsan's research (2021): code ran inside Apple, Microsoft, PayPal and 30+ other companies; PyTorch `torchtriton` (2022) |
| **Account takeover** | Steal a maintainer's credentials and publish a malicious version | `ua-parser-js` (2021), `coa`/`rc` (2021), `chalk`/`debug` phishing (2025) |
| **Malicious maintainer / handover** | A new "helpful" maintainer adds malware later | `event-stream` → `flatmap-stream` (2018), `xz-utils` backdoor CVE-2024-3094 (2024) |
| **Protestware** | The author sabotages their own package | `colors`/`faker` (2022), `node-ipc` (2022) |
| **Self-spreading worms** | Malware steals npm tokens and republishes itself into the victim's packages | "Shai-Hulud" (npm, 2025) |
| **CI/CD compromise** | Attack the build pipeline instead of the code | `tj-actions/changed-files` tags rewritten to leak secrets (2025) |

**Install scripts** are the delivery mechanism for most npm malware:
`preinstall` / `install` / `postinstall` run arbitrary code the moment you
type `npm install`. ChainSentry flags them (`INSTALL_SCRIPT`). The defence
is `npm install --ignore-scripts` / `npm ci --ignore-scripts`.

*Interview questions:* Why are transitive dependencies the bigger risk? How
would you defend a company against dependency confusion? (Scoped/namespaced
packages, registering your internal names publicly, a single private proxy
registry instead of `--extra-index-url`, and pinning with hashes.)

---

## 2. Typosquatting in detail

ChainSentry looks for the tricks attackers actually use (see
[`checks/typosquat.py`](../src/chainsentry/checks/typosquat.py)):

* **Edit distance**: one inserted, removed, swapped or replaced character
  (`reqeusts`). *Damerau*-Levenshtein counts a swap of adjacent letters as a
  single edit, which matches how people make typos.
* **Separator confusion**: `crossenv` vs `cross-env`.
* **Homoglyphs**: `jeIlyfish` (capital *I*), `rn` → `m`, or Cyrillic `е` in
  `rеquests`. Unicode **NFKC** normalisation plus a confusables map exposes
  these.
* **Combosquatting**: popular name plus an affix (`requests-py`).

The engineering trade-off is **precision vs recall**. Short names are
1 edit away from many legitimate packages (`six`/`sip`), so the tool only
compares names of 5+ characters by edit distance and never flags a package
that is popular itself.

---

## 3. Vulnerability identifiers: CVE, GHSA, PYSEC, OSV

| ID | Issued by | Notes |
|---|---|---|
| `CVE-2021-23337` | CVE Program (MITRE + CNAs) | The universal ID; NVD adds CVSS scores |
| `GHSA-35jh-r3h4-6jhm` | GitHub Security Advisories | Often published before a CVE exists; reviewed per ecosystem |
| `PYSEC-2021-…` | PyPA advisory database | Python-specific |
| `MAL-2024-…` | OpenSSF malicious-packages | **Malware**, not a bug: the package itself is hostile |

**OSV.dev** (Google/OpenSSF) aggregates all of these into one schema with
precise **affected version ranges** per ecosystem. The same issue usually
appears under several IDs, linked through `aliases`, and ChainSentry
de-duplicates them.

*Interview questions:* Why not just use NVD? (NVD's CPE matching is fuzzy for
open-source packages and has had large processing backlogs. OSV ranges are
precise per package manager.) What is a CNA? (A CVE Numbering Authority: an
organisation allowed to assign CVE IDs, e.g. GitHub, Red Hat.)

---

## 4. CVSS: Common Vulnerability Scoring System

The base score (0–10) comes from 8 metrics:

* **Exploitability**: Attack Vector (Network/Adjacent/Local/Physical),
  Attack Complexity, Privileges Required, User Interaction.
* **Scope**: can the attack affect components beyond the vulnerable one?
* **Impact**: Confidentiality, Integrity and Availability (the CIA triad).

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 CRITICAL**: remote,
easy, no login and no click needed, full compromise.
ChainSentry implements the v3.1 formula itself
([`checks/cvss.py`](../src/chainsentry/checks/cvss.py)).

Know the limits:
* The **base** score describes the bug in general, not *your* exposure.
  Temporal and environmental metrics exist for that.
* **CVSS v4.0** (2023) adds metrics such as Attack Requirements and splits
  impact on the vulnerable system from impact on subsequent systems.
* **EPSS** estimates the probability of exploitation in the next 30 days.
  **CISA KEV** lists vulnerabilities known to be exploited in the wild.
  Prioritising by KEV/EPSS beats sorting by CVSS alone.

*Interview questions:* Why can a 9.8 be less urgent than a 7.5? (The
vulnerable function may be unreachable from your code, while the 7.5 is in
KEV and actively exploited.) What does "Scope: Changed" mean? (The exploit
breaks out of its security boundary, e.g. a sandbox escape or XSS that acts
in the user's browser.)

---

## 5. SBOM: Software Bill of Materials

An SBOM is a machine-readable **ingredients list** of your software: every
component, version and identifier. When the next Log4Shell lands, the
question "are we affected?" becomes a search instead of a week of
archaeology.

* **Formats**: **CycloneDX** (OWASP; also models vulnerabilities and
  services) and **SPDX** (Linux Foundation; ISO/IEC 5962, strong on
  licensing). ChainSentry emits CycloneDX 1.5.
* **purl** (Package URL) is the universal component ID:
  `pkg:npm/%40babel/core@7.24.0`, `pkg:pypi/django@3.2.0`.
* **VEX** (Vulnerability Exploitability eXchange) is a companion document
  stating "we are / are not affected by CVE-X, because …".
* **Policy**: US Executive Order 14028 (2021) and the follow-up NTIA
  minimum elements made SBOMs a requirement for software sold to the US
  government. The EU Cyber Resilience Act pushes the same way.

*Interview questions:* SBOM vs lockfile? (A lockfile is tool-specific
install instructions; an SBOM is a standard, cross-ecosystem inventory meant
for consumers and auditors.) What can't an SBOM tell you? (Whether the code
is reachable, or whether a component was tampered with. For that you need
provenance and signatures.)

---

## 6. Lockfiles, pinning and integrity

* A **range** (`^4.17.0`, `>=2.0`) means "whatever is newest at install
  time". A malicious new release is installed automatically.
* A **lockfile** (`package-lock.json`) pins the exact version of *every*
  package, including transitive ones, plus an `integrity` hash
  (SHA-512 of the tarball). npm refuses a download whose hash doesn't match.
* pip's equivalent is `pip-compile --generate-hashes` / `pip install
  --require-hashes`.
* **Provenance** (npm provenance, PyPI Trusted Publishing, Sigstore) proves
  *which CI pipeline* built a package, which defeats stolen-token publishing.

*Interview question:* Does a lockfile protect you from a compromised package?
(Only from *future* malicious versions. If the bad version is already locked,
you keep installing it. That's why you scan the lockfile.)

---

## 7. CI/CD security (Phase 6)

* **`pull_request` vs `pull_request_target`**: `pull_request_target` runs
  with the base repository's secrets and a write token. If it checks out and
  runs the PR's code, any fork can steal secrets (a "pwn request"). ChainSentry's
  workflow uses `pull_request`.
* **Least privilege**: declare `permissions:` explicitly; the default
  `GITHUB_TOKEN` may be read/write.
* **Pin actions to a commit SHA**, not a tag. Tags can be moved, which is
  exactly what happened with `tj-actions/changed-files` in 2025.
* **Script injection**: never put `${{ github.event.* }}` or inputs directly
  inside `run:` scripts. Pass them through `env:` so they are data, not shell
  code.
