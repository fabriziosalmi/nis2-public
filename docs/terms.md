<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->

# Terms of Use / Termini di utilizzo

*Last updated: 2026-04-30 — version 1.0*

> **Scope.** These terms govern your use of (a) the documentation website at `https://fabriziosalmi.github.io/nis2-public/`, (b) the public source code repository at `https://github.com/fabriziosalmi/nis2-public`, and (c) any direct communication with the maintainer's listed contact email.
>
> **Self-hosted deployments** of the platform on your own infrastructure are governed by the AGPL-3.0 license and any contract you may have with the entity running that instance — these Terms do not apply to self-hosted deployments themselves.

## 1. Operator (Art. 7-12 D.Lgs 70/2003)

- **Salmi Fabrizio** (sole proprietor — *libero professionista*)
- Registered address: Via Sapri 9, 16134 Genova, Italy
- VAT (P.IVA): IT 03072120995
- ATECO code: 62.10.00 (Computer programming activities)
- Tax regime: *Regime semplificato*
- Contact: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

## 2. License of the platform

The platform source code is licensed under **GNU Affero General Public License version 3.0 only** (`AGPL-3.0-only`). The full text is available at [LICENSE](https://github.com/fabriziosalmi/nis2-public/blob/main/LICENSE) and at <https://www.gnu.org/licenses/agpl-3.0.html>.

You are free to use, study, modify, and distribute the software, **provided** that:
- You retain the copyright notice and license text in all copies and substantial portions
- If you modify the software and offer it to third parties as a network service, you must make your modified source code available to those third-party users under the same AGPL-3.0 terms
- You comply with all other AGPL-3.0 obligations

A **commercial dual license** without copyleft obligations is available — contact the operator above.

## 3. No warranty (AGPL-3.0 §15-16)

The software is provided **"AS IS", WITHOUT WARRANTY OF ANY KIND**, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the operator be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## 4. No legal or compliance advice

The platform, the documentation, and any output produced by it (compliance scores, governance checklists, scan findings, executive reports, ACN export JSONs, CSIRT Early Warning payloads, etc.) are **technical aids**, not legal, regulatory, or compliance advice. Specifically:

- A non-zero compliance score does **not** constitute attestation of NIS2 compliance, an ACN-grade audit certificate, or a substitute for the regulatory deliverables required by D.Lgs 138/2024 and its implementing Determinazioni.
- Scan findings are produced by automated heuristics and may contain false positives, false negatives, or be wholly inapplicable to your environment.
- Generated artefacts (PDF reports, ACN export files, CSIRT Early Warning JSON) are **drafts** to assist a qualified person — they must be reviewed and signed off by appropriate professionals before any regulatory submission or operational reliance.
- The 30-item Art. 21 governance checklist is a **community-curated didactic heuristic**, not a verbatim reproduction of the official ACN framework. See the *Disclaimer* section in the [README](https://github.com/fabriziosalmi/nis2-public#disclaimer--what-the-platform-is-not).

Engagement with a qualified NIS2 advisor and direct reference to ACN guidance remain mandatory for any production compliance posture.

## 5. Acceptable use of the documentation site and repository

You agree **not to**:

- Use the documentation site or repository to harass, defame, or harm any person or organisation
- Submit false security findings, attempt to exploit any disclosed information against third parties, or otherwise misuse the technical references contained in the documentation
- Probe, scan, or test the public maintainer-operated surfaces for vulnerabilities except via the responsible-disclosure channel described in [SECURITY.md](https://github.com/fabriziosalmi/nis2-public/blob/main/SECURITY.md)
- Reproduce or substantially copy the documentation under terms incompatible with the AGPL-3.0 license

## 6. Demo data — fictitious

The seed data shipped with the project (`scripts/seed_demo.py`) uses **fully fictitious organisations, domains (RFC 2606), and IP addresses (RFC 5737 / 1918)**. Any apparent resemblance to a real entity is unintentional. Pre-2.5.0 versions of this file referenced real Italian organisations; those versions have been **purged from the project's git history** in v2.5.0 via `git filter-repo`. If you forked or cloned the repository before v2.5.0, you are kindly asked to rebase or pull the rewritten history to avoid distributing the older version.

## 7. Third-party tools and services

Documentation references third-party tools and services (CertMate, Ollama, OpenAI, Cloudflare, etc.). Their use is governed by **their own terms** — these Terms do not extend to those services.

## 8. Limitation of liability

To the maximum extent permitted by applicable law:

- The operator shall not be liable for any indirect, incidental, special, consequential, or punitive damages, or any loss of profits, revenue, data, or goodwill arising out of or related to your use of the documentation site, the repository, or any output of the platform.
- The operator's total liability for any claim arising out of or related to these Terms or your use of the documentation site shall not exceed €100 or the total amount paid by you to the operator in the 12 months preceding the claim, whichever is greater.

These limitations apply notwithstanding the failure of the essential purpose of any limited remedy and to the maximum extent permitted by law. Mandatory consumer-protection statutes (where applicable) prevail.

## 9. Governing law and jurisdiction

These Terms are governed by the laws of the **Italian Republic**. The place of jurisdiction for any dispute is the **Tribunal of Genoa** (*Tribunale di Genova*), Italy, except where a mandatory consumer-protection venue applies.

## 10. Updates

We may update these Terms from time to time. Material changes are reflected in the *Last updated* date at the top and announced in the project's `CHANGELOG.md`. Continued use of the documentation site after a material update constitutes acceptance of the revised Terms.

## 11. Contact

**Salmi Fabrizio** — Via Sapri 9, 16134 Genova, Italy — [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)
