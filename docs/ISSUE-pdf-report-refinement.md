# PDF/HTML report — refinement to client-grade / LinkedIn-shareable perfection

**Goal.** The exported NIS2 report is both a client deliverable *and* a marketing
surface (a well-designed report shared on LinkedIn is a lead channel). It must
read as something a Big-4 auditor would hand a board: flawless pagination,
premium typography, at-a-glance posture, accessible colour, archival-grade PDF.

**Scope.** `packages/api/app/tasks/report_tasks.py` (`_gen_html` / `_gen_pdf`,
the WeasyPrint pipeline) + `packages/api/app/utils/report_i18n.py`. Reference
render: demo seed, Gamma Power scan, IT locale (4 pages).

> **STATUS 2026-07-04 — P0 + video-facing P1 SHIPPED** (commit `22909b8`):
> score donut, "Posture at a Glance" hero band (5 pillars), Art.21 a–j heatmap +
> legend + row letters, cover confidentiality line; thead/tbody header repetition,
> `break-inside`/`break-after` control, empty-state on the assets table, fixed
> 6-up KPI band. **STATUS 2 (commit pending):** premium embedded font (Lato,
> SIL OFL, base64 @font-face → subset-embedded in the PDF) + full fr/de/es
> localization of the new section labels (zero English leakage, verified).
> **STATUS 3 (commit pending) — P2 essentially complete:** WCAG AA contrast pass
> (all white-on-colour badges/heatmap moved to −700 shades, computed ≥5.0:1),
> severity-distribution stacked bar, PDF metadata (Title/Author/Subject/Keywords),
> **PDF/A-2b** archival variant + **tagged/accessible** PDF (verified: OutputIntent
> + sRGB ICC + pdfaid part/conformance present in the inflated streams), and trust
> chrome (per-page "Confidential" marker + closing methodology/disclaimer note).
> **Only remaining:** localizing the *scanner-generated* status text + executive
> summary (data-language, produced by the scanner, separate from report chrome).

**Baseline (already shipped in this branch).** Cover + score band + executive
summary + NIS2 Art.21 matrix + full governance checklist + Art.23 incident
register + Art.18 supply chain + BIA + findings + assets. Matrix no longer leaks
the raw `{status,description}` dict. This issue is about taking that from *good*
to *flawless*.

---

## P0 — correctness & pagination (breaks the "premium" illusion instantly)

- [ ] **Table headers don't repeat across page breaks.** Tables use bare
  `<table><tr><th>…`; the governance table spans pp.2→3 but the header row shows
  only on p.2, so p.3 is a headerless grid. → Wrap header rows in `<thead>` and
  body in `<tbody>`; CSS `thead{display:table-header-group}`.
  *Metric:* every table that crosses a page boundary repeats its header.
- [ ] **Rows split across page breaks.** No `break-inside` control. → `tr,
  td{break-inside:avoid}`. *Metric:* no row is cut in half by a page break.
- [ ] **Orphaned section headings.** An `<h2>` can land at the bottom of a page
  with its table on the next. → `h2{break-after:avoid}` + wrap each section in a
  container with `break-inside:avoid` for the heading + first rows.
  *Metric:* no `<h2>` is the last element on a page.
- [ ] **Empty "Assets (0)" table renders headers with zero rows** (p.4) — reads
  as broken. → When a section has no rows, render an empty-state line ("No
  hosts responded" / localized) or omit the section entirely (as the new NIS2
  sections already do). *Metric:* zero tables render with a header and no body.
- [ ] **Stats band wraps unevenly**: 6 KPIs flex-wrap so LOW drops to a lonely
  second row (see p.1). → Fix to a deliberate 6-up (or 3×2) grid so the band is
  visually balanced. *Metric:* KPI band is a single intentional grid, no orphan.

## P1 — visual craft (the difference between "clean" and "wow")

- [ ] **Embed a professional font** (self-hosted, base64 `@font-face` — CSP/offline
  safe). Today it's system Helvetica/Arial → renders differently per machine and
  looks generic. Candidate: Inter or IBM Plex Sans + a mono for `code`.
  *Metric:* identical, embedded typography regardless of host; PDF passes font-
  embedding check (`pdffonts` shows all fonts embedded/subset).
- [ ] **Add inline-SVG data-visualisation** (WeasyPrint renders SVG):
  - score **donut/gauge** on the cover instead of a plain number box;
  - severity **bar** (critical/high/medium/low);
  - Art.21 coverage **heatmap** (a–j × status);
  - governance completion **progress bars** per priority.
  *Metric:* ≥3 charts render crisply at print DPI; this is the single biggest
  LinkedIn "screenshot-worthy" lever.
- [ ] **Executive posture page** ("NIS2 posture at a glance") consolidating the
  five pillars — technical score, governance %, open Art.23 incidents,
  Art.18 supplier exposure, continuity (BCP/DRP) coverage — into one KPI hero
  band. This is the page people screenshot. *Metric:* one page, five pillars,
  no scrolling for the exec takeaway.
- [ ] **Cover polish**: real logo mark (SVG, not just the text eyebrow), report
  ID, issue date, and a **confidentiality tag** ("Confidential — for internal
  use"). Add an **org-logo slot** (white-label hook — even if empty by default).
  *Metric:* cover has logo + report-ID + classification.
- [ ] **Matrix a–j lettering + legend.** Auditors cite "Art. 21(2)(a)"; show the
  letter next to each measure and a one-line legend for the coverage statuses
  (Automated / Partial / Manual verification / Gap). *Metric:* each row shows its
  sub-paragraph letter; a status legend is present once.
- [ ] **Unify the two visual languages** (solid `.badge` vs tinted `.pill`) into
  one consistent token set, or use them by deliberate rule (severity=solid,
  status=tinted) documented in a comment. *Metric:* consistent, rule-based.

## P2 — accessibility, archival, localization, trust

- [ ] **WCAG AA contrast audit** of every badge/pill text on its background
  (target ≥4.5:1 for body, ≥3:1 for large). *Metric:* documented ratios, all pass.
- [ ] **Grayscale/print legibility**: pills lose meaning printed B/W (colour is
  the only signal). Add a glyph/label so status survives monochrome printing.
  *Metric:* report is unambiguous printed in grayscale.
- [ ] **Localization debt (introduced this branch):** the new NIS2 sections use a
  self-contained EN+IT label map (`_NIS2_LABELS`), so under fr/de/es those
  headers fall back to English while the rest is translated. → Move the keys into
  `report_i18n.py` for all five locales; drop `_NIS2_LABELS`. *Metric:* a fr/de/es
  report has zero English section headers.
- [ ] **Locale-aware dates/numbers** (e.g. `03/07/2026` for IT vs `2026-07-03`).
  *Metric:* dates/numbers formatted per report locale.
- [ ] **PDF metadata + PDF/A.** Set Title/Author/Subject/Keywords/lang in the PDF
  properties; offer **PDF/A-2b** output for archival (auditors/regulators expect
  it). *Metric:* `exiftool`/`veraPDF` show correct metadata; PDF/A validates.
- [ ] **Selectable, tagged text** (accessibility/structure). *Metric:* text is
  selectable; headings are tagged (WeasyPrint PDF tagging where available).
- [ ] **Trust chrome**: confidentiality + org name in the footer; a one-line
  methodology/disclaimer footnote ("automated posture signal — not a legal
  opinion"; the app already states this) and, for demo exports, the RFC-2606/5737
  fiction note. *Metric:* footer carries classification; disclaimer present once.
- [ ] **Data-quality nit (not the report):** seed/scanner text drops Italian
  accents ("vulnerabilita", "Continuita"). Fix at the source so the rendered copy
  is orthographically correct. *Metric:* no missing diacritics in generated copy.

---

## Acceptance (the "perfection" bar)
A report is done when, on the demo seed and a real scan, in all 5 locales:
1. no header-less table, no split row, no orphaned heading, no empty-header table;
2. all fonts embedded; ≥3 SVG charts; a one-page posture hero;
3. every colour token passes WCAG AA and survives grayscale;
4. correct PDF metadata, optional PDF/A validates, text selectable;
5. zero English leakage in non-EN locales;
6. a stranger on LinkedIn would assume it came from a commercial GRC suite.

## Suggested phasing
**PR 1 (P0):** pagination + empty-state + KPI grid — pure correctness, low risk.
**PR 2 (P1):** embedded font + SVG charts + posture hero + cover polish — the wow.
**PR 3 (P2):** a11y/contrast, i18n unification, PDF/A + metadata, trust chrome.

## Test assets
- `packages/api` unit: assert generated HTML contains `<thead>`, no `{'status'`,
  no empty `<tbody></tbody>`, section headers per locale.
- Visual regression: render the demo Gamma Power scan to PDF in en+it, snapshot
  each page (the 4-page reference in this branch is the "before").
