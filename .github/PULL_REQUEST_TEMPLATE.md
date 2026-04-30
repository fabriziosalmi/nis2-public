<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

  Thanks for the contribution. The template below mirrors how the
  maintainer writes commit messages and CHANGELOG entries — filling it
  in honestly speeds up review and reduces the back-and-forth that
  follows a vague PR description.
-->

## Summary

<!-- One or two sentences. What does this change do, and why? -->

## Why

<!--
  The motivation. Cite a specific user, audit finding, NIS2 / GDPR
  Article, or external-reviewer feedback if applicable. "Cleanup" is
  a fine reason; just say so.
-->

## What changes

<!-- A short bulleted list. Files / modules touched, not a diff dump. -->

-

## Surface impact

- [ ] API behaviour change
- [ ] Database schema (migration included)
- [ ] Web UI change (screenshots below)
- [ ] Scanner module
- [ ] Documentation site
- [ ] Deployment / packaging / CI
- [ ] None of the above (refactor / internal / docs only)

## Verification

<!--
  How did you test this? Concrete commands beat "tested locally".
  If a UI change, attach a screenshot or screen recording.
-->

- [ ] Web build passes (`cd packages/web && npx next build`)
- [ ] Unit tests pass (`make test`)
- [ ] Tested by hand against `make dev`
- [ ] i18n parity preserved (`node` parity check on `messages/*.json`)
- [ ] No new secrets committed (gitleaks-clean)

## NIS2 / GDPR / legal exposure

<!--
  If this PR touches anything personal-data-shaped, anything that
  changes what the operator (data controller) is told, or anything
  that materially shifts the maintainer's exposure under AGPL-3.0
  §15-16, flag it here so it can be reflected in CHANGELOG and the
  privacy notice as needed.

  Most PRs will say "no exposure change" — that's a fine answer.
-->

## Related issues / discussions

Closes #
Refs #
