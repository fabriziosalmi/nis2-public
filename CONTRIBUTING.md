# Contributing to NIS2 Compliance Platform

Thank you for considering contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/nis2-public.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Install dependencies: `make dev`

## Development Setup

```bash
# Start the full stack
make dev

# Run tests
make test

# Lint Python code
cd packages/api && ruff check .
cd packages/scanner && ruff check .

# Build the frontend
cd packages/web && npm run build
```

## Code Standards

- **Python**: Follow PEP 8. Use type hints. Use `ruff` for linting.
- **TypeScript**: Use strict mode. Prefer `const` over `let`.
- **Commits**: Use conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).
- **Tests**: Add tests for new features. Maintain 100% pass rate.

## Security Rules

The CI pipeline enforces these hard gates. PRs that violate them will be rejected:

- No `except:` without explicit exception types
- No `allow_origins=["*"]` in CORS configuration
- No plaintext secrets in committed files

## Pull Request Process

1. Ensure all tests pass: `make test`
2. Update documentation if your change affects the API or UI
3. Add your changes to the relevant translation files in `packages/web/messages/`
4. Open the PR with a clear description of what changed and why

## Releasing

`VERSION` at the repository root is the single source of truth. Four manifests
(`packages/api/pyproject.toml`, `packages/scanner/pyproject.toml`, the two
`package.json` files) and the supported-versions table in `SECURITY.md` are
derived from it — never edit them by hand.

```bash
make version                 # print the current version
make version-set VERSION=2.7.0   # write VERSION and propagate everywhere
# ...add the matching `## [2.7.0]` section to CHANGELOG.md...
make version-check           # what CI enforces
make version-check-release   # additionally requires the v2.7.0 git tag
git tag v2.7.0 && git push origin v2.7.0
```

`make version-check` runs in CI (`version-consistency`) and as part of
`make check`. It fails when a manifest drifts, when `CHANGELOG.md` has no entry
for the current version, or when `SECURITY.md` names the wrong supported minor.

The tag requirement is deliberately excluded from the default check: between
releases the tree is legitimately ahead of the newest tag, and failing every
commit for that would train people to ignore the gate. Run
`make version-check-release` when cutting a release.

Every one of these had already gone wrong before the check existed — v2.6.9
shipped with no tag and no release, `CHANGELOG.md` was missing entries for eight
tagged releases (one carrying a security fix), and `SECURITY.md` advertised the
wrong supported version for eleven releases.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, Node version)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.
