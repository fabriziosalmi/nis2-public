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

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, Node version)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.
