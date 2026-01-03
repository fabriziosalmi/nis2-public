# Release Process

This document describes how to create a new release for the NIS2 Public project.

## Prerequisites

- Ensure all changes are committed and pushed to the main branch
- Update version numbers in relevant files (package.json, etc.)
- Update CHANGELOG.md with release notes

## Creating a Release

### Automatic Release (Recommended)

The project uses GitHub Actions to automatically create releases when a tag is pushed:

1. **Create and push a tag:**
   ```bash
   git tag -a v0.9.0 -m "Release v0.9.0"
   git push origin v0.9.0
   ```

2. **GitHub Actions will automatically:**
   - Create a GitHub Release
   - Extract release notes from CHANGELOG.md
   - Publish the release

### Manual Release

If you prefer to create a release manually:

1. **Create and push the tag:**
   ```bash
   git tag -a v0.9.0 -m "Release v0.9.0"
   git push origin v0.9.0
   ```

2. **Create the release on GitHub:**
   - Go to https://github.com/fabriziosalmi/nis2-public/releases/new
   - Select the tag you just created (v0.9.0)
   - Set the release title to "Release v0.9.0"
   - Copy the relevant section from CHANGELOG.md into the release notes
   - Click "Publish release"

## Release Checklist

Before creating a release, ensure:

- [ ] All tests pass
- [ ] Documentation is up to date
- [ ] Version numbers are updated:
  - [ ] package.json
- [ ] CHANGELOG.md is updated with:
  - [ ] Release date
  - [ ] New features
  - [ ] Bug fixes
  - [ ] Breaking changes (if any)
- [ ] All changes are merged to the main branch
- [ ] The branch is clean (no uncommitted changes)

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version (X.0.0): Incompatible API changes
- **MINOR** version (0.X.0): New functionality in a backwards compatible manner
- **PATCH** version (0.0.X): Backwards compatible bug fixes

## For v0.9.0 Release

To complete the v0.9.0 release after merging this PR:

```bash
# Ensure you're on the main branch with the latest changes
git checkout main
git pull origin main

# Create and push the v0.9.0 tag
git tag -a v0.9.0 -m "Release v0.9.0 - Initial public release"
git push origin v0.9.0
```

The GitHub Actions workflow will automatically create the release.
