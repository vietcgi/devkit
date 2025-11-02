# Release Process

This document describes how to release new versions of Devkit.

## Overview

Devkit uses [Semantic Versioning](https://semver.org/) and automated releases via GitHub Actions.

## Release Workflow

### 1. Prepare Release

```bash
# Update VERSION file
scripts/bump-version.sh minor  # or major/patch

# Update CHANGELOG.md
# Add entry for new version with date and changes

# Verify changes
git diff VERSION CHANGELOG.md

# Commit
git add VERSION CHANGELOG.md
git commit -m "chore: bump version to $(cat VERSION)"
```

### 2. Tag Release

```bash
# Create annotated tag
VERSION=$(cat VERSION)
git tag -a v$VERSION -m "Release v$VERSION"

# Push to GitHub (triggers CI/CD)
git push origin main
git push origin v$VERSION
```

### 3. CI/CD Pipeline

Automatic steps (no manual action needed):

1. **Version Verification**
   - Validates VERSION file format
   - Checks git tag matches VERSION
   - Fails if validation errors

2. **Security Checks**
   - Runs security scans
   - Verifies no hardcoded credentials
   - Checks for vulnerabilities

3. **Build Assets**
   - Generates SHA256 checksums
   - Creates release notes from CHANGELOG
   - Uploads artifacts

4. **Publish Release**
   - Creates GitHub release
   - Attaches checksums and notes
   - Announces release

5. **Documentation**
   - Updates CHANGELOG
   - Commits changelog update
   - Pushes to main

## Version Numbers

### MAJOR.MINOR.PATCH

- **MAJOR** (3.0.0): Breaking changes
  - Config format changed
  - API incompatibility
  - Database migration required

- **MINOR** (3.1.0): New features
  - New roles/functionality
  - New configuration options
  - Backward compatible

- **PATCH** (3.1.5): Bug fixes
  - Security patches
  - Bug fixes
  - Performance improvements
  - No API changes

## Release Checklist

Before pushing release tag:

- [ ] All tests passing locally: `python3 -m unittest discover tests`
- [ ] Documentation updated: README, CHANGELOG, docs/
- [ ] Version files updated: `VERSION`, CHANGELOG.md
- [ ] No uncommitted changes: `git status`
- [ ] Code reviewed and merged to main
- [ ] Security check passed
- [ ] Performance baselines measured
- [ ] Upgrade guide written (if breaking changes)

## Changelog Format

Follow "Keep a Changelog" format:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing features

### Fixed
- Bug fixes

### Security
- Security fixes

### Breaking Changes
- Changes that break compatibility
```

## Release Announcement

After release is published:

1. **Update Documentation**
   - Add release notes link
   - Update install instructions
   - Update examples

2. **Notify Users**
   - Create discussion post (if major)
   - Tweet/social media (if significant)
   - Email newsletter (if applicable)

3. **Monitor Issues**
   - Watch for bug reports
   - Respond quickly to issues
   - Plan patch release if needed

## Hotfix Releases

For urgent security or critical bug fixes:

```bash
# Check out latest release
git checkout v3.1.0

# Create hotfix branch
git checkout -b hotfix/security-issue

# Fix the issue
# ... make changes ...

# Update version (patch bump)
scripts/bump-version.sh patch
# VERSION is now 3.1.1

# Update CHANGELOG
# ... add entry for 3.1.1 ...

# Commit and push
git add VERSION CHANGELOG.md
git commit -m "security: fix critical vulnerability"
git push origin hotfix/security-issue

# Create PR to main
gh pr create --title "Hotfix: Security vulnerability" ...

# After merge, tag and release
git pull origin main
git tag -a v3.1.1 -m "Release v3.1.1"
git push origin v3.1.1
```

## Rollback Procedure

If a release has critical issues:

```bash
# Identify last good version
git tag -l | sort -V | tail -5

# Create rollback
git tag -d v3.1.5
git push origin :v3.1.5
git reset --hard v3.1.4

# Push rollback notification
git push origin main
```

## Release Best Practices

1. **Test thoroughly before releasing**
   - Run full test suite
   - Test on multiple systems
   - Verify upgrade path

2. **Document changes clearly**
   - Write descriptive CHANGELOG entries
   - Include migration guides for major versions
   - Add examples for new features

3. **Communicate with users**
   - Release announcements
   - Upgrade guides
   - Known issues and workarounds

4. **Plan for hotfixes**
   - Monitor bug reports closely
   - Be prepared to release patches quickly
   - Maintain security fixes in older versions

5. **Maintain backwards compatibility**
   - Support N-1 major versions minimum
   - Provide deprecation warnings
   - Include migration paths

## Release Metrics

Track release health:

```bash
# Check downloads
gh release view v3.1.0 --json assets

# Monitor issues
gh issue list --label "3.1.0" --state all

# Track bug reports post-release
gh issue list --since "7 days ago" --label "bug"
```

## Continuous Monitoring

After release:

1. **Day 1**: Watch for critical issues
2. **Week 1**: Gather user feedback
3. **Month 1**: Plan next release based on issues
4. **Ongoing**: Security vulnerability monitoring

## Release Cadence

Planned release schedule:

- **Security fixes**: As needed (hotfix)
- **Bug fixes**: Monthly (patch)
- **New features**: Quarterly (minor)
- **Major versions**: Yearly or as needed

## Version Support Matrix

| Version | Release | End of Life | Support |
|---------|---------|-------------|---------|
| 3.1.x   | Oct 2025 | Oct 2026    | Active |
| 3.0.x   | Jan 2025 | Oct 2025    | Security fixes only |
| 2.x     | 2024    | Jan 2025    | Unsupported |

---

**Need to release?** Follow the checklist above and the CI/CD pipeline handles the rest!

For questions: See [SECURITY.md](../SECURITY.md) for security releases or file an [issue](https://github.com/vietcgi/devkit/issues).
