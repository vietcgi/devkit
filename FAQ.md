# Frequently Asked Questions (FAQ)

## Installation & Setup

### Q: What are the system requirements?

**A:** Devkit requires:

- macOS 10.15+ or Linux (Ubuntu 18.04+)
- 5GB free disk space
- Bash 4.0+
- Internet connection (for initial setup)
- Optional: Python 3.9+ for enhanced features

### Q: Can I run this on Windows?

**A:** Devkit is designed for macOS and Linux. For Windows, consider:

- Using Windows Subsystem for Linux (WSL2)
- Running in a Docker container
- Using a Linux virtual machine

### Q: How long does the initial setup take?

**A:** Initial setup typically takes 5-10 minutes depending on:

- Internet connection speed
- Your system's specs
- Number of packages to install
- Selected roles (core, development, etc.)

### Q: Can I install Devkit offline?

**A:** Not yet, but you can:

- Use caching from previous installations
- Pre-download packages on a networked machine
- Use a local package mirror

### Q: How do I update Devkit after installation?

**A:** Run:

```bash
cd devkit
git pull origin main
./bootstrap.sh
```

See [UPGRADE.md](UPGRADE.md) for version-specific upgrade paths.

## Configuration

### Q: Where is my configuration stored?

**A:** Configuration is stored in `~/.devkit/config.yaml` with the following structure:

```
~/.devkit/
├── config.yaml          # Main configuration
├── logs/                # Setup logs
├── cache/               # Installation cache
├── audit/               # Audit logs
└── plugins/             # Custom plugins
```

### Q: How do I customize my setup?

**A:** Edit `~/.devkit/config.yaml` and re-run:

```bash
./bootstrap.sh
```

Changes are merged with existing configuration.

### Q: Can I use Devkit without configuration?

**A:** Yes! Devkit works with sensible defaults. Configuration is optional for customization.

### Q: How do I reset to default configuration?

**A:** Backup and delete your current config, then re-run bootstrap:

```bash
cp ~/.devkit/config.yaml ~/.devkit/config.yaml.backup
rm ~/.devkit/config.yaml
./bootstrap.sh  # Creates fresh default config
```

## Troubleshooting

### Q: Installation fails with "Homebrew not found"

**A:** Install Homebrew first:

```bash
/bin/bash -c "$(curl -fsSL https://brew.sh/install.sh)"
source ~/.zshrc  # or ~/.bashrc
./bootstrap.sh
```

### Q: I get "permission denied" errors

**A:** Make scripts executable:

```bash
chmod +x bootstrap.sh
chmod +x scripts/*.sh
```

Or run with bash explicitly:

```bash
bash bootstrap.sh
```

### Q: Setup is slow or hangs

**A:** This usually means:

- **Network issues**: Check internet connection
- **Disk space**: Verify 5GB+ free space
- **CPU throttling**: Your system may be under heavy load

Try:

```bash
./bootstrap.sh --skip-gui  # Skip GUI app installation
```

### Q: I see warnings but setup completes

**A:** Warnings are usually non-fatal. Check:

- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for specific warnings
- `~/.devkit/logs/setup.log` for details
- Run verification: `./verify-setup.sh`

### Q: How do I uninstall Devkit?

**A:** Devkit doesn't have an uninstaller because:

- It installs packages you may want to keep
- Different setups have different uninstall needs
- You manually decide what to keep/remove

To remove Devkit files:

```bash
rm -rf ~/.devkit
rm -rf ~/devkit  # If cloned here
```

Packages installed by Devkit remain (use `brew uninstall` to remove).

## Performance

### Q: Why is my first installation slow?

**A:** Initial installation downloads and installs 50+ packages. Subsequent runs are much faster due to caching.

### Q: How can I speed up installation?

**A:** Several ways:

1. **Use caching**: Run setup twice, second time is 75-80% faster
2. **Skip GUI apps**: `./bootstrap.sh --skip-gui`
3. **Select specific roles**: Edit config to include only what you need
4. **Check network**: Run `ping github.com` to verify connectivity

### Q: What about installation caching?

**A:** Devkit automatically caches:

- Successful package installations
- Downloaded scripts and configurations
- Verification results

Cache is stored in `~/.devkit/cache/` and cleaned after 24 hours.

## Security

### Q: Is it safe to run bootstrap from curl?

**A:** Yes, it's safe because:

- Bootstrap script has built-in checksum verification
- CI/CD pipeline generates and publishes checksums
- Installation verifies integrity before execution

Always download from official sources:

```bash
curl -fsSL https://raw.githubusercontent.com/vietcgi/devkit/main/scripts/install.sh | bash
```

### Q: What permissions does Devkit need?

**A:** Devkit requires:

- Write access to home directory (`~`)
- Sudo access for system package installation
- Network access to GitHub and Homebrew repos

### Q: How do I enable audit logging?

**A:** Audit logging is enabled by default in config. Logs are stored in:

```
~/.devkit/audit/audit-YYYYMMDD.jsonl
```

Logs are:

- Secure (mode 0600)
- JSON formatted
- Rotated daily
- Archived after 90 days

### Q: Can I enable signature verification for audit logs?

**A:** Yes, modify the audit system initialization:

```python
from cli.audit import AuditLogger
logger = AuditLogger(enable_signing=True)
```

This adds SHA256 signatures to all audit entries.

## Development

### Q: How do I contribute to Devkit?

**A:** See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Code standards
- Testing requirements
- Pull request process

### Q: How do I report a bug?

**A:** File an issue on GitHub:

1. Check [existing issues](https://github.com/vietcgi/devkit/issues) first
2. Include system info: `uname -a`
3. Include log: `~/.devkit/logs/setup.log`
4. Describe steps to reproduce

### Q: How do I request a feature?

**A:** Open a GitHub issue with:

- Clear use case
- Why it's important
- Suggested implementation (optional)

## Plugins

### Q: Can I create custom plugins?

**A:** Yes! See [PLUGIN_DEVELOPMENT_GUIDE.md](docs/PLUGIN_DEVELOPMENT_GUIDE.md) for:

- Plugin structure
- Development guide
- Security requirements
- Distribution

### Q: Where do I install plugins?

**A:** Place plugins in:

```
~/.devkit/plugins/my-plugin/
├── manifest.json
└── __init__.py
```

Then run: `./bootstrap.sh` to load them.

### Q: Can I disable plugins?

**A:** Yes, in `~/.devkit/config.yaml`:

```yaml
global:
  disabled_plugins:
    - plugin-name-1
    - plugin-name-2
```

## Fleet Management

### Q: Can I manage multiple machines?

**A:** Yes, Devkit supports fleet management via:

- Central configuration server
- Inventory-based setup
- Health check aggregation
- Audit log streaming

See [docs/GLOBAL_SETUP_GUIDE.md](docs/GLOBAL_SETUP_GUIDE.md) for details.

### Q: How do I monitor health across machines?

**A:** Use health check endpoints:

```bash
# Local health check
./verify-setup.sh

# JSON output for integration
devkit health --json
```

## Support

### Q: Where can I get help?

**A:** Multiple support options:

1. **Documentation**: Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. **GitHub Issues**: Report bugs and request features
3. **Discussions**: Ask questions and share knowledge
4. **Email**: Contact maintainers (see [SUPPORT.md](SUPPORT.md))

### Q: How do I report security issues?

**A:** Do NOT create public issues for security vulnerabilities!

Instead:

1. Email security details to: [maintainer-email@example.com]
2. Include affected versions
3. Describe impact
4. Allow 30 days for response

See [SECURITY.md](SECURITY.md) for complete policy.

### Q: What's the version numbering scheme?

**A:** Devkit uses [Semantic Versioning](https://semver.org/):

- MAJOR (3.0.0): Breaking changes
- MINOR (3.1.0): New features
- PATCH (3.1.5): Bug fixes

See [UPGRADE.md](UPGRADE.md) for upgrade instructions.

## Advanced Topics

### Q: Can I customize the Ansible playbooks?

**A:** Yes, place custom roles in:

```
~/.devkit/roles/custom-role/
└── tasks/
    └── main.yml
```

Add to config:

```yaml
global:
  enabled_roles:
    - custom-role
```

### Q: How do I integrate Devkit with CI/CD?

**A:** Use health checks and audit logs:

```bash
# In your CI/CD pipeline
./bootstrap.sh
./verify-setup.sh

# Check health
devkit health --json | grep healthy
```

### Q: Can I use Devkit in Docker?

**A:** Yes, add to Dockerfile:

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y git curl bash

RUN curl -fsSL https://raw.githubusercontent.com/vietcgi/devkit/main/scripts/install.sh | bash

RUN ./bootstrap.sh
```

---

**Can't find your question?** Check:

- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues
- [SUPPORT.md](SUPPORT.md) - Support options
- [GitHub Issues](https://github.com/vietcgi/devkit/issues) - Search existing questions

Still stuck? Open a new discussion or issue on GitHub!
