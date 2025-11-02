# Support

Thank you for using this Mac/Linux setup automation! This document explains
how to get help.

## Getting Help

### Before Asking for Help

1. **Read the Documentation**
    - [README.md](README.md) - Overview and quick start
    - [docs/GLOBAL_SETUP_GUIDE.md](docs/GLOBAL_SETUP_GUIDE.md) - Detailed setup guide
    - [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common problems and solutions
    - [docs/GLOBAL_SETUP_GUIDE.md](docs/GLOBAL_SETUP_GUIDE.md) - Advanced deployment

2. **Run Verification Script**

    ```bash
    ./verify-setup.sh
    ```

    This checks your system and identifies common issues.

3. **Check for Known Issues**
    See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for solutions to common problems:
    - Node.js version manager conflicts (nvm vs mise)
    - Homebrew installation issues
    - Permission problems
    - Shell configuration issues

4. **Review Recent Changes**
    Check [CHANGELOG.md](CHANGELOG.md) for breaking changes in recent versions.

## Support Channels

### GitHub Issues (Recommended)

For bugs, feature requests, and questions:

1. **Search existing issues** first: [Search Issues](https://github.com/vietcgi/devkit/issues)
2. **Open a new issue** if needed: [New Issue](https://github.com/vietcgi/devkit/issues/new)

When opening an issue, please include:

- **Description**: Clear description of the problem
- **Steps to reproduce**: How to recreate the issue
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: Output from `./verify-setup.sh`
- **System info**:

    ```bash
    uname -a
    sw_vers  # macOS only
    brew --version
    ansible --version
    ```

### GitHub Discussions

For general questions and discussions: [Discussions](https://github.com/vietcgi/devkit/discussions)

Topics:

- **Q&A**: Ask questions and help others
- **Ideas**: Suggest new features
- **Show and Tell**: Share your customizations
- **General**: Other discussions

### Security Issues

**Do not report security vulnerabilities publicly.**

See [SECURITY.md](SECURITY.md) for how to report security issues responsibly.

## What to Include

### For Bugs

```markdown
### Description
[Clear description of the bug]

### Steps to Reproduce
1. Run `./bootstrap-ansible.sh`
2. Wait for completion
3. Error appears: [paste error]

### Expected Behavior
[What should happen]

### Actual Behavior
[What actually happens]

### Environment
- OS: macOS 14.2 (Sonoma) / Ubuntu 22.04
- Chip: Apple M2 / Intel x86_64
- Shell: zsh 5.9
- Homebrew: 4.2.0
- Ansible: 9.1.0

### Verification Output
[Paste output from ./verify-setup.sh]

### Error Logs
[Paste relevant error messages or logs]
```

### For Feature Requests

```markdown
### Feature Description
[What feature would you like to see?]

### Use Case
[Why is this feature needed? What problem does it solve?]

### Proposed Implementation
[How might this be implemented? (optional)]

### Alternatives Considered
[What alternatives have you considered?]
```

## Response Times

This is an open-source project maintained by volunteers. Response times vary:

- **Critical security issues**: 48 hours
- **Bugs**: 3-7 days
- **Feature requests**: 7-14 days
- **Questions**: 1-7 days (community-driven)

**Note**: These are target times, not guarantees. Community contributions and
discussions help everyone faster!

## Self-Help Resources

### Documentation

- **Setup Guide**: [docs/GLOBAL_SETUP_GUIDE.md](docs/GLOBAL_SETUP_GUIDE.md)
- **Troubleshooting**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Deployment**: [docs/GLOBAL_SETUP_GUIDE.md](docs/GLOBAL_SETUP_GUIDE.md)
- **Migration**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

### Verification Tools

```bash
# Check system health
./verify-setup.sh

# Check Ansible syntax
ansible-playbook setup.yml --syntax-check

# Dry run (no changes)
ansible-playbook -i inventory.yml setup.yml --check --limit localhost

# Check Brewfile syntax
brew bundle check --file=Brewfile
```

### Update Tools

```bash
# Update all packages and tools
./update.sh

# Update just Homebrew
brew update && brew upgrade && brew cleanup

# Update just mise tools
mise upgrade && mise prune
```

### Common Commands

```bash
# Show installed packages
brew list

# Show mise tools
mise list

# Show VS Code extensions
code --list-extensions

# Check for outdated packages
brew outdated
mise outdated
```

## Community Guidelines

When asking for help:

- **Be respectful** - Treat others as you'd like to be treated
- **Be clear** - Provide details and context
- **Be patient** - Maintainers are volunteers
- **Search first** - Check if your question has been answered
- **Share solutions** - Help others by sharing what worked
- **Give back** - Answer questions, improve docs, contribute code

## Contributing

Want to help improve this project? See [README.md](README.md#contributing)
for contribution guidelines.

Ways to contribute:

- Report bugs and suggest features
- Improve documentation
- Answer questions in Discussions
- Submit pull requests
- Share your customizations
- Star the repository

## External Resources

### Homebrew

- [Homebrew Documentation](https://docs.brew.sh/)
- [Homebrew FAQ](https://docs.brew.sh/FAQ)
- [Homebrew Common Issues](https://docs.brew.sh/Common-Issues)

### Ansible

- [Ansible Documentation](https://docs.ansible.com/)
- [Ansible Community](https://www.ansible.com/community)

### mise

- [mise Documentation](https://mise.jdx.dev/)
- [mise GitHub](https://github.com/jdx/mise)

### Shell Configuration

- [Oh My Zsh](https://ohmyz.sh/)
- [Powerlevel10k](https://github.com/romkatv/powerlevel10k)
- [zsh Documentation](https://zsh.sourceforge.io/Doc/)

## Frequently Asked Questions

### Where can I customize packages?

Edit `Brewfile` (base packages) or `Brewfile.sre` (SRE packages), then run:

```bash
ansible-playbook setup.yml --tags packages
```

### How do I change tool versions?

Edit `.mise.toml`, then run:

```bash
mise install
```

### How do I update everything?

Run the update script:

```bash
./update.sh
```

### Can I use this on Linux?

Yes! This setup supports macOS and Linux. See README.md for details.

### How do I uninstall?

Currently there's no automated uninstall. To manually uninstall:

1. Remove installed packages: `brew bundle cleanup --force`
2. Restore backed-up dotfiles from `~/*.backup`
3. Remove directories: `~/.oh-my-zsh`, `~/.config/nvim`, etc.

### Is this safe to run multiple times?

Yes! The setup is idempotent - safe to run multiple times without breaking
your system.

## Need More Help?

If you've:

- Read the documentation
- Checked known issues
- Searched existing issues
- Run verification tools

...and still need help, please [open an issue](https://github.com/vietcgi/devkit/issues/new) with all the
details.

---

**Last Updated**: 2025-10-27
**Support Version**: 1.0
