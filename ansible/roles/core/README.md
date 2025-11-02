# Core Role

## Overview

The **Core** role sets up the foundation for all other roles in the Devkit Ansible playbook. This role handles:

- System detection (macOS vs Linux)
- Homebrew installation and configuration
- Core package installation (git, curl, wget, build tools)
- Directory structure creation for Devkit
- Logging infrastructure setup

## Purpose

This role must run first as other roles depend on variables and tools it provides. It detects the operating system and configures the appropriate package manager, ensuring all prerequisite tools are available.

## Requirements

- Ansible 2.9+
- Valid `$HOME` and `$USER` environment variables
- Internet connection for package downloads

## Role Variables

### Default Variables (`defaults/main.yml`)

```yaml
homebrew_prefix: "/opt/homebrew"        # Set by role based on OS/arch
current_user: "{{ ansible_user_id }}"   # Current user running playbook
home_dir: "{{ ansible_user_dir }}"      # User's home directory
os_family: "{{ ansible_os_family }}"    # OS family (Darwin/Linux/etc)
is_macos: true/false                    # Boolean: is macOS?
is_linux: true/false                    # Boolean: is Linux?
```

## Tasks Performed

1. **System Detection**
   - Detects OS (macOS or Linux)
   - Detects architecture (ARM64 vs x86_64)
   - Sets Homebrew path based on architecture

2. **Directory Creation**
   - Creates `.devkit/` directory structure
   - Creates subdirectories: logs, backups, plugins, config
   - Sets proper permissions (0755)

3. **Package Manager Setup**
   - **macOS**: Detects and uses Homebrew (ARM64 or Intel path)
   - **Linux**: Installs Homebrew or uses native package manager (apt/dnf/pacman)

4. **Core Package Installation**
   - **macOS**: git, curl, wget via Homebrew
   - **Linux**: git, curl, wget, build-essential, python3-dev (apt)
   - **Fedora**: git, curl, wget, gcc, make, python3-devel (dnf)
   - **Arch**: git, curl, wget, base-devel (pacman)

5. **Logging Setup**
   - Creates `.devkit/logs/archive` directory structure
   - Initializes setup log file with timestamp and platform info

## Handlers

This role provides 4 handlers:

- `verify homebrew installation` - Validates Homebrew installation
- `update homebrew` - Updates Homebrew packages
- `notify installation complete` - Completion notification
- `environment updated` - Reloads environment PATH

## Dependencies

None. This role has no dependencies and should run first.

## Example Playbook

```yaml
- name: Bootstrap devkit
  hosts: localhost
  gather_facts: yes
  roles:
    - core
```

## Platform Support

| Platform | Support | Notes |
|----------|---------|-------|
| macOS (Apple Silicon) | ✓ | Uses /opt/homebrew |
| macOS (Intel) | ✓ | Uses /usr/local |
| Debian/Ubuntu | ✓ | Uses apt |
| Fedora/RHEL | ✓ | Uses dnf |
| Arch Linux | ✓ | Uses pacman |

## Tags

- `always` - Runs in all scenarios
- `homebrew` - Homebrew-specific tasks
- `packages` - Package installation tasks
- `linux` - Linux-only tasks
- `setup` - Directory and infrastructure setup
- `logging` - Logging infrastructure tasks

## Notes

- This role detects architecture at runtime for proper Homebrew path selection
- Platform detection is automatic via Ansible fact gathering
- All paths are relative to the current user's home directory
- The role handles both interactive and CI/CD environments
- Idempotent: safe to run multiple times

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Homebrew not found | Arch detection failed | Check `uname -m` output |
| Package install fails | Network issue | Check internet connectivity |
| Permission denied | User permissions | Run with appropriate privileges |
| Path not set | HOME not defined | Set `$HOME` environment variable |

## See Also

- [Homebrew Documentation](https://brew.sh)
- [Ansible Facts](https://docs.ansible.com/ansible/latest/user_guide/playbooks_vars_facts.html)
- Related roles: `shell`, `editors`, `git`, `security`, `dotfiles`
