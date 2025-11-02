# Shell Role

## Overview

The **Shell** role configures modern shell environments (Zsh, Fish) with plugins, themes, and productivity enhancements. This role handles:

- Shell installation (Zsh, Fish, or both)
- Oh My Zsh framework and plugin installation
- Theme configuration (Powerlevel10k)
- Shell configuration with aliases and functions
- Font installation for theme support
- Version manager integration (direnv, mise)

## Purpose

This role transforms the shell experience with modern features, syntax highlighting, autocomplete suggestions, and a beautiful prompt. It customizes the shell environment based on user preference.

## Requirements

- Ansible 2.9+
- **Core role** (must run first for Homebrew setup)
- Valid `$HOME` environment variable
- Internet connection for theme/plugin downloads

## Role Variables

### Default Variables (`defaults/main.yml`)

```yaml
config_shell: "zsh"                     # Shell choice: 'zsh' or 'fish'
homebrew_prefix: "/opt/homebrew"       # Homebrew path (from core role)
home_dir: "{{ ansible_user_dir }}"     # User's home directory
is_macos: true/false                   # Is macOS? (from core role)
```

### Configuration

Control shell choice via `config_shell` variable:

```yaml
- name: Configure shell
  hosts: localhost
  vars:
    config_shell: "zsh"  # or "fish"
  roles:
    - shell
```

## Tasks Performed

### For Zsh

1. **Installation**
   - Install Zsh via Homebrew
   - Install Zsh completions
   - Install syntax highlighting and autosuggestions plugins

2. **Oh My Zsh Setup**
   - Download and configure Oh My Zsh framework
   - Install Powerlevel10k theme
   - Install MesloLGS Nerd Font for theme rendering

3. **Configuration**
   - Create `.zshrc` with PATH configuration
   - Enable plugins (git, docker, kubectl, fzf, direnv, etc.)
   - Set Powerlevel10k as default theme
   - Add useful aliases (ll, la, grep, cat, ls)
   - Integrate with direnv and mise
   - Add custom functions (e.g., cdtemp)

### For Fish

1. **Installation**
   - Install Fish shell via Homebrew

2. **Configuration**
   - Create Fish config with PATH setup
   - Add shell aliases
   - Set environment variables

## Handlers

This role provides 6 handlers:

- `reload zsh configuration` - Reloads Zsh config in shell session
- `verify oh-my-zsh installation` - Verifies Oh My Zsh framework
- `update oh-my-zsh` - Updates Oh My Zsh to latest version
- `install zsh plugins` - Verifies plugin installations
- `reload powerlevel10k` - Refreshes theme from git
- `shell configuration complete` - Completion notification

## Dependencies

- **core** role (provides `homebrew_prefix` and system variables)

## Example Playbook

```yaml
# Install Zsh (default)
- name: Configure shell
  hosts: localhost
  roles:
    - core
    - shell

# Install Fish instead
- name: Configure with Fish shell
  hosts: localhost
  vars:
    config_shell: "fish"
  roles:
    - core
    - shell
```

## Features by Shell

### Zsh Features

| Feature | Description |
|---------|-------------|
| **Theme** | Powerlevel10k (modern, configurable prompt) |
| **Plugins** | git, docker, kubectl, fzf, direnv, syntax-highlight, autosuggestions |
| **Aliases** | ll, la, grep, cat, ls (with colors/icons) |
| **Functions** | cdtemp (create and cd to temp dir) |
| **Integration** | direnv, mise (version managers) |
| **Font** | MesloLGS Nerd Font (icons and special chars) |

### Fish Features

| Feature | Description |
|---------|-------------|
| **Shell** | Fish 3.x (friendly interactive shell) |
| **Aliases** | ll, la, cat, ls |
| **PATH** | Pre-configured for Homebrew and system tools |

## Platform Support

| Platform | Zsh | Fish |
|----------|-----|------|
| macOS | ✓ | ✓ |
| Linux | ✓ | ✓ |

## Tags

- `shell` - All shell tasks
- `zsh` - Zsh-specific tasks
- `fish` - Fish-specific tasks
- `config` - Configuration files
- `plugins` - Plugin installations
- `theme` - Theme-related tasks
- `fonts` - Font installations

## Configuration Files

- **Zsh**: `~/.zshrc` - Main Zsh configuration
- **Fish**: `~/.config/fish/config.fish` - Fish configuration
- **Oh My Zsh**: `~/.oh-my-zsh/` - Framework directory
- **Powerlevel10k**: `~/.oh-my-zsh/custom/themes/powerlevel10k/` - Theme directory

## Customization

### Add Custom Plugins

Edit the `plugins=()` list in the role's template:

```bash
plugins=(
  git
  docker
  # Add your plugins here
  custom-plugin
)
```

### Change Theme

Modify the `ZSH_THEME` variable in `.zshrc`:

```bash
ZSH_THEME="powerlevel10k/powerlevel10k"  # or another theme
```

### Add Aliases

Add to the Zsh configuration template:

```bash
alias myalias='command'
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Theme not rendering | Font not installed | Install Nerd Font or configure terminal font |
| Plugins not loading | Plugin missing | Install via Homebrew or git |
| PATH not correct | Environment not sourced | Restart terminal or source ~/.zshrc |
| Oh My Zsh not found | Installation failed | Check internet connectivity, rerun role |

## See Also

- [Oh My Zsh Documentation](https://ohmyz.sh/)
- [Powerlevel10k Configuration](https://github.com/romkatv/powerlevel10k)
- [Fish Shell Documentation](https://fishshell.com/docs/current/)
- [Zsh Documentation](https://zsh.sourceforge.io/Doc/)
- Related roles: `core`, `dotfiles`, `editors`
