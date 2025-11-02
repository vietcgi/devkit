# Editors Role

## Overview

The **Editors** role sets up modern development editors and IDEs:

- Neovim (modern Vim) with LSP support
- Plugin manager installation (vim-plug)
- Language server protocol (LSP) configuration
- VS Code integration hints
- JetBrains IDE configuration (optional)

## Purpose

This role configures powerful, extensible editors for development with built-in language intelligence, syntax highlighting, and productivity features.

## Requirements

- Ansible 2.9+
- **Core role** (must run first for Homebrew)
- Valid `$HOME` environment variable
- Internet connection for plugin downloads

## Role Variables

### Default Variables (`defaults/main.yml`)

```yaml
home_dir: "{{ ansible_user_dir }}"     # User's home directory
homebrew_prefix: "/opt/homebrew"       # Homebrew path (from core role)
is_macos: true/false                   # Is macOS? (from core role)
```

## Tasks Performed

### Neovim Setup

1. **Installation**
   - Install Neovim via Homebrew

2. **Plugin Manager**
   - Install vim-plug plugin manager
   - Create plugin directories

3. **Configuration**
   - Create `~/.config/nvim/init.lua` with modern Lua config
   - Configure basic editor settings (line numbers, tabs, etc.)
   - Set up LSP keybindings
   - Configure LSP servers for: Lua, Python, TypeScript, Go, Rust

4. **LSP Support**
   - Install cmp-nvim-lsp for completion
   - Configure language servers
   - Set up diagnostic displays

## Handlers

This role provides 8 handlers:

- `verify neovim installation` - Check Neovim is available
- `install nvim plugins` - Run PlugInstall
- `update nvim plugins` - Update all plugins
- `vim-plug verified` - Verify plugin manager
- `clear nvim cache` - Clear Neovim cache
- `verify nvim config` - Validate configuration
- `editor setup complete` - Completion notification
- `vscode available` - VS Code installation hint

## Dependencies

- **core** role (provides `homebrew_prefix` and system variables)

## Example Playbook

```yaml
- name: Configure editors
  hosts: localhost
  roles:
    - core
    - editors
```

## Editor Features

### Neovim Features

| Feature | Description |
|---------|-------------|
| **Init.lua** | Modern Lua-based configuration |
| **LSP** | Language Server Protocol support |
| **Keybindings** | Leader-based (space) key mappings |
| **Plugins** | vim-plug for plugin management |
| **Languages** | Python, Lua, TypeScript, Go, Rust |
| **Line Numbers** | Relative and absolute numbering |
| **Search** | Case-sensitive/insensitive smart search |

### LSP Servers Configured

- **lua_ls** - Lua language server
- **pyright** - Python static analysis
- **tsserver** - TypeScript/JavaScript
- **gopls** - Go language server
- **rust_analyzer** - Rust language server

## Configuration Files

- **Neovim Config**: `~/.config/nvim/init.lua`
- **Plugin Dir**: `~/.local/share/nvim/site/autoload/plug.vim`
- **Plugins**: `~/.config/nvim/plugged/`
- **Cache**: `~/.local/share/nvim/`

## Tags

- `editors` - All editor tasks
- `neovim` - Neovim-specific
- `plugins` - Plugin management
- `config` - Configuration tasks
- `lsp` - LSP setup
- `vscode` - VS Code hints

## Customization

### Add Language Server

Edit `init.lua` template and add to servers list:

```lua
local servers = {
  'lua_ls',
  'pyright',
  'new_language_server',
}
```

### Add Plugin

Edit vim-plug section in `init.lua`:

```vim
Plug 'plugin/author/name'
```

### Change Keybindings

Modify the keymaps section:

```lua
keymap('n', '<leader>key', ':command<CR>', opts)
```

## Post-Setup Steps

1. **Install Plugins**

   ```bash
   nvim +PlugInstall +qall
   ```

2. **Update Plugins**

   ```bash
   nvim +PlugUpdate +qall
   ```

3. **Test LSP**

   ```bash
   nvim test.py  # Open Python file, LSP should activate
   ```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Neovim not found | Installation failed | Check Homebrew, rerun role |
| Plugins not loading | vim-plug missing | Run `:PlugInstall` in Neovim |
| LSP not working | Server not installed | Install via `:Mason` or npm |
| Config not applied | Cache stale | Clear: `rm -rf ~/.local/share/nvim` |
| Icons not showing | Font issue | Install Nerd Font from shell role |

## VS Code Setup

For VS Code installation:

```bash
brew install --cask visual-studio-code
# or from Mac App Store
```

Recommended extensions:

- Neovim extension (for Neovim keybindings)
- Python, Pylance
- Go, Rust Analyzer
- GitLens

## Related Editors

| Editor | Role | Notes |
|--------|------|-------|
| Neovim | This role | Primary editor |
| VS Code | Manual | Can be installed via Homebrew |
| Vim | core/shell | Available by default |
| Nano | core/shell | Minimal editor |

## See Also

- [Neovim Documentation](https://neovim.io/)
- [vim-plug Documentation](https://github.com/junegunn/vim-plug)
- [LSP Specification](https://microsoft.github.io/language-server-protocol/)
- [Lua in Neovim](https://neovim.io/doc/user/luaref.html)
- [LSP Config](https://github.com/neovim/nvim-lspconfig)
- Related roles: `core`, `shell`
