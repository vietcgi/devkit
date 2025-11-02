#!/usr/bin/env bash
#
# Setup Verification Script
# Checks for common configuration issues and conflicts
#
# Usage: ./verify-setup.sh

set -euo pipefail

# Source common functions library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/functions.sh"

# Counters
PASS=0
WARN=0
FAIL=0

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Mac Setup Verification Script              ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Wrapper functions for verify-setup.sh-specific behavior
# These wrap the library functions and add counter updates
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# ============================================================================
# System Checks
# ============================================================================
echo -e "${BLUE}[System]${NC}"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    pass "Operating System: macOS"
    HOMEBREW_PREFIX="/opt/homebrew"
else
    OS="Linux"
    pass "Operating System: Linux"
    HOMEBREW_PREFIX="/home/linuxbrew/.linuxbrew"
fi

# ============================================================================
# Core Tools
# ============================================================================
echo ""
echo -e "${BLUE}[Core Tools]${NC}"

# Homebrew
if command -v brew &>/dev/null; then
    BREW_VERSION=$(brew --version | head -n1)
    pass "Homebrew: ${BREW_VERSION}"

    # Check if Homebrew is installed in the expected location
    if [[ -x "${HOMEBREW_PREFIX}/bin/brew" ]]; then
        pass "Homebrew location: ${HOMEBREW_PREFIX}"
    else
        warn "Homebrew found but not in expected location: ${HOMEBREW_PREFIX}"
    fi
else
    fail "Homebrew: Not installed"
    info "  Install: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
fi

# Git
if command -v git &>/dev/null; then
    GIT_VERSION=$(git --version | cut -d' ' -f3)
    pass "Git: v${GIT_VERSION}"
else
    fail "Git: Not installed"
fi

# Ansible
if command -v ansible &>/dev/null; then
    ANSIBLE_VERSION=$(ansible --version | head -n1 | awk '{print $2}' | tr -d ']')
    pass "Ansible: v${ANSIBLE_VERSION}"
else
    warn "Ansible: Not installed (required for setup.yml)"
    info "  Install: brew install ansible"
fi

# ============================================================================
# Version Manager Conflict Check
# ============================================================================
echo ""
echo -e "${BLUE}[Version Manager Conflicts]${NC}"

# Check for nvm vs mise conflict
NVM_FOUND=false
MISE_FOUND=false

if command -v nvm &>/dev/null || [ -d "$HOME/.nvm" ]; then
    NVM_FOUND=true
    fail "nvm is installed (conflicts with mise)"
    info "  Fix: brew uninstall nvm && rm -rf ~/.nvm"
else
    pass "nvm: Not installed (good - using mise)"
fi

if command -v mise &>/dev/null; then
    MISE_FOUND=true
    MISE_VERSION=$(mise --version)
    pass "mise: ${MISE_VERSION}"
else
    warn "mise: Not installed"
    info "  Install: brew install mise"
fi

if $NVM_FOUND && $MISE_FOUND; then
    fail "CRITICAL: Both nvm and mise are installed - this causes conflicts!"
    info "  See KNOWN-ISSUES.md Issue #11 for resolution"
fi

# ============================================================================
# Node.js Configuration
# ============================================================================
echo ""
echo -e "${BLUE}[Node.js]${NC}"

if command -v node &>/dev/null; then
    NODE_VERSION=$(node --version)
    NODE_PATH=$(which node)
    pass "Node.js: ${NODE_VERSION}"

    # Check if node is managed by mise
    if [[ "$NODE_PATH" == *".local/share/mise"* ]]; then
        pass "Node.js managed by mise"
    elif [[ "$NODE_PATH" == *".nvm"* ]]; then
        warn "Node.js managed by nvm (should use mise)"
    elif [[ "$NODE_PATH" == *"homebrew"* ]]; then
        warn "Node.js managed by Homebrew (should use mise)"
    else
        warn "Node.js source unknown: ${NODE_PATH}"
    fi
else
    warn "Node.js: Not installed"
    info "  Install: mise install node@lts && mise use -g node@lts"
fi

# Check mise node config
if [ -f .mise.toml ]; then
    if grep -q "node" .mise.toml; then
        pass ".mise.toml: Node.js configured"
    else
        warn ".mise.toml: Node.js not configured"
    fi
else
    warn ".mise.toml: Not found in current directory"
fi

# ============================================================================
# Other Version-Managed Tools
# ============================================================================
echo ""
echo -e "${BLUE}[Development Tools]${NC}"

if command -v go &>/dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    pass "Go: ${GO_VERSION}"
else
    warn "Go: Not installed"
fi

if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    pass "Python: ${PYTHON_VERSION}"
else
    warn "Python: Not installed"
fi

# ============================================================================
# Shell Configuration
# ============================================================================
echo ""
echo -e "${BLUE}[Shell Configuration]${NC}"

# Check current shell
CURRENT_SHELL=$(basename "$SHELL")
if [ "$CURRENT_SHELL" = "zsh" ]; then
    pass "Shell: zsh"
else
    warn "Shell: ${CURRENT_SHELL} (recommended: zsh)"
fi

# Check Oh My Zsh
if [ -d "$HOME/.oh-my-zsh" ]; then
    pass "Oh My Zsh: Installed"
else
    warn "Oh My Zsh: Not installed"
fi

# Check Powerlevel10k
if [ -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" ]; then
    pass "Powerlevel10k: Installed"
else
    warn "Powerlevel10k: Not installed"
fi

# Check .zshrc
if [ -f "$HOME/.zshrc" ]; then
    pass ".zshrc: Exists"

    # Check for mise activation
    if grep -q "mise activate" "$HOME/.zshrc"; then
        pass ".zshrc: mise activation configured"
    else
        warn ".zshrc: mise activation missing"
        info "  Add: eval \"\$(mise activate zsh)\""
    fi
else
    warn ".zshrc: Not found"
fi

# ============================================================================
# Editor Configuration
# ============================================================================
echo ""
echo -e "${BLUE}[Editor Configuration]${NC}"

# Neovim
if command -v nvim &>/dev/null; then
    NVIM_VERSION=$(nvim --version | head -n1 | awk '{print $2}')
    pass "Neovim: ${NVIM_VERSION}"

    if [ -d "$HOME/.config/nvim" ]; then
        pass "Neovim config: Exists"
    else
        warn "Neovim config: Not found"
    fi
else
    warn "Neovim: Not installed"
fi

# VS Code
if command -v code &>/dev/null; then
    pass "VS Code: Installed"
    EXT_COUNT=$(code --list-extensions 2>/dev/null | wc -l | tr -d ' ')
    info "  Extensions installed: ${EXT_COUNT}"
else
    warn "VS Code: Not installed"
fi

# ============================================================================
# Dotfiles Management
# ============================================================================
echo ""
echo -e "${BLUE}[Dotfiles Management]${NC}"

if command -v chezmoi &>/dev/null; then
    pass "chezmoi: Installed"

    if [ -d "$HOME/.local/share/chezmoi" ]; then
        pass "chezmoi: Initialized"
    else
        warn "chezmoi: Not initialized"
        info "  Run: chezmoi init"
    fi
else
    warn "chezmoi: Not installed"
fi

# ============================================================================
# macOS-Specific Checks
# ============================================================================
if [ "$OS" = "macOS" ]; then
    echo ""
    echo -e "${BLUE}[macOS Configuration]${NC}"

    # Check for dockutil (used in setup.yml)
    if command -v dockutil &>/dev/null; then
        pass "dockutil: Installed"
    else
        warn "dockutil: Not installed (needed for Dock configuration)"
    fi

    # Check Xcode Command Line Tools
    if xcode-select -p &>/dev/null; then
        pass "Xcode Command Line Tools: Installed"
    else
        warn "Xcode Command Line Tools: Not installed"
        info "  Install: xcode-select --install"
    fi
fi

# ============================================================================
# Repository Status
# ============================================================================
echo ""
echo -e "${BLUE}[Repository Status]${NC}"

# Check if we're in a git repo
if [ -d .git ]; then
    pass "Git repository: Detected"

    # Check for uncommitted changes
    if git diff --quiet && git diff --cached --quiet; then
        pass "Working directory: Clean"
    else
        warn "Working directory: Has uncommitted changes"
        info "  Run: git status"
    fi

    # Check for untracked files
    UNTRACKED=$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')
    if [ "$UNTRACKED" -eq 0 ]; then
        pass "Untracked files: None"
    else
        warn "Untracked files: ${UNTRACKED} files"
        info "  Run: git status"
    fi
else
    warn "Not in a git repository"
fi

# Check for required files
echo ""
echo -e "${BLUE}[Required Files]${NC}"

for file in setup.yml Brewfile .mise.toml inventory.yml; do
    if [ -f "$file" ]; then
        pass "${file}: Found"
    else
        fail "${file}: Missing"
    fi
done

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Summary                                     ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}Passed:${NC} $PASS"
echo -e "${YELLOW}Warnings:${NC} $WARN"
echo -e "${RED}Failed:${NC} $FAIL"
echo ""

if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo -e "${GREEN}Perfect! Your setup is A++${NC}"
    exit 0
elif [ $FAIL -eq 0 ]; then
    echo -e "${YELLOW}Good! Minor improvements suggested${NC}"
    exit 0
else
    echo -e "${RED}Issues found. Please address failed checks.${NC}"
    echo ""
    echo "For troubleshooting, see:"
    echo "  - KNOWN-ISSUES.md"
    echo "  - QUICKSTART-ANSIBLE.md"
    exit 1
fi
