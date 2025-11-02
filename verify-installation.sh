#!/bin/bash
# Post-installation verification script
# Fails if critical tools are missing

set -e

# Source Homebrew environment dynamically
if [ -f /home/linuxbrew/.linuxbrew/bin/brew ]; then
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
elif [ -f /opt/homebrew/bin/brew ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
elif [ -f /usr/local/bin/brew ]; then
    eval "$(/usr/local/bin/brew shellenv)"
elif command -v brew &>/dev/null; then
    eval "$(brew shellenv)"
fi

echo "Current PATH: $PATH"
echo ""

# Verify CRITICAL tools (must exist)
echo "=== Verifying Critical Tools ==="
echo "Checking git..."
git --version || {
    echo "❌ CRITICAL: git not found"
    exit 1
}

echo "Checking python3..."
python3 --version || {
    echo "❌ CRITICAL: python3 not found"
    exit 1
}

echo "Checking ansible..."
ansible-playbook --version || {
    echo "❌ CRITICAL: ansible-playbook not found"
    exit 1
}

# Verify OPTIONAL tools (warn if missing, don't fail)
echo ""
echo "=== Verifying Optional Tools (Warnings Only) ==="

if command -v zsh &>/dev/null; then
    echo "✓ zsh found: $(zsh --version)"
else
    echo "⚠️  zsh not found"
fi

if command -v tmux &>/dev/null; then
    echo "✓ tmux found: $(tmux -V)"
else
    echo "⚠️  tmux not found"
fi

if command -v nvim &>/dev/null; then
    echo "✓ nvim found: $(nvim --version 2>&1 | head -1)"
else
    echo "⚠️  nvim not found"
fi

if command -v fzf &>/dev/null; then
    echo "✓ fzf found"
else
    echo "⚠️  fzf not found"
fi

if command -v rg &>/dev/null; then
    echo "✓ ripgrep found"
else
    echo "⚠️  ripgrep not found"
fi

if command -v bat &>/dev/null; then
    echo "✓ bat found"
else
    echo "⚠️  bat not found"
fi

echo ""
echo "=== Verifying Config Files ==="

if [ -f ~/.zshrc ]; then
    echo "✓ .zshrc found"
else
    echo "⚠️  .zshrc not found"
fi

if [ -f ~/.tmux.conf ]; then
    echo "✓ .tmux.conf found"
else
    echo "⚠️  .tmux.conf not found"
fi

if [ -d ~/.config/nvim ]; then
    echo "✓ nvim config found"
else
    echo "⚠️  nvim config not found"
fi

echo ""
echo "✓✓✓ Verification Complete - All Critical Tools Present ✓✓✓"
exit 0
