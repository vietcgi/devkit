#!/usr/bin/env bash

###############################################################################
# System Update Script
# Updates all tools, packages, and configurations
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
UPDATED=0
SKIPPED=0
FAILED=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    ((UPDATED++))
}

print_warning() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((FAILED++))
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "darwin"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)

###############################################################################
# Main Update Function
###############################################################################

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║        System Update Script                                   ║"
    echo "║        Updates all tools and packages                         ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    print_info "Detected OS: $OS"
    echo ""

    # 1. Update Homebrew
    print_header "Updating Homebrew"
    if command -v brew &>/dev/null; then
        print_info "Updating Homebrew itself..."
        if brew update; then
            print_success "Homebrew updated"
        else
            print_error "Failed to update Homebrew"
        fi

        print_info "Upgrading installed packages..."
        if brew upgrade; then
            print_success "Packages upgraded"
        else
            print_warning "No packages to upgrade or upgrade failed"
        fi

        print_info "Cleaning up old versions..."
        if brew cleanup; then
            print_success "Cleanup complete"
        else
            print_warning "Cleanup had issues"
        fi

        print_info "Checking for issues..."
        brew doctor || print_warning "Brew doctor found some issues (may be non-critical)"
    else
        print_warning "Homebrew not installed"
    fi

    # 2. Update mise tools
    print_header "Updating mise Tools"
    if command -v mise &>/dev/null; then
        print_info "Updating mise itself..."
        if brew upgrade mise 2>/dev/null || true; then
            print_success "mise updated"
        fi

        print_info "Upgrading all mise-managed tools..."
        if mise upgrade; then
            print_success "mise tools upgraded"
        else
            print_warning "No mise tools to upgrade"
        fi

        print_info "Pruning old tool versions..."
        if mise prune; then
            print_success "Old versions pruned"
        else
            print_warning "No old versions to prune"
        fi

        print_info "Current tool versions:"
        mise list || true
    else
        print_warning "mise not installed"
    fi

    # 3. Update Oh My Zsh
    print_header "Updating Oh My Zsh"
    if [ -d "$HOME/.oh-my-zsh" ]; then
        print_info "Updating Oh My Zsh..."
        if "$HOME/.oh-my-zsh/tools/upgrade.sh" 2>/dev/null; then
            print_success "Oh My Zsh updated"
        else
            print_warning "Oh My Zsh update skipped or failed"
        fi

        print_info "Updating Powerlevel10k theme..."
        if [ -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" ]; then
            cd "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" &&
                git pull &&
                cd - >/dev/null &&
                print_success "Powerlevel10k updated"
        else
            print_warning "Powerlevel10k not installed"
        fi

        print_info "Updating zsh plugins..."
        for plugin_dir in "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"/plugins/*; do
            if [ -d "$plugin_dir/.git" ]; then
                plugin_name=$(basename "$plugin_dir")
                print_info "Updating $plugin_name..."
                if cd "$plugin_dir" && git pull && cd - >/dev/null; then
                    print_success "$plugin_name updated"
                else
                    print_warning "$plugin_name update failed"
                fi
            fi
        done
    else
        print_warning "Oh My Zsh not installed"
    fi

    # 4. Update Tmux Plugin Manager (TPM)
    print_header "Updating Tmux Plugins"
    if [ -d "$HOME/.tmux/plugins/tpm" ]; then
        print_info "Updating TPM..."
        if cd "$HOME/.tmux/plugins/tpm" && git pull && cd - >/dev/null; then
            print_success "TPM updated"
        else
            print_warning "TPM update failed"
        fi

        print_info "Updating tmux plugins..."
        if command -v tmux &>/dev/null && [ -f "$HOME/.tmux.conf" ]; then
            # Update plugins using TPM's update script
            "$HOME/.tmux/plugins/tpm/bin/update_plugins" all 2>/dev/null ||
                print_warning "Tmux plugins update skipped (run prefix+U in tmux)"
        else
            print_warning "Tmux not configured"
        fi
    else
        print_warning "TPM not installed"
    fi

    # 5. Update VS Code extensions
    print_header "Updating VS Code Extensions"
    if command -v code &>/dev/null; then
        print_info "Updating VS Code extensions..."
        if code --update-extensions 2>/dev/null ||
            (code --list-extensions | xargs -L 1 code --install-extension 2>/dev/null); then
            print_success "VS Code extensions updated"
        else
            print_warning "VS Code extensions update failed"
        fi
    else
        print_warning "VS Code not installed"
    fi

    # 6. Update Neovim plugins
    print_header "Updating Neovim Plugins"
    if command -v nvim &>/dev/null && [ -f "$HOME/.config/nvim/init.lua" ]; then
        print_info "Updating Neovim plugins via lazy.nvim..."
        if nvim --headless "+Lazy! sync" +qa 2>/dev/null; then
            print_success "Neovim plugins updated"
        else
            print_warning "Neovim plugins update failed (run :Lazy sync manually)"
        fi
    else
        print_warning "Neovim not configured"
    fi

    # 7. Update pre-commit hooks
    print_header "Updating Pre-commit Hooks"
    if command -v pre-commit &>/dev/null && [ -f ".pre-commit-config.yaml" ]; then
        print_info "Updating pre-commit hooks..."
        if pre-commit autoupdate; then
            print_success "Pre-commit hooks updated"
        else
            print_warning "Pre-commit update failed"
        fi

        print_info "Running pre-commit on all files..."
        if pre-commit run --all-files; then
            print_success "Pre-commit checks passed"
        else
            print_warning "Some pre-commit checks failed (review output)"
        fi
    else
        print_warning "Pre-commit not configured"
    fi

    # 8. Update this repository
    print_header "Updating This Repository"
    if [ -d ".git" ]; then
        print_info "Checking for repository updates..."
        git fetch origin

        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse '@{u}' 2>/dev/null || echo "$LOCAL")

        if [ "$LOCAL" != "$REMOTE" ]; then
            print_warning "Repository has updates available"
            print_info "Run 'git pull' to update (review changes first!)"
        else
            print_success "Repository is up to date"
        fi
    else
        print_warning "Not a git repository"
    fi

    # 9. Check for system updates (macOS only)
    if [[ "$OS" == "darwin" ]]; then
        print_header "Checking macOS Updates"
        print_info "Checking for macOS system updates..."
        if softwareupdate -l 2>&1 | grep -q "No new software available"; then
            print_success "macOS is up to date"
        else
            print_warning "macOS updates available (run: softwareupdate -ia)"
        fi
    fi

    # 10. Summary
    print_header "Update Summary"
    echo -e "${GREEN}Updated:${NC} $UPDATED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo ""

    if [ $FAILED -gt 0 ]; then
        print_warning "Some updates failed. Review output above."
        exit 1
    else
        print_success "All updates completed successfully!"
        echo ""
        print_info "Recommended: Restart your terminal to apply all changes"
        echo ""
    fi
}

# Run main function
main "$@"
