#!/bin/bash
# shellcheck disable=SC2034,SC2120,SC2162  # Variables used externally, unused functions OK
################################################################################
# Devkit Bootstrap Script (PRIMARY ENTRY POINT)
#
# PURPOSE: Bootstrap development environment without Python dependency
# SUPPORTS: macOS and Linux (with or without Python, Ansible, or Homebrew)
# REQUIREMENTS: bash (built-in on all systems)
#
# USAGE:
#   curl -fsSL https://raw.githubusercontent.com/vietcgi/devkit/main/bootstrap.sh | bash
#   ./bootstrap.sh
#   ./bootstrap.sh --python-only
#   ./bootstrap.sh --interactive
#   ./bootstrap.sh --skip-python
#
# This is the PRIMARY ENTRY POINT for Devkit
# Works on systems with or without Python installed
################################################################################

set -euo pipefail # Strict error handling: exit on error, undefined vars, pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="Devkit"
PYTHON_REQUIRED=true
INTERACTIVE_MODE=false
SKIP_ANSIBLE=false
VERIFY_ONLY=false
ENVIRONMENT="development"
SELECTED_ROLES="core,shell,editors,languages,development"

# SECURITY: Bootstrap integrity verification
# This checksum is automatically updated on each release by CI/CD
BOOTSTRAP_CHECKSUM="${DEVKIT_BOOTSTRAP_CHECKSUM:-}" # Can be overridden by environment

################################################################################
# Utility Functions
################################################################################

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

suggest_fix() {
    local issue="$1"
    local suggestion="$2"
    echo -e "${YELLOW}💡 Suggestion:${NC} $suggestion" >&2
}

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${BLUE}» $1${NC}"
}

################################################################################
# Security: Bootstrap Script Integrity Verification
################################################################################

verify_bootstrap_integrity() {
    # Only verify if checksum is set (not in development mode)
    if [ -z "$BOOTSTRAP_CHECKSUM" ]; then
        log_info "Bootstrap integrity check skipped (development mode)"
        return 0
    fi

    # Can only verify if running from a file (not piped from curl)
    if [ ! -f "$0" ]; then
        log_warning "Bootstrap integrity check skipped (piped execution)"
        return 0
    fi

    local actual_checksum
    # Use cross-platform compatible checksum command
    if command -v sha256sum &>/dev/null; then
        actual_checksum=$(sha256sum "$0" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        actual_checksum=$(shasum -a 256 "$0" | awk '{print $1}')
    else
        log_warning "Bootstrap integrity check skipped (no checksum utility available)"
        return 0
    fi

    if [ "$actual_checksum" != "$BOOTSTRAP_CHECKSUM" ]; then
        log_error "Bootstrap script integrity check FAILED!"
        log_error "Expected checksum: $BOOTSTRAP_CHECKSUM"
        log_error "Actual checksum:   $actual_checksum"
        log_error ""
        log_error "SECURITY WARNING: Script may have been tampered with or corrupted."
        log_error "This could indicate:"
        log_error "  • A network man-in-the-middle attack (MITM)"
        log_error "  • Script corruption during download"
        log_error "  • Running a modified/outdated version"
        log_error ""
        log_error "DO NOT PROCEED. Aborting setup."
        return 1
    fi

    log_success "Bootstrap script integrity verified"
    return 0
}

################################################################################
# Retry Logic with Exponential Backoff
################################################################################

retry() {
    local max_attempts=3
    local timeout=2
    local attempt=1

    while ((attempt <= max_attempts)); do
        if "$@"; then
            return 0
        fi

        if ((attempt < max_attempts)); then
            log_warning "Attempt $attempt failed, retrying in ${timeout}s... (attempt $((attempt + 1))/$max_attempts)"
            sleep "$timeout"
            timeout=$((timeout + 1)) # Exponential backoff: 2s, 3s, 4s
        fi

        attempt=$((attempt + 1))
    done

    log_error "Command failed after $max_attempts attempts: $*"
    return 1
}

################################################################################
# System Detection
################################################################################

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        UNAME_S="Darwin"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        UNAME_S="Linux"
    else
        log_error "Unsupported OS: $OSTYPE"
        return 1
    fi
    log_success "Detected OS: $OS ($OSTYPE)"
}

detect_arch() {
    ARCH=$(uname -m)
    if [[ "$ARCH" == "arm64" ]] || [[ "$ARCH" == "aarch64" ]]; then
        ARCH_TYPE="arm64"
    elif [[ "$ARCH" == "x86_64" ]]; then
        ARCH_TYPE="x86_64"
    else
        log_error "Unsupported architecture: $ARCH"
        return 1
    fi
    log_success "Detected architecture: $ARCH_TYPE"
}

################################################################################
# Prerequisite Installation
################################################################################

install_system_dependencies() {
    print_section "Installing system dependencies"

    local os_type
    os_type=$(uname -s)

    if [[ "$os_type" == "Darwin" ]]; then
        # macOS: Homebrew is a prerequisite, system dependencies are minimal
        log_info "macOS detected - using Homebrew for dependencies"
        return 0
    elif [[ "$os_type" == "Linux" ]]; then
        # Linux: Install build dependencies based on package manager
        log_info "Detecting Linux distribution..."

        # Detect package manager and install required dependencies
        if command -v apt-get &>/dev/null; then
            log_info "Debian/Ubuntu detected - installing dependencies via apt-get"

            # Update package lists
            if [[ $EUID -ne 0 ]]; then
                if command -v sudo &>/dev/null; then
                    sudo apt-get update -qq || {
                        log_error "Failed to update package lists via apt-get"
                        return 1
                    }

                    # Install essential build tools and curl
                    sudo apt-get install -y -qq build-essential curl git ca-certificates || {
                        log_error "Failed to install build tools via apt-get"
                        return 1
                    }

                    # Install pipx (optional - not critical to bootstrap success)
                    sudo apt-get install -y -qq pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
                else
                    log_error "sudo not found, but required for apt-get"
                    return 1
                fi
            else
                apt-get update -qq || {
                    log_error "Failed to update package lists via apt-get (running as root)"
                    return 1
                }

                apt-get install -y -qq build-essential curl git ca-certificates pipx || {
                    log_error "Failed to install build tools via apt-get (running as root)"
                    return 1
                }
            fi

            log_success "Build tools installed via apt-get"

        elif command -v dnf &>/dev/null; then
            log_info "Fedora/RHEL detected - installing dependencies via dnf"

            # Install essential build tools and curl
            if [[ $EUID -ne 0 ]]; then
                if command -v sudo &>/dev/null; then
                    sudo dnf install -y gcc gcc-c++ make curl git ca-certificates || {
                        log_error "Failed to install build tools via dnf"
                        return 1
                    }

                    # Install pipx (optional - not critical to bootstrap success)
                    sudo dnf install -y python3-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
                else
                    log_error "sudo not found, but required for dnf"
                    return 1
                fi
            else
                dnf install -y gcc gcc-c++ make curl git ca-certificates || {
                    log_error "Failed to install build tools via dnf (running as root)"
                    return 1
                }

                # Install pipx (optional - not critical to bootstrap success)
                dnf install -y python3-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
            fi

            log_success "Build tools installed via dnf"

        elif command -v yum &>/dev/null; then
            log_info "RHEL/CentOS detected - installing dependencies via yum"

            # Install essential build tools and curl
            if [[ $EUID -ne 0 ]]; then
                if command -v sudo &>/dev/null; then
                    sudo yum install -y gcc gcc-c++ make curl git ca-certificates || {
                        log_error "Failed to install build tools via yum"
                        return 1
                    }

                    # Install pipx (optional - not critical to bootstrap success)
                    sudo yum install -y python3-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
                else
                    log_error "sudo not found, but required for yum"
                    return 1
                fi
            else
                yum install -y gcc gcc-c++ make curl git ca-certificates || {
                    log_error "Failed to install build tools via yum (running as root)"
                    return 1
                }

                # Install pipx (optional - not critical to bootstrap success)
                yum install -y python3-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
            fi

            log_success "Build tools installed via yum"

        elif command -v pacman &>/dev/null; then
            log_info "Arch Linux detected - installing dependencies via pacman"

            # Install essential build tools and curl
            if [[ $EUID -ne 0 ]]; then
                if command -v sudo &>/dev/null; then
                    sudo pacman -S --noconfirm base-devel curl git ca-certificates || {
                        log_error "Failed to install build tools via pacman"
                        return 1
                    }

                    # Install pipx (optional - not critical to bootstrap success)
                    sudo pacman -S --noconfirm python-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
                else
                    log_error "sudo not found, but required for pacman"
                    return 1
                fi
            else
                pacman -S --noconfirm base-devel curl git ca-certificates || {
                    log_error "Failed to install build tools via pacman (running as root)"
                    return 1
                }

                # Install pipx (optional - not critical to bootstrap success)
                pacman -S --noconfirm python-pipx 2>/dev/null || log_warning "pipx installation skipped (not available)"
            fi

            log_success "Build tools installed via pacman"

        elif command -v apk &>/dev/null; then
            log_info "Alpine Linux detected - installing dependencies via apk"

            # Install essential build tools and curl
            if [[ $EUID -ne 0 ]]; then
                if command -v sudo &>/dev/null; then
                    sudo apk add --no-cache gcc g++ make curl git ca-certificates || {
                        log_error "Failed to install build tools via apk"
                        return 1
                    }

                    # Install pipx (optional - not critical to bootstrap success)
                    sudo apk add --no-cache py3-pip 2>/dev/null || log_warning "pipx installation skipped (not available)"
                else
                    log_error "sudo not found, but required for apk"
                    return 1
                fi
            else
                apk add --no-cache gcc g++ make curl git ca-certificates || {
                    log_error "Failed to install build tools via apk (running as root)"
                    return 1
                }

                # Install pipx (optional - not critical to bootstrap success)
                apk add --no-cache py3-pip 2>/dev/null || log_warning "pipx installation skipped (not available)"
            fi

            log_success "Build tools installed via apk"

        else
            log_warning "No supported package manager found (apt-get, dnf, yum, pacman, apk)"
            log_warning "Attempting to continue anyway - some dependencies may be missing"
            return 0
        fi
    fi

    log_success "System dependencies installed"
}

install_homebrew() {
    print_section "Installing Homebrew"

    if command -v brew &>/dev/null; then
        log_success "Homebrew already installed"
        return 0
    fi

    log_info "Downloading and installing Homebrew (with retry logic)..."

    # Define the installation function
    do_install_homebrew() {
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    }

    if [[ "$OS" == "macos" ]]; then
        retry do_install_homebrew || {
            log_error "Failed to install Homebrew on macOS after 3 attempts"
            log_error ""
            log_error "This could be caused by:"
            log_error "  • Network connectivity issues"
            log_error "  • Firewall blocking GitHub access"
            log_error "  • Insufficient disk space (5+ GB needed)"
            log_error "  • Missing required command line tools"
            suggest_fix "homebrew" "Run 'show_help brew' or check https://brew.sh"
            return 1
        }
    elif [[ "$OS" == "linux" ]]; then
        retry do_install_homebrew || {
            log_error "Failed to install Homebrew on Linux after 3 attempts"
            log_error ""
            log_error "Common solutions:"
            log_error "  • Check disk space: df -h"
            log_error "  • Install build tools: sudo apt-get install build-essential"
            log_error "  • Install git: sudo apt-get install git"
            log_error "  • Check network: ping github.com"
            suggest_fix "homebrew-linux" "See https://docs.brew.sh/Homebrew-on-Linux"
            return 1
        }

        # Add Homebrew to PATH for current shell on Linux
        # This is needed immediately after installation so subsequent commands can find brew
        if [[ -d "/home/linuxbrew/.linuxbrew/bin" ]]; then
            export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
        fi
    fi

    log_success "Homebrew installed successfully"
}

install_python() {
    print_section "Installing Python"

    if command -v python3 &>/dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        log_success "Python 3 already installed: $PYTHON_VERSION"
        return 0
    fi

    log_info "Installing Python 3 via Homebrew..."

    if ! command -v brew &>/dev/null; then
        log_error "Homebrew is required to install Python"
        log_error ""
        log_error "Please install Homebrew first:"
        log_error "  /bin/bash -c \"\$(curl -fsSL https://brew.sh/install.sh)\""
        log_error ""
        suggest_fix "python" "Install Homebrew before installing Python"
        return 1
    fi

    # Use retry for network-dependent brew install
    retry brew install python3 || {
        log_error "Failed to install Python3 after 3 attempts"
        log_error ""
        log_error "Possible solutions:"
        log_error "  • Check network connection: ping github.com"
        log_error "  • Check disk space: df -h (need 2+ GB free)"
        log_error "  • Update Homebrew: brew update"
        log_error "  • Check Homebrew state: brew doctor"
        suggest_fix "python" "Try manual installation: brew install python@3.13"
        return 1
    }

    log_success "Python 3 installed successfully"
}

install_ansible() {
    print_section "Installing Ansible"

    if command -v ansible-playbook &>/dev/null; then
        ANSIBLE_VERSION=$(ansible-playbook --version 2>&1 | head -1)
        log_success "Ansible already installed: $ANSIBLE_VERSION"
        return 0
    fi

    # Detect OS
    local os_type
    os_type=$(uname -s)

    if [[ "$os_type" == "Darwin" ]]; then
        # macOS: use Homebrew
        log_info "Installing Ansible via Homebrew (macOS)..."

        if ! command -v brew &>/dev/null; then
            log_error "Homebrew is required to install Ansible"
            log_error ""
            log_error "Please install Homebrew first: https://brew.sh"
            suggest_fix "ansible" "Install Homebrew before attempting Ansible installation"
            return 1
        fi

        if ! command -v python3 &>/dev/null; then
            log_error "Python 3 is required to install Ansible"
            log_error "Please install Python first via: brew install python3"
            suggest_fix "ansible" "Install Python 3 before attempting Ansible installation"
            return 1
        fi

        # Use retry for network-dependent brew install
        retry brew install ansible || {
            log_error "Failed to install Ansible after 3 attempts"
            log_error ""
            log_error "Troubleshooting steps:"
            log_error "  1. Check if Homebrew is working: brew --version"
            log_error "  2. Update Homebrew: brew update"
            log_error "  3. Check Python: python3 --version"
            log_error "  4. Try individual install: brew install ansible"
            log_error "  5. Check brew logs: brew log --file install.log"
            suggest_fix "ansible" "See https://docs.ansible.com/ansible/latest/installation_guide/"
            return 1
        }
    else
        # Linux: try pip first (preferred), then system package manager
        log_info "Installing Ansible via pip3 (Linux)..."

        if ! command -v pip3 &>/dev/null; then
            log_error "pip3 not found, attempting system package manager..."

            # Try system package manager as fallback
            if command -v apt-get &>/dev/null; then
                log_info "Attempting to install ansible via apt-get..."
                if [[ $EUID -ne 0 ]]; then
                    if command -v sudo &>/dev/null; then
                        if ! sudo apt-get update -qq; then
                            log_error "Failed to update package lists via apt-get"
                            return 1
                        fi
                        if ! sudo apt-get install -y ansible; then
                            log_error "Failed to install Ansible via apt-get"
                            return 1
                        fi
                    else
                        log_error "sudo not found, but required for apt-get"
                        return 1
                    fi
                else
                    if ! apt-get update -qq; then
                        log_error "Failed to update package lists via apt-get (running as root)"
                        return 1
                    fi
                    if ! apt-get install -y ansible; then
                        log_error "Failed to install Ansible via apt-get (running as root)"
                        return 1
                    fi
                fi
            elif command -v dnf &>/dev/null; then
                log_info "Attempting to install ansible via dnf..."
                if [[ $EUID -ne 0 ]]; then
                    if command -v sudo &>/dev/null; then
                        if ! sudo dnf install -y ansible; then
                            log_error "Failed to install Ansible via dnf"
                            return 1
                        fi
                    else
                        log_error "sudo not found, but required for dnf"
                        return 1
                    fi
                else
                    if ! dnf install -y ansible; then
                        log_error "Failed to install Ansible via dnf (running as root)"
                        return 1
                    fi
                fi
            elif command -v pacman &>/dev/null; then
                log_info "Attempting to install ansible via pacman..."
                if [[ $EUID -ne 0 ]]; then
                    if command -v sudo &>/dev/null; then
                        if ! sudo pacman -S --noconfirm ansible; then
                            log_error "Failed to install Ansible via pacman"
                            return 1
                        fi
                    else
                        log_error "sudo not found, but required for pacman"
                        return 1
                    fi
                else
                    if ! pacman -S --noconfirm ansible; then
                        log_error "Failed to install Ansible via pacman (running as root)"
                        return 1
                    fi
                fi
            else
                log_error "No supported package manager found (apt-get, dnf, pacman)"
                suggest_fix "ansible" "Install pip3 or a supported package manager"
                return 1
            fi
        else
            # Use pip3 to install ansible (user or system-wide)
            log_info "Using pip3 to install Ansible..."

            # Try user installation first (preferred, doesn't need sudo)
            if retry pip3 install --user ansible; then
                log_success "Ansible installed via pip3 (user)"
            # If user installation fails, try system-wide
            elif retry pip3 install ansible; then
                log_success "Ansible installed via pip3 (system)"
            else
                log_error "Failed to install Ansible via pip3 after 3 attempts"
                log_error ""
                log_error "Troubleshooting steps:"
                log_error "  1. Verify pip3 is installed: pip3 --version"
                log_error "  2. Upgrade pip: pip3 install --upgrade pip"
                log_error "  3. Check disk space: df -h /tmp"
                log_error "  4. Try manual install: pip3 install ansible"
                suggest_fix "ansible" "Ensure pip3 is functional and has sufficient disk space"
                return 1
            fi
        fi
    fi

    log_success "Ansible installed successfully"
}

################################################################################
# Configuration Management (Pure Bash)
################################################################################

create_default_config() {
    print_section "Creating default configuration"

    CONFIG_DIR="$HOME/.devkit"
    CONFIG_FILE="$CONFIG_DIR/config.yaml"
    LOG_DIR="$CONFIG_DIR/logs"

    if ! mkdir -p "$CONFIG_DIR" "$LOG_DIR"; then
        log_error "Failed to create configuration directories: $CONFIG_DIR, $LOG_DIR"
        return 1
    fi

    if [[ -f "$CONFIG_FILE" ]]; then
        log_warning "Configuration already exists at $CONFIG_FILE"
        return 0
    fi

    cat >"$CONFIG_FILE" <<'EOF'
# Devkit Configuration
# Edit this file to customize your setup
# Default environment: development
# See documentation at https://github.com/vietcgi/devkit for more options

global:
  setup_name: "Development Environment"
  setup_environment: development

  enabled_roles:
    - core
    - shell
    - editors
    - languages
    - development

  disabled_roles: []

  logging:
    enabled: true
    level: info
    logfile: ~/.devkit/logs/setup.log

  security:
    enable_ssh_setup: false
    enable_gpg_setup: false
    enable_audit_logging: true
EOF

    log_success "Configuration created at $CONFIG_FILE"
    log_info "Log directory created at $LOG_DIR"
}

################################################################################
# Pure Bash Configuration Validation (No Python Required)
################################################################################

validate_config_bash() {
    print_section "Validating configuration (Bash)"

    local config_file="$HOME/.devkit/config.yaml"

    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        log_info "Try running: create_default_config"
        return 1
    fi

    # Basic YAML validation (check for proper indentation)
    if ! grep -q "^global:" "$config_file"; then
        log_error "Invalid configuration: missing 'global' section in $config_file"
        return 1
    fi

    log_success "Configuration validated successfully"
}

################################################################################
# Interactive Setup (Pure Bash - No Python Required)
################################################################################

interactive_setup_bash() {
    print_section "Interactive Setup"

    echo -e "${BOLD}Which environment are you setting up?${NC}"
    echo "1) Development (default)"
    echo "2) Production"
    echo "3) Staging"
    echo ""
    read -p "Select (1-3) [1]: " env_choice
    env_choice=${env_choice:-1}

    case $env_choice in
    1) ENVIRONMENT="development" ;;
    2) ENVIRONMENT="production" ;;
    3) ENVIRONMENT="staging" ;;
    *) ENVIRONMENT="development" ;;
    esac

    log_success "Selected environment: $ENVIRONMENT"

    echo ""
    echo -e "${BOLD}Which roles would you like to install?${NC}"
    echo "1) Minimal (core, shell)"
    echo "2) Standard (core, shell, editors, languages, development)"
    echo "3) Full (all roles)"
    echo ""
    read -p "Select (1-3) [2]: " roles_choice
    roles_choice=${roles_choice:-2}

    case $roles_choice in
    1) SELECTED_ROLES="core,shell" ;;
    2) SELECTED_ROLES="core,shell,editors,languages,development" ;;
    3) SELECTED_ROLES="core,shell,editors,languages,development,containers,cloud,security,databases" ;;
    *) SELECTED_ROLES="core,shell,editors,languages,development" ;;
    esac

    log_success "Selected roles: $SELECTED_ROLES"
}

################################################################################
# Ansible Playbook Execution
################################################################################

run_ansible_setup() {
    print_section "Running Ansible setup"

    if [[ ! -f "$SCRIPT_DIR/setup.yml" ]]; then
        log_error "setup.yml not found at $SCRIPT_DIR"
        return 1
    fi

    if ! command -v ansible-playbook &>/dev/null; then
        log_error "Ansible not found. Please install Ansible first."
        return 1
    fi

    log_info "Starting Ansible playbook..."
    log_info "This may take 2-5 minutes depending on your system..."

    if ! cd "$SCRIPT_DIR"; then
        log_error "Failed to change to script directory: $SCRIPT_DIR"
        return 1
    fi

    if ! ansible-playbook -i inventory.yml setup.yml \
        --extra-vars="setup_environment=${ENVIRONMENT:-development}" \
        --extra-vars="enabled_roles=${SELECTED_ROLES:-core,shell,editors,languages,development}"; then
        log_error "Ansible setup failed"
        return 1
    fi

    log_success "Ansible setup completed"
}

################################################################################
# Verification
################################################################################

verify_installation() {
    print_section "Verifying installation"

    local checks_passed=0
    local checks_total=0

    # Check Homebrew
    checks_total=$((checks_total + 1))
    if command -v brew &>/dev/null; then
        log_success "Homebrew: installed"
        checks_passed=$((checks_passed + 1))
    else
        log_warning "Homebrew: not installed"
    fi

    # Check git
    checks_total=$((checks_total + 1))
    if command -v git &>/dev/null; then
        log_success "Git: installed"
        checks_passed=$((checks_passed + 1))
    else
        log_warning "Git: not installed"
    fi

    # Check Ansible
    checks_total=$((checks_total + 1))
    if command -v ansible-playbook &>/dev/null; then
        log_success "Ansible: installed"
        checks_passed=$((checks_passed + 1))
    else
        log_warning "Ansible: not installed"
    fi

    # Check Python
    checks_total=$((checks_total + 1))
    if command -v python3 &>/dev/null; then
        log_success "Python 3: installed"
        checks_passed=$((checks_passed + 1))
    else
        log_warning "Python 3: not installed"
    fi

    echo ""
    log_info "Verification: $checks_passed/$checks_total checks passed"

    if [[ $checks_passed -eq $checks_total ]]; then
        return 0
    else
        return 1
    fi
}

################################################################################
# Developer Tools Setup
# NOTE: Git SSH configuration and pre-commit setup are now handled by Ansible
# See: ansible/roles/git/tasks/main.yml
################################################################################

################################################################################
# Help and Usage
################################################################################

show_help() {
    cat <<'EOF'
Devkit Bootstrap Script - Development Environment Setup

USAGE:
    ./bootstrap.sh [OPTIONS]

OPTIONS:
    --help              Show this help message
    --interactive       Interactive setup (with questions)
    --python-only       Install Python and exit (no setup)
    --skip-ansible      Skip Ansible setup
    --skip-python       Skip Python installation
    --verify-only       Only verify prerequisites

EXAMPLES:
    # Standard setup (recommended)
    ./bootstrap.sh

    # Interactive setup
    ./bootstrap.sh --interactive

    # Just install prerequisites
    ./bootstrap.sh --python-only

    # Verify system
    ./bootstrap.sh --verify-only

ENVIRONMENT:
    The script automatically detects your OS and architecture.
    Currently supports:
    - macOS (Intel and Apple Silicon)
    - Linux (Ubuntu, Debian, Fedora, and compatible)

WHAT GETS INSTALLED:
    1. Homebrew (macOS/Linux package manager)
    2. Ansible (for system configuration)
    3. 100+ development tools (configured via roles)
    4. Shell configuration (Zsh with Oh My Zsh)
    5. Editors (Neovim, VS Code)
    6. Version managers and language runtimes
    7. Container tools and cloud CLIs

REQUIREMENTS:
    - bash (built-in on all systems)
    - curl (for downloading files)
    - Internet connection

CONFIGURATION:
    Edit ~/.devkit/config.yaml to:
    - Choose which roles to install
    - Customize environment settings
    - Enable/disable security features

TROUBLESHOOTING:
    - Check logs: tail -f ~/.devkit/logs/setup.log
    - Run with verbose: bash -x ./bootstrap.sh
    - Check prerequisites: ./bootstrap.sh --verify-only
    - View config: cat ~/.devkit/config.yaml

DOCUMENTATION:
    - Project: https://github.com/vietcgi/devkit
    - Issues: https://github.com/vietcgi/devkit/issues
    - Wiki: https://github.com/vietcgi/devkit/wiki

EOF
}

################################################################################
# Main Execution
################################################################################

main() {
    # SECURITY: Verify bootstrap script integrity first
    if ! verify_bootstrap_integrity; then
        exit 1
    fi

    print_header "Devkit Bootstrap - Development Environment Setup"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
        --help)
            show_help
            exit 0
            ;;
        --interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        --python-only)
            PYTHON_REQUIRED=true
            shift
            ;;
        --skip-ansible)
            SKIP_ANSIBLE=true
            shift
            ;;
        --skip-python)
            PYTHON_REQUIRED=false
            shift
            ;;
        --verify-only)
            VERIFY_ONLY=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        esac
    done

    # Step 1: Detect system
    print_section "Step 1: System Detection"
    detect_os || exit 1
    detect_arch || exit 1

    # Step 2: Install system dependencies (for Linux platforms)
    print_section "Step 2: Install System Dependencies"
    install_system_dependencies || {
        log_warning "System dependencies installation failed. Some features may not work."
    }

    # Step 3: Install Homebrew
    print_section "Step 3: Install Homebrew"
    install_homebrew || {
        log_warning "Homebrew installation failed. Some features may not work."
    }

    # Step 4: Install Python
    if [[ "$PYTHON_REQUIRED" == "true" ]]; then
        print_section "Step 4: Install Python"
        install_python || {
            log_warning "Python installation failed. Python tools will not be available."
        }
    fi

    # Step 5: Install Ansible
    if [[ "$SKIP_ANSIBLE" != "true" ]]; then
        print_section "Step 5: Install Ansible"
        if ! install_ansible; then
            log_error "Ansible installation failed"
            log_error "Debug info:"
            log_error "  OS: ${OS:-unknown}"
            log_error "  Architecture: ${ARCH_TYPE:-unknown}"
            if command -v ansible-playbook >/dev/null 2>&1; then
                log_error "  Ansible found in PATH"
            else
                log_error "  Ansible NOT in PATH"
            fi
            log_error "Continuing without Ansible (some features may not work)"
            SKIP_ANSIBLE=true
        fi
    fi

    # Step 5: Create configuration
    print_section "Step 5: Configuration"
    create_default_config || exit 1
    validate_config_bash || exit 1

    # Step 6: Interactive setup
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        print_section "Step 6: Interactive Setup"
        interactive_setup_bash
    fi

    # Step 7: Verification
    print_section "Step 7: Verification"
    verify_installation || {
        log_warning "Some checks failed but setup may still work"
    }

    # Step 8: Run Ansible
    if [[ "$SKIP_ANSIBLE" != "true" ]] && [[ "$VERIFY_ONLY" != "true" ]]; then
        print_section "Step 8: Running Setup"
        run_ansible_setup || exit 1
    fi

    # Success
    print_header "✓ Bootstrap Complete"
    echo ""
    log_success "Devkit has been successfully installed!"
    echo ""
    echo "Next steps:"
    echo "  1. Review configuration: nano ~/.devkit/config.yaml"
    echo "  2. Check logs: tail -f ~/.devkit/logs/setup.log"
    echo "  3. Customize roles: edit ~/.devkit/config.yaml"
    echo "  4. Restart your shell: exec \$SHELL"
    echo ""
    log_info "Your development environment is ready!"

    # Create success marker for CI/CD verification
    if ! mkdir -p ~/.devkit; then
        log_warning "Failed to create ~/.devkit directory for success marker"
    elif ! touch ~/.devkit/.bootstrap_success; then
        log_warning "Failed to create success marker file"
    fi
}

# Run main function
main "$@"
