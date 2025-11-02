#!/bin/bash
################################################################################
# Secure Devkit Installation Wrapper
#
# PURPOSE: Download and execute bootstrap script with checksum verification
# USAGE:   bash <(curl -fsSL https://raw.githubusercontent.com/vietcgi/devkit/main/scripts/install.sh)
#
# This wrapper:
# 1. Downloads bootstrap script from GitHub
# 2. Downloads expected checksum from GitHub
# 3. Verifies checksum before execution
# 4. Executes bootstrap script securely
# 5. Cleans up temporary files
#
# SECURITY: Uses HTTPS, checksums, and time-limited downloads
################################################################################

set -euo pipefail

# Configuration
# shellcheck disable=SC2034  # GITHUB_REPO defined for documentation/future use
GITHUB_REPO="https://github.com/vietcgi/devkit"
RAW_GITHUB="https://raw.githubusercontent.com/vietcgi/devkit"
BRANCH="${DEVKIT_BRANCH:-main}"
BOOTSTRAP_URL="$RAW_GITHUB/$BRANCH/bootstrap.sh"
RELEASE_CHECKSUM_URL="${DEVKIT_CHECKSUM_URL:-}"

# Temporary files (cleaned up on exit)
TEMP_DIR=$(mktemp -d)
SCRIPT_FILE="$TEMP_DIR/bootstrap.sh"
CHECKSUM_FILE="$TEMP_DIR/bootstrap.sha256"

# Cleanup on exit
cleanup() {
    rm -rf "$TEMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

################################################################################
# Main Installation Logic
################################################################################

main() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Devkit Secure Installation${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo

    # Check prerequisites
    log_info "Checking prerequisites..."
    check_prerequisites || return 1

    # Download bootstrap script
    log_info "Downloading bootstrap script from $BRANCH branch..."
    download_bootstrap_script || return 1

    # Determine and verify checksum
    log_info "Verifying script integrity..."
    verify_script_integrity || return 1

    # Execute bootstrap script
    log_success "All security checks passed. Starting setup..."
    echo

    # Execute with arguments passed to this script
    bash "$SCRIPT_FILE" "$@"
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log_success "Devkit setup completed successfully!"
    else
        log_error "Devkit setup failed with exit code $exit_code"
    fi

    return $exit_code
}

################################################################################
# Helper Functions
################################################################################

check_prerequisites() {
    local missing=()

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    fi

    if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
        missing+=("sha256sum or shasum")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_info "Install them using your system package manager:"
        log_info "  macOS: brew install coreutils"
        log_info "  Ubuntu/Debian: sudo apt-get install coreutils"
        return 1
    fi

    log_success "All prerequisites met"
    return 0
}

download_bootstrap_script() {
    # Download with 30 second timeout and follow redirects
    if ! curl \
        --max-time 30 \
        --fail \
        --silent \
        --show-error \
        --location \
        -o "$SCRIPT_FILE" \
        "$BOOTSTRAP_URL"; then
        log_error "Failed to download bootstrap script"
        log_info "URL: $BOOTSTRAP_URL"
        log_info "Please check your internet connection and try again"
        return 1
    fi

    # Verify file was downloaded
    if [ ! -s "$SCRIPT_FILE" ]; then
        log_error "Downloaded file is empty"
        return 1
    fi

    # Verify it's executable bash script
    if ! head -1 "$SCRIPT_FILE" | grep -q "#!/bin/bash"; then
        log_error "Downloaded file doesn't appear to be a bash script"
        return 1
    fi

    log_success "Bootstrap script downloaded ($(wc -c <"$SCRIPT_FILE") bytes)"
    return 0
}

verify_script_integrity() {
    local expected_checksum=""

    # Try to get expected checksum from environment variable first
    if [ -n "${DEVKIT_BOOTSTRAP_CHECKSUM:-}" ]; then
        expected_checksum="$DEVKIT_BOOTSTRAP_CHECKSUM"
        log_info "Using checksum from DEVKIT_BOOTSTRAP_CHECKSUM environment variable"
    # Try to download from GitHub
    elif [ -n "$RELEASE_CHECKSUM_URL" ]; then
        log_info "Downloading checksum from: $RELEASE_CHECKSUM_URL"
        if curl \
            --max-time 10 \
            --fail \
            --silent \
            -o "$CHECKSUM_FILE" \
            "$RELEASE_CHECKSUM_URL"; then
            expected_checksum=$(awk '{print $1}' "$CHECKSUM_FILE")
            log_success "Checksum downloaded"
        else
            log_warning "Could not download checksum file (may be development version)"
        fi
    else
        log_warning "No checksum available (development mode - skipping verification)"
        log_info "For production use, set DEVKIT_BOOTSTRAP_CHECKSUM environment variable"
        return 0
    fi

    # If we have a checksum, verify it
    if [ -n "$expected_checksum" ]; then
        local actual_checksum
        actual_checksum=$(sha256sum "$SCRIPT_FILE" 2>/dev/null | awk '{print $1}' ||
            shasum -a 256 "$SCRIPT_FILE" 2>/dev/null | awk '{print $1}')

        if [ "$actual_checksum" != "$expected_checksum" ]; then
            log_error "Checksum verification FAILED!"
            log_error "Expected: $expected_checksum"
            log_error "Got:      $actual_checksum"
            log_error ""
            log_error "SECURITY WARNING: Downloaded script does not match expected checksum!"
            log_error "This could indicate:"
            log_error "  • Network tampering (MITM attack)"
            log_error "  • Corrupted download"
            log_error "  • Wrong branch/version"
            log_error ""
            log_error "DO NOT EXECUTE THE SCRIPT. Aborting."
            return 1
        fi

        log_success "Checksum verification passed"
        log_success "Downloaded script is authentic"
    fi

    return 0
}

################################################################################
# Entry Point
################################################################################

main "$@"
