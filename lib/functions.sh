#!/bin/bash
################################################################################
# Devkit Common Shell Functions Library
#
# This file contains shared utility functions used across all shell scripts
# in the Devkit project. It centralizes:
# - Logging functions (with colored output)
# - System detection utilities
# - Retry logic with exponential backoff
# - Header and section printing
#
# Usage:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/functions.sh"
#
# Color Definitions:
#   RED: Error and critical messages
#   GREEN: Success messages
#   YELLOW: Warnings and informational prompts
#   BLUE: Headers and general information
#   NC: No Color (reset)
################################################################################

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================================
# LOGGING FUNCTIONS
#
# These functions provide consistent colored output across all scripts.
# Each function outputs to the appropriate stream (stdout for info/success,
# stderr for warnings/errors) to maintain proper Unix semantics.
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1" >&2
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

suggest_fix() {
    local suggestion="$1"
    echo -e "${YELLOW}💡 Suggestion:${NC} $suggestion" >&2
}

# ============================================================================
# HEADER AND SECTION PRINTING
#
# These functions format output for better visual hierarchy and readability
# in shell script output.
# ============================================================================

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

# ============================================================================
# SYSTEM DETECTION
#
# Functions to detect operating system and architecture at runtime.
# Results are printed to stdout so they can be captured by calling code.
# ============================================================================

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    if [[ "$arch" == "arm64" ]] || [[ "$arch" == "aarch64" ]]; then
        echo "arm64"
    elif [[ "$arch" == "x86_64" ]]; then
        echo "x86_64"
    else
        echo "unknown"
    fi
}

# ============================================================================
# RETRY LOGIC WITH EXPONENTIAL BACKOFF
#
# Executes a command with automatic retries and exponential backoff.
# Useful for network operations and other transient failures.
#
# Parameters:
#   $1: Initial timeout in seconds (default: 2)
#   $2...: Command and arguments to execute
#
# Returns:
#   0 if command succeeds on any attempt
#   1 if command fails after all retries
#
# Example:
#   retry 2 curl -fsSL https://example.com/script.sh
# ============================================================================

retry() {
    local max_attempts=3
    local timeout=2
    local attempt=1

    # Check if first argument is a timeout value
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        timeout=$1
        shift
    fi

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

# ============================================================================
# EXPORT FUNCTIONS
#
# Make all functions available to scripts that source this library
# ============================================================================

export -f log_info
export -f log_success
export -f log_warning
export -f log_error
export -f suggest_fix
export -f print_header
export -f print_section
export -f detect_os
export -f detect_arch
export -f retry
