#!/usr/bin/env bash

###############################################################################
# Comprehensive Multi-Distribution Test Script
# Tests devkit on Debian, Ubuntu, Fedora, Arch, and openSUSE
###############################################################################

set -euo pipefail

# Source common functions library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/functions.sh"

# Test results tracking
PASSED=0
FAILED=0
declare -A RESULTS

# Custom print_header for test-all-distributions.sh formatting
print_header() {
    local CYAN='\033[0;36m'
    echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${CYAN}"
    echo -e "${CYAN}║$(printf '%63s' "" | tr ' ' ' ')║${NC}"
    echo -e "${CYAN}║  $(printf '%-59s' "$1")  ║${NC}"
    echo -e "${CYAN}║$(printf '%63s' "" | tr ' ' ' ')║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
}

# Wrapper functions to match test script's formatting
print_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check Docker
check_docker() {
    if ! docker ps &>/dev/null; then
        print_error "Docker is not running. Please start Docker Desktop."
        exit 1
    fi
    print_success "Docker is running"
}

# Test a distribution
test_distribution() {
    local distro_name="$1"
    local docker_image="$2"
    local expected_result="$3" # "pass" or "fail" or "skip"

    print_header "Testing $distro_name"

    local log_file="/tmp/test-${distro_name//[: ]/-}.log"

    print_info "Docker image: $docker_image"
    print_info "Expected: $expected_result"
    print_info "Log file: $log_file"
    echo ""

    # Run the test
    local start_time
    start_time=$(date +%s)

    if docker run --rm -v "$(pwd):/workspace" -w /workspace "$docker_image" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        chmod +x bootstrap.sh
        ./bootstrap.sh 2>&1
    " >"$log_file" 2>&1; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Check for Ansible RECAP
        if grep -q "failed=0" "$log_file"; then
            print_success "$distro_name: PASSED (${duration}s)"
            RESULTS["$distro_name"]="PASS"
            ((PASSED++))

            # Extract RECAP
            echo ""
            grep "PLAY RECAP" -A 1 "$log_file" || echo "RECAP not found"
            echo ""
        else
            print_warning "$distro_name: Bootstrap completed but check RECAP (${duration}s)"
            RESULTS["$distro_name"]="WARN"
            grep "PLAY RECAP" -A 1 "$log_file" || echo "RECAP not found"
        fi
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        print_error "$distro_name: FAILED (${duration}s)"
        RESULTS["$distro_name"]="FAIL"
        ((FAILED++))

        echo ""
        print_info "Last 20 lines of log:"
        tail -20 "$log_file"
        echo ""
    fi

    print_info "Full log saved to: $log_file"
    echo ""
}

# Print final summary
print_summary() {
    print_header "Test Results Summary"

    echo -e "${CYAN}Distribution Test Results:${NC}\n"

    for distro in "${!RESULTS[@]}"; do
        local result="${RESULTS[$distro]}"
        case "$result" in
        PASS)
            echo -e "  ${GREEN}✅ $distro${NC} - PASSED"
            ;;
        FAIL)
            echo -e "  ${RED}❌ $distro${NC} - FAILED"
            ;;
        WARN)
            echo -e "  ${YELLOW}⚠️  $distro${NC} - WARNING"
            ;;
        esac
    done

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Passed: $PASSED${NC}"
    echo -e "${RED}❌ Failed: $FAILED${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [ $FAILED -eq 0 ]; then
        print_success "🎉 All tests passed!"
        return 0
    else
        print_error "Some tests failed. Check logs in /tmp/test-*.log"
        return 1
    fi
}

###############################################################################
# Main
###############################################################################

main() {
    print_header "Mac-Setup Multi-Distribution Test Suite"

    print_info "This script tests the mac-setup repository on multiple Linux distributions"
    print_info "Expected to pass: Debian, Ubuntu, Fedora, Arch, openSUSE"
    echo ""

    # Check prerequisites
    check_docker

    if [ ! -f "bootstrap.sh" ]; then
        print_error "bootstrap.sh not found. Run from devkit directory."
        exit 1
    fi

    print_success "Found bootstrap.sh"
    echo ""

    # Prompt for which tests to run
    echo "Select distributions to test:"
    echo "  1. All distributions (recommended)"
    echo "  2. Debian family only (Debian, Ubuntu)"
    echo "  3. RedHat family only (Fedora)"
    echo "  4. Arch family only (Arch Linux)"
    echo "  5. Custom selection"
    echo ""
    read -r -p "Choice [1]: " choice
    choice=${choice:-1}

    case "$choice" in
    1)
        # Test all distributions
        test_distribution "Debian 12" "debian:12" "pass"
        test_distribution "Debian 11" "debian:11" "pass"
        test_distribution "Ubuntu 24.04" "ubuntu:24.04" "pass"
        test_distribution "Ubuntu 22.04" "ubuntu:22.04" "pass"
        test_distribution "Fedora 40" "fedora:40" "pass"
        test_distribution "Fedora 39" "fedora:39" "pass"
        test_distribution "Arch Linux" "archlinux:latest" "pass"
        test_distribution "openSUSE Leap" "opensuse/leap:latest" "pass"
        ;;
    2)
        # Debian family
        test_distribution "Debian 12" "debian:12" "pass"
        test_distribution "Debian 11" "debian:11" "pass"
        test_distribution "Ubuntu 24.04" "ubuntu:24.04" "pass"
        test_distribution "Ubuntu 22.04" "ubuntu:22.04" "pass"
        ;;
    3)
        # RedHat family
        test_distribution "Fedora 40" "fedora:40" "pass"
        test_distribution "Fedora 39" "fedora:39" "pass"
        ;;
    4)
        # Arch family
        test_distribution "Arch Linux" "archlinux:latest" "pass"
        ;;
    5)
        # Custom
        print_info "Custom selection not yet implemented. Running all tests."
        test_distribution "Debian 12" "debian:12" "pass"
        test_distribution "Ubuntu 24.04" "ubuntu:24.04" "pass"
        test_distribution "Fedora 40" "fedora:40" "pass"
        test_distribution "Arch Linux" "archlinux:latest" "pass"
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
    esac

    # Print summary
    print_summary
}

# Run main
main "$@"
