#!/bin/bash
################################################################################
# Devkit Performance Benchmark Script
#
# Measures installation performance and generates reports
#
# USAGE:
#   scripts/benchmark.sh [options]
#   scripts/benchmark.sh --runs 5 --output benchmark-results.json
#
# OPTIONS:
#   -r, --runs NUM        Number of benchmark runs (default: 3)
#   -o, --output FILE     Output file for results (default: benchmark.json)
#   -c, --clear-cache     Clear cache between runs
#   -s, --skip-gui        Skip GUI apps to reduce time
#   -h, --help            Show this help message
################################################################################

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
RUNS=3
OUTPUT_FILE="benchmark.json"
CLEAR_CACHE=false
SKIP_GUI=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
        -r | --runs)
            RUNS="$2"
            shift 2
            ;;
        -o | --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -c | --clear-cache)
            CLEAR_CACHE=true
            shift
            ;;
        -s | --skip-gui)
            SKIP_GUI=true
            shift
            ;;
        -h | --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
        esac
    done
}

show_help() {
    grep "^#" "$0" | grep -v "^#!/" | sed 's/^# //'
}

# Logging functions
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

# System information
get_system_info() {
    local os_type
    local arch
    local cpu_count
    local ram_gb

    if [[ "$OSTYPE" == "darwin"* ]]; then
        os_type="macOS"
        arch=$(uname -m)
        cpu_count=$(sysctl -n hw.ncpu)
        ram_gb=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    else
        os_type="Linux"
        arch=$(uname -m)
        cpu_count=$(nproc)
        ram_gb=$(($(cat /proc/meminfo | grep MemTotal | awk '{print $2}') / 1024 / 1024))
    fi

    cat <<EOF
{
  "os": "$os_type",
  "arch": "$arch",
  "cpu_count": $cpu_count,
  "ram_gb": $ram_gb
}
EOF
}

# Disk space check
get_disk_space() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        df -h / | awk 'NR==2 {print $4}' | sed 's/G//'
    else
        df -h / | awk 'NR==2 {print $4}' | sed 's/G//'
    fi
}

# Cache size
get_cache_size() {
    if [ -d ~/.devkit/cache ]; then
        du -sh ~/.devkit/cache | awk '{print $1}'
    else
        echo "0B"
    fi
}

# Run single benchmark
run_benchmark() {
    local run_num=$1
    local duration
    local cache_size_before
    local cache_size_after

    log_info "Running benchmark $run_num/$RUNS..."

    if [ "$CLEAR_CACHE" = true ]; then
        log_warning "Clearing cache..."
        rm -rf ~/.devkit/cache
    fi

    cache_size_before=$(get_cache_size)

    # Run bootstrap with timing
    local bootstrap_cmd="./bootstrap.sh"
    if [ "$SKIP_GUI" = true ]; then
        bootstrap_cmd="$bootstrap_cmd --skip-gui"
    fi

    local start_time
    start_time=$(date +%s%N)
    cd "$PROJECT_DIR"

    if $bootstrap_cmd >/tmp/bootstrap-$run_num.log 2>&1; then
        local end_time
        end_time=$(date +%s%N)
        duration=$(echo "scale=2; ($end_time - $start_time) / 1000000000" | bc)
    else
        log_error "Bootstrap failed on run $run_num"
        cat /tmp/bootstrap-$run_num.log | tail -20
        return 1
    fi

    cache_size_after=$(get_cache_size)

    cat <<EOF
{
  "run": $run_num,
  "duration_seconds": $duration,
  "cache_size_before": "$cache_size_before",
  "cache_size_after": "$cache_size_after"
}
EOF
}

# Generate report
generate_report() {
    local results_json="$1"
    local num_runs
    num_runs=$(echo "$results_json" | jq 'length')
    local total_time=0
    local min_time=999999
    local max_time=0
    local first_run_time=0
    local last_run_time=0

    log_info "Generating benchmark report..."

    # Calculate statistics using jq to extract durations
    local run_num=0
    while IFS= read -r duration; do
        total_time=$(echo "$total_time + $duration" | bc)

        if (($(echo "$duration < $min_time" | bc -l))); then
            min_time=$duration
        fi
        if (($(echo "$duration > $max_time" | bc -l))); then
            max_time=$duration
        fi

        run_num=$((run_num + 1))
        if [ $run_num -eq 1 ]; then
            first_run_time=$duration
        fi
        last_run_time=$duration
    done < <(echo "$results_json" | jq '.[] | .duration_seconds')

    local avg_time
    avg_time=$(echo "scale=2; $total_time / $num_runs" | bc)
    local improvement
    improvement=$(echo "scale=1; (($first_run_time - $last_run_time) / $first_run_time) * 100" | bc)

    cat <<EOF
╔══════════════════════════════════════════════════════════════╗
║         DEVKIT PERFORMANCE BENCHMARK RESULTS                 ║
╚══════════════════════════════════════════════════════════════╝

Benchmark Configuration:
  Runs: $num_runs
  Clear cache between runs: $CLEAR_CACHE
  Skip GUI apps: $SKIP_GUI

System Information:
  $(get_system_info | jq -r 'keys[] as $k | "  \($k): \(.[$k])"')

Results:
  First run: ${first_run_time}s
  Last run: ${last_run_time}s
  Average: ${avg_time}s
  Min: ${min_time}s
  Max: ${max_time}s
  Improvement: ${improvement}%

Cache Impact:
  The final run was ${improvement}% faster than the first run,
  demonstrating the effectiveness of caching.

Recommendations:
EOF

    if (($(echo "$improvement < 30" | bc -l))); then
        cat <<EOF
  - Run more benchmarks to better utilize caching
  - Check network speed (may be bottleneck)
  - Consider using fewer roles (skip GUI, etc.)
EOF
    else
        cat <<EOF
  - Caching is working effectively!
  - Reuse cache for faster repeated installs
  - Consider pre-staging cache for new machines
EOF
    fi

    cat <<EOF

Full Results (JSON):
  $OUTPUT_FILE

═════════════════════════════════════════════════════════════════
EOF
}

# Main
main() {
    parse_args "$@"

    log_info "Devkit Performance Benchmark"
    log_info "Starting $RUNS benchmark run(s)..."
    echo ""

    # Collect results
    local results="["
    for ((i = 1; i <= RUNS; i++)); do
        if [ $i -gt 1 ]; then
            results="$results,"
        fi
        local run_result
        run_result=$(run_benchmark $i)
        results="$results$run_result"
    done
    results="$results]"

    # Save results
    echo "$results" | jq '.' >"$OUTPUT_FILE"
    log_success "Results saved to $OUTPUT_FILE"
    echo ""

    # Generate report
    generate_report "$results"

    log_success "Benchmark complete!"
}

# Run main function with arguments
main "$@"
