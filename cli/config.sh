#!/bin/bash
################################################################################
# Mac-Setup Configuration Manager (Using yq for YAML operations)
#
# PURPOSE: Manage mac-setup configuration safely and reliably
# REQUIRES: bash, yq
#
# USAGE:
#   ./cli/config.sh list              # List enabled roles
#   ./cli/config.sh get global.logging.level
#   ./cli/config.sh set global.logging.level debug
#   ./cli/config.sh validate          # Validate configuration
#   ./cli/config.sh export yaml       # Export as YAML
#   ./cli/config.sh export json       # Export as JSON
#
# This uses yq for proper YAML/JSON operations instead of text-based tools
################################################################################

set -e

CONFIG_FILE="${1:-$HOME/.devkit/config.yaml}"
if [[ ! -f "$CONFIG_FILE" ]]; then
    CONFIG_FILE="config/config.yaml"
fi

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

################################################################################
# Configuration Functions Using yq
################################################################################

# Get YAML value using yq
get_yaml_value() {
    local key="$1"
    local file="$2"

    # Convert dot notation to yq path
    # e.g., "global.logging.level" -> ".global.logging.level"
    local yq_path=".${key//.//}"

    yq eval "$yq_path" "$file" 2>/dev/null || echo "null"
}

# List all enabled roles
list_roles() {
    local file="$1"

    echo -e "${BLUE}Enabled Roles:${NC}"
    yq eval '.enabled_roles[]' "$file" 2>/dev/null | sed 's/^/  - /'
}

# Validate configuration
validate_config() {
    local file="$1"
    local errors=0

    echo -e "${BLUE}Validating Configuration:${NC}"

    # Check required sections using yq
    if yq eval '.global' "$file" >/dev/null 2>&1 && [[ $(yq eval '.global' "$file") != "null" ]]; then
        echo -e "${GREEN}✓ Global section present${NC}"
    else
        echo -e "${RED}✗ Missing 'global' section${NC}"
        errors=$((errors + 1))
    fi

    # Check logging section
    if yq eval '.global.logging' "$file" >/dev/null 2>&1 && [[ $(yq eval '.global.logging' "$file") != "null" ]]; then
        echo -e "${GREEN}✓ Logging section present${NC}"
    else
        echo -e "${RED}✗ Missing 'logging' section${NC}"
        errors=$((errors + 1))
    fi

    # Check enabled_roles
    if yq eval '.enabled_roles' "$file" >/dev/null 2>&1 && [[ $(yq eval '.enabled_roles' "$file") != "null" ]]; then
        echo -e "${GREEN}✓ Enabled roles section present${NC}"
    else
        echo -e "${RED}✗ Missing 'enabled_roles' section${NC}"
        errors=$((errors + 1))
    fi

    if [[ $errors -eq 0 ]]; then
        echo -e "\n${GREEN}✓ Configuration is valid${NC}"
        return 0
    else
        echo -e "\n${RED}✗ Configuration has $errors error(s)${NC}"
        return 1
    fi
}

# Export configuration
export_config() {
    local format="${1:-yaml}"
    local file="$2"

    if [[ "$format" == "yaml" ]]; then
        cat "$file"
    elif [[ "$format" == "json" ]]; then
        yq eval -o json "$file"
    else
        echo -e "${RED}Error: Unknown format '$format'. Use 'yaml' or 'json'${NC}"
        return 1
    fi
}

################################################################################
# Command Handlers
################################################################################

list_command() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    list_roles "$CONFIG_FILE"
}

get_command() {
    local key="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    if [[ -z "$key" ]]; then
        echo -e "${RED}Error: Please specify a key${NC}"
        return 1
    fi

    echo -e "${BLUE}$key:${NC}"
    local value
    value=$(get_yaml_value "$key" "$CONFIG_FILE")
    if [[ "$value" == "null" ]]; then
        echo -e "${RED}Key not found: $key${NC}"
        return 1
    fi
    echo "$value"
}

set_command() {
    local key="$1"
    local value="$2"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    if [[ -z "$key" ]] || [[ -z "$value" ]]; then
        echo -e "${RED}Error: Please specify key and value${NC}"
        return 1
    fi

    echo -e "${BLUE}Setting $key = $value${NC}"

    # Use yq to safely update the value
    # Convert dot notation to yq path
    local yq_path=".${key//.//}"

    # Create temporary file for yq output
    local temp_file
    temp_file=$(mktemp)

    if yq eval "$yq_path = \"$value\"" "$CONFIG_FILE" >"$temp_file" 2>/dev/null; then
        mv "$temp_file" "$CONFIG_FILE"
        echo -e "${GREEN}✓ Updated${NC}"
    else
        rm -f "$temp_file"
        echo -e "${RED}✗ Failed to update configuration${NC}"
        return 1
    fi
}

validate_command() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    validate_config "$CONFIG_FILE"
}

export_command() {
    local format="${1:-yaml}"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    export_config "$format" "$CONFIG_FILE"
}

help_command() {
    cat <<'EOF'
Mac-Setup Configuration Manager

USAGE:
    config.sh COMMAND [ARGS]

COMMANDS:
    list                        List enabled roles
    get <key>                   Get configuration value
    set <key> <value>           Set configuration value
    validate                    Validate configuration
    export [format]             Export configuration (yaml/json)
    help                        Show this help message

EXAMPLES:
    # List roles
    ./config.sh list

    # Get value
    ./config.sh get global.logging.level

    # Set value
    ./config.sh set global.logging.level debug

    # Validate
    ./config.sh validate

    # Export as JSON
    ./config.sh export json

CONFIGURATION FILE:
    $HOME/.devkit/config.yaml

REQUIREMENTS:
    - bash
    - yq (for YAML operations)

EOF
}

################################################################################
# Main
################################################################################

main() {
    local command="${1:-help}"

    case "$command" in
    list)
        list_command
        ;;
    get)
        get_command "$2"
        ;;
    set)
        set_command "$2" "$3"
        ;;
    validate)
        validate_command
        ;;
    export)
        export_command "$2"
        ;;
    help | --help | -h)
        help_command
        ;;
    *)
        echo -e "${RED}Unknown command: $command${NC}"
        help_command
        exit 1
        ;;
    esac
}

main "$@"
