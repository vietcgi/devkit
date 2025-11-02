#!/bin/bash
################################################################################
# Mac-Setup Configuration Manager (Pure Bash)
#
# PURPOSE: Manage mac-setup configuration without Python
# REQUIRES: bash, grep, sed, awk
#
# USAGE:
#   ./cli/config.sh list              # List enabled roles
#   ./cli/config.sh get global.logging.level
#   ./cli/config.sh set global.logging.level debug
#   ./cli/config.sh validate          # Validate configuration
#   ./cli/config.sh export yaml       # Export as YAML
#
# This is a lightweight bash alternative to the Python config engine
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
# YAML Parser Functions (Pure Bash)
################################################################################

# Parse YAML key from configuration
get_yaml_value() {
    local key="$1"
    local file="$2"

    # Convert dot notation to grep pattern
    # e.g., "global.logging.level" -> "level"
    local last_key
    last_key=$(echo "$key" | awk -F. '{print $NF}')

    grep "^[[:space:]]*$last_key:" "$file" | head -1 | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# List all enabled roles
list_roles() {
    local file="$1"

    echo -e "${BLUE}Enabled Roles:${NC}"
    grep -A 10 "enabled_roles:" "$file" | grep "^[[:space:]]*-" | sed 's/^[[:space:]]*-[[:space:]]*/  - /'
}

# Validate configuration
validate_config() {
    local file="$1"
    local errors=0

    echo -e "${BLUE}Validating Configuration:${NC}"

    # Check required sections
    if ! grep -q "^global:" "$file"; then
        echo -e "${RED}✗ Missing 'global' section${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}✓ Global section present${NC}"
    fi

    # Check logging section
    if ! grep -q "logging:" "$file"; then
        echo -e "${RED}✗ Missing 'logging' section${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}✓ Logging section present${NC}"
    fi

    # Check enabled_roles
    if ! grep -q "enabled_roles:" "$file"; then
        echo -e "${RED}✗ Missing 'enabled_roles' section${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}✓ Enabled roles section present${NC}"
    fi

    if [[ $errors -eq 0 ]]; then
        echo -e "\n${GREEN}✓ Configuration is valid${NC}"
        return 0
    else
        echo -e "\n${RED}✗ Configuration has $errors error(s)${NC}"
        return 1
    fi
}

# Export configuration (simple display)
export_config() {
    local format="${1:-yaml}"
    local file="$2"

    if [[ "$format" == "yaml" ]]; then
        cat "$file"
    elif [[ "$format" == "json" ]]; then
        echo '{'
        grep -v "^#" "$file" | grep -v "^$" | sed 's/$/,/' | sed '$s/,$//' | sed 's/^/  /'
        echo '}'
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
    get_yaml_value "$key" "$CONFIG_FILE"
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
    # Simple sed replacement (basic implementation)
    sed -i '' "s/^\([[:space:]]*\)$(echo "$key" | awk -F. '{print $NF}'):.*/\1$(echo "$key" | awk -F. '{print $NF}'): $value/" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Updated${NC}"
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
Mac-Setup Configuration Manager (Bash)

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

    # Export
    ./config.sh export yaml

CONFIGURATION FILE:
    $HOME/.devkit/config.yaml

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
