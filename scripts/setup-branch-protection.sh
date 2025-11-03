#!/bin/bash
#
# Setup GitHub Branch Protection for main branch
#
# Requires: GitHub CLI (gh) and authenticated access to the repository
# Usage: ./scripts/setup-branch-protection.sh
#
# This script enforces:
# - Require status checks to pass
# - Require code reviews (1 approver)
# - Dismiss stale pull request approvals
# - Require branches to be up to date
# - Include administrators in restrictions
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Repo owner and name (will be extracted from git remote)
REPO=$(git remote get-url origin | sed 's/.*[:/]\([^/]*\)\/\([^/]*\)\.git$/\1\/\2/')

echo -e "${YELLOW}Setting up branch protection for main branch in ${REPO}${NC}"

# Check if gh CLI is installed
if ! command -v gh &>/dev/null; then
    echo -e "${RED}ERROR: GitHub CLI (gh) is not installed${NC}"
    echo "Install from: https://cli.github.com"
    exit 1
fi

# Check if authenticated
if ! gh auth status &>/dev/null; then
    echo -e "${RED}ERROR: Not authenticated with GitHub CLI${NC}"
    echo "Run: gh auth login"
    exit 1
fi

echo "Configuring branch protection rules..."

# Update branch protection with all required checks
gh api "repos/${REPO}/branches/main/protection" \
    --method PUT \
    -f required_status_checks='{"strict":true,"contexts":["Python Code Quality","Bash Script Quality","YAML Quality","Code Complexity Analysis","Performance Benchmarks","Mutation Testing (Test Quality)","Type Checking (mypy)","ci","security"]}' \
    -f enforce_admins=true \
    -f required_pull_request_reviews='{"dismiss_stale_reviews":true,"require_code_owner_reviews":false,"required_approving_review_count":1}' \
    -f restrictions=null \
    -f allow_force_pushes=false \
    -f allow_deletions=false \
    -f require_linear_history=false \
    -f required_conversation_resolution=false \
    -f require_last_push_approval=false

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Branch protection successfully configured${NC}"
    echo ""
    echo "Configuration:"
    echo "  • Required status checks to pass before merge"
    echo "  • Require 1 code review approval"
    echo "  • Dismiss stale pull request approvals"
    echo "  • Require branches to be up to date"
    echo "  • Include administrators in restrictions"
    echo "  • Prevent force pushes"
    echo "  • Prevent deletion of branch"
else
    echo -e "${RED}✗ Failed to configure branch protection${NC}"
    exit 1
fi

echo ""
echo "To dismiss this protection requirement:"
echo "  gh api repos/${REPO}/branches/main/protection --method DELETE"
