#!/bin/bash
# Semantic version bumper for Devkit
# Usage: scripts/bump-version.sh [major|minor|patch]

set -euo pipefail

VERSION_FILE="VERSION"

if [ ! -f "$VERSION_FILE" ]; then
    echo "ERROR: $VERSION_FILE not found"
    exit 1
fi

CURRENT=$(cat "$VERSION_FILE")
IFS='.' read -r MAJOR MINOR PATCH <<<"$CURRENT"

case "${1:-patch}" in
major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
patch)
    PATCH=$((PATCH + 1))
    ;;
*)
    echo "Usage: $0 [major|minor|patch]"
    echo "Current version: $CURRENT"
    exit 1
    ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
echo "$NEW_VERSION" >"$VERSION_FILE"
echo "Bumped version: $CURRENT → $NEW_VERSION"
