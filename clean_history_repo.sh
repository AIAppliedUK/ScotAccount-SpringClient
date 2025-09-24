#!/bin/bash

# Create a backup branch
git branch backup-before-cleanup-repo

# Remove files from git history
git filter-repo --invert-paths \
    --path Planning.md \
    --path Tasks.md \
    --path "Technical Documentation.txt" \
    --path-glob "scotaccountclient/src/main/resources/keys/*.pem" \
    --path-glob "scotaccountclient/src/test/resources/keys/*.pem" \
    --force

# Force push the changes
git push origin --force --all 