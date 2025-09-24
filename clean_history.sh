#!/bin/bash

# Create a backup branch
git branch backup-before-cleanup

# Remove files from git history
git filter-branch --force --index-filter \
"git rm --cached --ignore-unmatch \
Planning.md \
Tasks.md \
'Technical Documentation.txt' \
scotaccountclient/src/main/resources/keys/*.pem \
scotaccountclient/src/test/resources/keys/*.pem" \
--prune-empty --tag-name-filter cat -- --all

# Force garbage collection
git gc --aggressive --prune=now

# Force push the changes
git push origin --force --all 