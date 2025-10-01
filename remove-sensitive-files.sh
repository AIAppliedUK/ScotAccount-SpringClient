#!/bin/bash

# Script to remove sensitive files from git repository
# This script will help clean up any sensitive files that were accidentally committed

echo "🔒 Removing sensitive files from git repository..."

# Remove sensitive files from git tracking (but keep them locally)
echo "Removing .pem files from git tracking..."
git rm --cached src/main/resources/keys/*.pem 2>/dev/null || echo "No .pem files found in tracking"

echo "Removing other sensitive key files from git tracking..."
git rm --cached src/main/resources/keys/*.key 2>/dev/null || echo "No .key files found in tracking"
git rm --cached src/main/resources/keys/*.crt 2>/dev/null || echo "No .crt files found in tracking"
git rm --cached src/main/resources/keys/*.p12 2>/dev/null || echo "No .p12 files found in tracking"
git rm --cached src/main/resources/keys/*.pfx 2>/dev/null || echo "No .pfx files found in tracking"
git rm --cached src/main/resources/keys/*.jks 2>/dev/null || echo "No .jks files found in tracking"
git rm --cached src/main/resources/keys/*.keystore 2>/dev/null || echo "No .keystore files found in tracking"

# Remove sensitive application properties
echo "Removing sensitive application properties from git tracking..."
git rm --cached src/main/resources/application-prod.properties 2>/dev/null || echo "No application-prod.properties found in tracking"
git rm --cached src/main/resources/application-dev.properties 2>/dev/null || echo "No application-dev.properties found in tracking"
git rm --cached src/main/resources/application-local.properties 2>/dev/null || echo "No application-local.properties found in tracking"

# Remove environment files
echo "Removing environment files from git tracking..."
git rm --cached .env 2>/dev/null || echo "No .env file found in tracking"
git rm --cached .env.local 2>/dev/null || echo "No .env.local file found in tracking"
git rm --cached .env.production 2>/dev/null || echo "No .env.production file found in tracking"

# Create a .gitkeep file to maintain directory structure
echo "Creating .gitkeep to maintain keys directory structure..."
mkdir -p src/main/resources/keys
touch src/main/resources/keys/.gitkeep

echo ""
echo "✅ Sensitive files removed from git tracking"
echo ""
echo "📝 Next steps:"
echo "1. Review the changes: git status"
echo "2. Commit the removal: git commit -m 'Remove sensitive files from tracking'"
echo "3. Push the changes: git push"
echo ""
echo "⚠️  IMPORTANT: If sensitive files were already pushed to a remote repository,"
echo "   you should also:"
echo "   - Rotate any exposed keys immediately"
echo "   - Consider using git filter-branch or BFG Repo-Cleaner to remove from history"
echo "   - Contact your security team if production keys were exposed"
echo ""
echo "🔐 Security reminder:"
echo "   - Always use .gitignore before committing sensitive files"
echo "   - Consider using environment variables for sensitive configuration"
echo "   - Regularly rotate keys and credentials" 