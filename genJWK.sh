#!/bin/bash

# JWK Generator Script for ScotAccount Client
# This script provides convenient ways to run the JWKGenerator utility
# with various parameters for converting private keys to JWK format.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_KEY_FILE=""
DEFAULT_KEY_USE="sig"
DEFAULT_PUBLIC_ONLY=false
PROJECT_DIR="scotaccountclient"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "JWK Generator Script for ScotAccount Client"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --file FILE        Path to private key file (PEM format) (required)"
    echo "  -u, --use USE          Key usage: sig (signature) or enc (encryption) [default: sig]"
    echo "  -p, --public-only      Output only the public key [default: false]"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Convert RSA private key to JWK for signatures"
    echo "  $0 --file src/main/resources/keys/private.pem --use sig"
    echo ""
    echo "  # Convert EC private key to JWK for encryption"
    echo "  $0 --file ec-private-key.pem --use enc"
    echo ""
    echo "  # Generate public key only"
    echo "  $0 --file private-key.pem --public-only"
    echo ""
    echo "  # Quick conversion with defaults"
    echo "  $0 --file private-key.pem"
    echo ""
    echo "Common key file locations:"
    echo "  - src/main/resources/keys/private.pem"
    echo "  - test-rsa-private.pem"
    echo "  - test-ec-private.pem"
}

# Function to check if Maven is available
check_maven() {
    if ! command -v mvn &> /dev/null; then
        print_error "Maven is not installed or not in PATH"
        print_info "Please install Maven to use this script"
        exit 1
    fi
}

# Function to check if project directory exists
check_project() {
    if [ ! -d "$PROJECT_DIR" ]; then
        print_error "Project directory '$PROJECT_DIR' not found"
        print_info "Please run this script from the project root directory"
        exit 1
    fi
}

# Function to build the project if needed
build_project() {
    print_info "Building project..."
    cd "$PROJECT_DIR"
    
    if [ ! -d "target/classes" ] || [ "src/main/java" -nt "target/classes" ]; then
        print_info "Compiling project..."
        mvn compile -q
        print_success "Project compiled successfully"
    else
        print_info "Project is up to date"
    fi
    
    cd ..
}

# Function to run JWKGenerator
run_jwk_generator() {
    local key_file="$1"
    local key_use="$2"
    local public_only="$3"
    
    print_info "Running JWKGenerator..."
    print_info "Key file: $key_file"
    print_info "Key use: $key_use"
    print_info "Public only: $public_only"
    echo ""
    
    cd "$PROJECT_DIR"
    
    # Convert relative path to absolute path for Maven execution
    local absolute_key_file
    if [[ "$key_file" == /* ]]; then
        # Already absolute path
        absolute_key_file="$key_file"
    else
        # Convert relative path to absolute
        absolute_key_file="$(cd .. && pwd)/$key_file"
    fi
    
    # Build command arguments
    local args="--file \"$absolute_key_file\" --use \"$key_use\""
    if [ "$public_only" = true ]; then
        args="$args --public-only"
    fi
    
    # Run the JWKGenerator
    print_info "Executing: mvn exec:java -Dexec.mainClass=\"scot.gov.scotaccountclient.JWKGenerator\" -Dexec.args=\"$args\""
    echo ""
    
    mvn exec:java -Dexec.mainClass="scot.gov.scotaccountclient.JWKGenerator" -Dexec.args="$args"
    
    local exit_code=$?
    cd ..
    
    if [ $exit_code -eq 0 ]; then
        print_success "JWK generation completed successfully"
    else
        print_error "JWK generation failed with exit code $exit_code"
        exit $exit_code
    fi
}

# Function to validate key file
validate_key_file() {
    local key_file="$1"
    
    if [ ! -f "$key_file" ]; then
        print_error "Key file does not exist: $key_file"
        print_info "Please check the file path and try again"
        echo ""
        print_info "Available key files in current directory:"
        if ls *.pem 2>/dev/null; then
            echo
            print_info "To use one of these files, specify the correct path with -f:"
            echo "  Example: ./genJWK.sh -f ec_private_key.pem --use sig"
        else
            echo "  No .pem files found in current directory"
            echo ""
            print_info "To create test keys, you can use OpenSSL:"
            echo "  # Generate RSA private key (traditional format)"
            echo "  openssl genrsa -out rsa_private_key.pem 2048"
            echo ""
            echo "  # Generate EC private key (traditional format)"
            echo "  openssl ecparam -genkey -name prime256v1 -out ec_private_key.pem"
            echo ""
            echo "  # Note: JWKGenerator now supports both traditional and PKCS#8 formats"
        fi
        exit 1
    fi
    
    # Check if it's a PEM file with a private key section
    if ! grep -q "BEGIN.*PRIVATE KEY" "$key_file"; then
        print_warning "File may not be a valid PEM private key file"
        print_info "Expected format: -----BEGIN PRIVATE KEY-----, -----BEGIN RSA PRIVATE KEY-----, or -----BEGIN EC PRIVATE KEY-----"
    fi
}

# Function to validate key use
validate_key_use() {
    local key_use="$1"
    
    if [ "$key_use" != "sig" ] && [ "$key_use" != "enc" ]; then
        print_error "Invalid key use: $key_use"
        print_info "Valid values are: sig (signature) or enc (encryption)"
        exit 1
    fi
}

# Parse command line arguments
KEY_FILE=""
KEY_USE="$DEFAULT_KEY_USE"
PUBLIC_ONLY="$DEFAULT_PUBLIC_ONLY"

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            KEY_FILE="$2"
            shift 2
            ;;
        -u|--use)
            KEY_USE="$2"
            shift 2
            ;;
        -p|--public-only)
            PUBLIC_ONLY=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$KEY_FILE" ]; then
    print_error "Key file is required"
    echo ""
    show_usage
    exit 1
fi

# Main execution
print_info "Starting JWK Generator Script"
echo ""

# Validate inputs
validate_key_file "$KEY_FILE"
validate_key_use "$KEY_USE"

# Check prerequisites
check_maven
check_project

# Build project if needed
build_project

# Run JWKGenerator
run_jwk_generator "$KEY_FILE" "$KEY_USE" "$PUBLIC_ONLY"

print_success "Script completed successfully"
