# ScotAccount Client Application

A Spring Boot application demonstrating secure integration with ScotAccount's OAuth2/OIDC authentication service for Scottish Government digital services.

## Overview

This application serves as a reference implementation for integrating with ScotAccount, the Scottish Government's digital identity service. It demonstrates secure authentication flows, verified attribute retrieval, and best practices for building trusted digital services.

## Key Features

- **OIDC Authentication**: Secure OpenID Connect authentication with ScotAccount
- **PKCE Security**: Proof Key for Code Exchange for enhanced security
- **Verified Attributes**: Retrieval and display of verified user claims
- **JWT Client Authentication**: Secure client assertion using RSA or EC key pairs (ES256/RS256)
- **OIDC Backchannel Logout**: Full OIDC backchannel logout specification compliance
- **Session Management**: Secure session handling with CSRF protection
- **GPG45 Compliance**: Support for Government identity assurance levels

## Prerequisites

Before running this application, ensure you have:

- **Java 21** or higher installed
- **Maven 3.6** or higher installed
- **ScotAccount client credentials** (client ID and secret)
- **RSA or EC key pair** for JWT client assertions (ES256 or RS256)
- **Access to ScotAccount integration environment**

## Quick Start Guide

### 1. Download and Extract

```bash
# Clone or download the application
git clone [repository-url]
cd ScotAccount-SpringClient/scotaccountclient
```

### 2. Configure Cryptographic Keys (RSA or EC)

The application supports both **RSA** and **Elliptic Curve (EC)** keys for JWT client assertions:

- **RS256**: RSA with SHA-256 (traditional, widely supported)
- **ES256**: ECDSA with P-256 curve and SHA-256 (modern, more efficient)

#### Option A: Using Elliptic Curve Keys (ES256) - Recommended

EC keys are more efficient and provide equivalent security with smaller key sizes:

```bash
# Create the keys directory
mkdir -p src/main/resources/keys

# Generate EC private key (P-256 curve)
openssl ecparam -genkey -name prime256v1 -out src/main/resources/keys/ec_private_key.pem

# Extract public key
openssl ec -in src/main/resources/keys/ec_private_key.pem -pubout -out src/main/resources/keys/ec_public_key.pem
```

#### Option B: Using RSA Keys (RS256)

```bash
# Create the keys directory
mkdir -p src/main/resources/keys

# Generate RSA private key (2048-bit)
openssl genrsa -out src/main/resources/keys/rsa_private_key.pem 2048

# Extract public key
openssl rsa -in src/main/resources/keys/rsa_private_key.pem -pubout -out src/main/resources/keys/rsa_public_key.pem

```

#### Key Configuration in application.properties

Update your `application.properties` to reference your chosen key:

```properties
# For EC keys
scotaccount.private-key-path=keys/ec_private_key.pem

# For RSA keys
scotaccount.private-key-path=keys/rsa_private_key.pem
```

**Important**: Ensure your private key has restricted permissions:

```bash
chmod 600 src/main/resources/keys/*_private_key.pem
```

**Security Note**: The `.gitignore` file is configured to prevent sensitive files from being committed to the repository. If you accidentally commit sensitive files, run the cleanup script:

```bash
chmod +x remove-sensitive-files.sh
./remove-sensitive-files.sh
```

### 3. Configure Application Properties

Edit `src/main/resources/application.properties`:

```properties
# ScotAccount Client Configuration
spring.security.oauth2.client.registration.scotaccount.client-id=your-client-id
spring.security.oauth2.client.registration.scotaccount.scope=openid scotaccount.address scotaccount.gpg45.medium scotaccount.email

# ScotAccount Provider Configuration
spring.security.oauth2.client.provider.scotaccount.issuer-uri=https://issuer.main.integration.scotaccount.service.gov.scot
spring.security.oauth2.client.provider.scotaccount.user-info-uri=https://issuer.main.integration.scotaccount.service.gov.scot/attributes/values

# Application Configuration
server.port=8080
server.servlet.context-path=/
```

### 4. Build and Run

```bash
# Build the application
mvn clean install

# Run the application using Spring Boot plugin
mvn spring-boot:run

# Alternative: Run using Maven profile
mvn clean install -P run-app
```

### 5. Run Configurations

The project includes several convenient run configurations:

#### Application Run Configurations

```bash
# Run the main ScotAccount client application
mvn spring-boot:run

# Run with Maven profile
mvn clean install -P run-app

# Run with specific Spring profile
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

#### JWK Generator Shell Script

A convenient shell script `genJWK.sh` is provided for easy JWK generation:

```bash
# Make the script executable (first time only)
chmod +x genJWK.sh

# Show help
./genJWK.sh --help
```

**Script Features:**

- Automatic project compilation if needed
- Input validation for key files and parameters
- Colored output for better readability
- Error handling and helpful messages
- Support for both RSA and EC key types (traditional SEC1 and PKCS#8 formats)
- **RFC 7638 JWK Thumbprint**: Automatically generates kid (key ID) using JWK thumbprint, matching the application's JWT signing

#### VS Code Launch Configurations

The project includes VS Code launch configurations in `.vscode/launch.json`:

- **ScotAccount Client**: Run the main application
- **Debug ScotAccount Client (Hot Reload)**: Run with hot reload for development
- **JWKGenerator**: Run the JWK generator utility

To use these configurations:

1. Open the project in VS Code
2. Go to the Run and Debug panel (Ctrl+Shift+D)
3. Select the desired configuration from the dropdown
4. Click the play button or press F5

### 6. Register Public JWK with ScotAccount

**Critical Step**: Before the application can authenticate with ScotAccount, you must register your **public JWK** with ScotAccount.

#### Generate Public JWK

Using the JWK generator, create your public JWK:

```bash
# For EC keys
./genJWK.sh --file scotaccountclient/src/main/resources/keys/ec_private_key.pem --public-only

# For RSA keys
./genJWK.sh --file scotaccountclient/src/main/resources/keys/rsa_private_key.pem --public-only
```

This will output a JSON object like:

**EC (ES256) Example:**
```json
{
  "kty": "EC",
  "use": "sig",
  "crv": "P-256",
  "kid": "sxWZgRPLexBTjj59mZHLWG_XkVgN5rOlw2IWJ8EIpVY",
  "x": "Yc98_IOmVt4RGW8WeS8bUMlBy_dmnvGSHwL1Th3ZYkc",
  "y": "ZXjD_mpR4JPQpJj-3t5Ogcr-6zrmw7VRfdJbqHHU_dw",
  "iat": 1759352798
}
```

**RSA (RS256) Example:**
```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "abc123...",
  "n": "...",
  "e": "AQAB",
  "iat": 1759352798
}
```

#### Register with ScotAccount

1. **Copy the public JWK JSON** (the entire JSON object)
2. **Contact ScotAccount support** or access their client registration portal
3. **Register the public JWK** for your client ID
4. **Ensure the `kid` matches** - The kid in the JWK must match what the application generates (it's calculated using RFC 7638 JWK thumbprint)

**Important Notes:**
- The `kid` (key ID) is automatically calculated using RFC 7638 JWK thumbprint
- The application's JWT signing will use the same kid in the JWT header
- If the kid doesn't match what's registered with ScotAccount, you'll get a 401 Unauthorized error
- Only register the **public** portion of the JWK (never share the private key `d` parameter)

### 7. Access the Application

Open your web browser and navigate to:

```
http://localhost:8090
```

## Authentication Flow

The application implements the OAuth2 authorization code flow with PKCE and JWT client assertions:

1. **User Access**: User visits the application homepage
2. **Login Initiation**: User clicks "Login with ScotAccount"
3. **ScotAccount Authentication**: User is redirected to ScotAccount for authentication
4. **Authorization Code**: ScotAccount returns an authorization code
5. **Token Exchange**: Application exchanges code for access and ID tokens using JWT client assertion (ES256 or RS256)
6. **Attribute Retrieval**: Application fetches verified user attributes
7. **User Display**: Application displays user information and verified claims

## Logout Flows

The application supports three distinct logout mechanisms:

### 1. RP-Initiated Logout (Front-Channel)
**Endpoint**: `/logout`

Standard OpenID Connect RP-initiated logout where the user explicitly logs out:

```
POST /logout
```

**Flow**:
1. User clicks logout button
2. Application invalidates local session
3. Redirects user to ScotAccount's `end_session_endpoint`
4. ScotAccount logs user out and redirects back to application

### 2. Backchannel Logout (Server-to-Server)
**Endpoint**: `/logout/backchannel` or `/logout/back-channel`

OIDC backchannel logout specification (RFC) compliant endpoint for server-to-server logout:

```
POST /logout/backchannel
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Flow**:
1. ScotAccount detects logout (user logs out elsewhere)
2. ScotAccount sends POST request to `/logout/backchannel` with signed `logout_token`
3. Application validates JWT signature and claims (issuer, audience, iat, events, sub/sid)
4. Application invalidates the user's session
5. Returns HTTP 200 OK (no redirect)

**Logout Token Validation**:
- ✅ JWT signature verification using ScotAccount's JWKS
- ✅ Issuer claim matches ScotAccount issuer
- ✅ Audience claim contains client ID
- ✅ `iat` claim validation
- ✅ `events` claim contains `http://schemas.openid.net/event/backchannel-logout`
- ✅ Either `sub` or `sid` claim present
- ✅ `nonce` claim must NOT be present

### 3. Application Logout (Local)
**Endpoint**: `/logout/application`

Local application logout without notifying ScotAccount:

```
POST /logout/application
```

**Flow**:
1. Invalidates local session only
2. Clears session cookies (JSESSIONID, XSRF-TOKEN)
3. Redirects to home page
4. User remains logged in to ScotAccount (SSO session active)

## Security Features

### PKCE (Proof Key for Code Exchange)

- Prevents authorization code interception attacks
- Generates code verifier and challenge for each authentication request
- Ensures secure token exchange

### JWT Client Authentication

- Supports both **ES256 (Elliptic Curve)** and **RS256 (RSA)** algorithms
- Uses Nimbus JOSE+JWT library for proper ECDSA signature generation
- Generates **kid (key ID)** using RFC 7638 JWK thumbprint
- Creates client assertions with required claims (iss, sub, aud, jti, iat, exp)
- Validates logout tokens using ScotAccount's JWKS endpoint

**JWT Header Structure**:
```json
{
  "kid": "sxWZgRPLexBTjj59mZHLWG_XkVgN5rOlw2IWJ8EIpVY",
  "typ": "JWT",
  "alg": "ES256"
}
```

**Key Components**:
- **JwtUtil.java**: Core JWT signing and validation logic
- **Automatic key type detection**: Supports RSA and EC keys
- **RFC 7638 compliant**: kid matches JWK thumbprint for proper key identification

### Session Management

- Secure session handling with CSRF protection
- Session fixation protection
- Maximum session limits
- Secure cookie configuration

### Verified Attributes

- Retrieves verified user claims from ScotAccount
- Supports GPG45 identity assurance levels
- Displays verified address and identity information

## Project Structure

```
scotaccountclient/
├── src/main/java/scot/gov/scotaccountclient/
│   ├── ScotaccountClientApplication.java    # Main application class
│   ├── SecurityConfig.java                  # OAuth2 security configuration
│   ├── HomeController.java                  # Main page controller
│   ├── LoginController.java                 # Authentication handling
│   ├── LogoutController.java                # Three logout flows (RP-initiated, backchannel, local)
│   ├── ErrorController.java                 # User-friendly error handling
│   ├── VerificationController.java          # Verification flow
│   ├── AttributeService.java                # User attribute fetching
│   ├── JwtUtil.java                        # JWT signing (ES256/RS256) and validation
│   ├── JWKGenerator.java                   # CLI utility for JWK conversion
│   └── CustomOAuth2AccessTokenResponseClient.java  # Token handling with JWT assertions
├── src/main/resources/
│   ├── application.properties               # Application configuration
│   ├── templates/                           # Thymeleaf templates
│   │   ├── index.html                      # Main application view
│   │   └── error.html                      # Error page (Scottish Government styled)
│   └── keys/                               # Cryptographic keys
│       ├── ec_private_key.pem              # EC private key (ES256)
│       ├── ec_public_key.pem               # EC public key
│       ├── rsa_private_key.pem             # RSA private key (RS256)
│       └── rsa_public_key.pem              # RSA public key
├── genJWK.sh                               # Shell script for JWK generation
└── docs/                                   # Documentation
    ├── diagrams/                           # Architecture diagrams
    └── javadoc/                            # API documentation
```

## Configuration Options

### ScotAccount Integration

```properties
# Client Registration
spring.security.oauth2.client.registration.scotaccount.client-id=your-client-id
spring.security.oauth2.client.registration.scotaccount.client-secret=your-client-secret

# Scopes for verified attributes
spring.security.oauth2.client.registration.scotaccount.scope=openid scotaccount.address scotaccount.gpg45.medium scotaccount.email

# ScotAccount Provider
spring.security.oauth2.client.provider.scotaccount.issuer-uri=https://issuer.main.integration.scotaccount.service.gov.scot
spring.security.oauth2.client.provider.scotaccount.user-info-uri=https://issuer.main.integration.scotaccount.service.gov.scot/attributes/values
```

### Session Configuration

```properties
# Session timeout (5 minutes)
server.servlet.session.timeout=5m

# Session management
spring.session.timeout=5m
```

### Logging Configuration

```properties
# Application logging
logging.level.scot.gov.scotaccountclient=INFO
logging.level.org.springframework.security=INFO

# OAuth2 debugging (set to DEBUG for troubleshooting)
logging.level.org.springframework.security.oauth2=INFO
```

## Troubleshooting

### Common Issues

#### 1. Cryptographic Key Errors

**Problem**: `java.security.InvalidKeyException` or key loading failures

**Solution**:
- Ensure keys are in PEM format (supports both traditional SEC1 and PKCS#8 for EC keys)
- Check file permissions (private key should be 600)
- Verify key headers are correct:
  - EC: `-----BEGIN EC PRIVATE KEY-----` (SEC1) or `-----BEGIN PRIVATE KEY-----` (PKCS#8)
  - RSA: `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----` (PKCS#8)
- Ensure BouncyCastle dependencies are present in pom.xml (`bcprov-jdk18on`, `bcpkix-jdk18on`)

**Problem**: `ClassNotFoundException: org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter`

**Solution**:
- Ensure `bcpkix-jdk18on` dependency is in pom.xml (required for Nimbus PEM parsing)
- Run `mvn clean install` to update dependencies
- Restart the application (old classpath may be cached)

#### 2. Authentication Failures

**Problem**: 401 Unauthorized during token exchange

**Solution**:
- **JWT Client Assertion Issues**:
  - Verify public JWK is registered with ScotAccount
  - Ensure `kid` in registered JWK matches the one generated by the application (check logs for `[JWT] Loaded EC private key successfully with kid: ...`)
  - Use `./genJWK.sh --file <key-file> --public-only` to generate the correct public JWK with matching kid
  - Verify the JWT algorithm (ES256 for EC keys, RS256 for RSA keys) is supported by ScotAccount
- **General Authentication**:
  - Verify client ID and secret are correct
  - Check ScotAccount integration environment access
  - Ensure redirect URI is registered with ScotAccount

**Problem**: Authentication redirect loops

**Solution**:
- Check session configuration and timeout settings
- Verify CSRF token handling
- Review SecurityConfig.java for proper authentication entry points

#### 3. Attribute Retrieval Issues

**Problem**: No verified attributes displayed
**Solution**:

- Check access token has required scopes
- Verify client assertion is valid
- Review ScotAccount service logs

#### 4. Session Issues

**Problem**: Session timeouts or CSRF errors

**Solution**:
- Check session timeout configuration
- Verify CSRF token configuration (backchannel logout endpoint is excluded from CSRF)
- Review browser cookie settings

#### 5. Backchannel Logout Issues

**Problem**: Backchannel logout returns 400 Bad Request

**Solution**:
- Verify `logout_token` parameter is present in POST request
- Check JWT signature validation (ScotAccount's JWKS must be accessible)
- Review logout token claims validation:
  - Issuer matches ScotAccount issuer
  - Audience contains client ID
  - Events claim contains backchannel-logout URI
  - Either sub or sid is present
  - Nonce is NOT present

**Problem**: Backchannel logout causes redirect instead of 200 OK

**Solution**:
- Ensure endpoint returns `ResponseEntity<Void>` with `@ResponseBody` annotation
- Verify endpoint is excluded from authentication requirements in SecurityConfig
- Check that `Cache-Control: no-store` header is set in response

### Debug Mode

To enable detailed logging for troubleshooting:

```properties
logging.level.scot.gov.scotaccountclient=DEBUG
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.web=DEBUG
```

## Development

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=HomeControllerTest

# Generate test coverage report
mvn test jacoco:report
```

### Building for Production

```bash
# Create production JAR
mvn clean package -DskipTests

# Run production JAR
java -jar target/scotaccountclient-1.0.0.jar
```

## Security Best Practices

### Key Management

- Store private keys securely with restricted permissions
- Rotate keys regularly (recommended every 6 months)
- Never commit private keys to version control
- Use environment variables for sensitive configuration

### Application Security

- Keep dependencies updated
- Use HTTPS in production
- Implement proper error handling
- Log security events appropriately

### ScotAccount Integration

- Register your application with ScotAccount
- Use appropriate scopes for your use case
- Implement proper logout flows
- Handle token refresh appropriately

## Support and Documentation

### Additional Resources

- **ScotAccount Documentation**: [ScotAccount Developer Portal]
- **Spring Security Documentation**: [Spring Security Reference]
- **OAuth2 Specification**: [RFC 6749]

### Getting Help

- Review the troubleshooting section above
- Check application logs for detailed error messages
- Consult the ScotAccount integration documentation
- Contact the development team for technical support

## Key Implementation Files

### JWT and Cryptographic Operations

#### JwtUtil.java
Handles all JWT signing and validation with support for both EC and RSA keys:

- **Key Loading**: Supports EC (SEC1/PKCS#8) and RSA (traditional/PKCS#8) formats
- **Key ID Generation**: RFC 7638 JWK thumbprint for consistent kid values
- **Client Assertion Creation**: ES256 or RS256 signed JWTs for token endpoint authentication
- **Logout Token Validation**: Comprehensive validation per OIDC backchannel logout spec

**Key Methods**:
- `loadPrivateKey()`: Loads EC or RSA private keys using Nimbus JOSE+JWT
- `createClientAssertion()`: Creates signed JWT with proper kid header
- `validateJwt()`: Validates logout tokens using ScotAccount's JWKS
- `generateKeyId()`: Generates RFC 7638 compliant JWK thumbprint

#### JWKGenerator.java
Command-line utility for converting PEM keys to JWK format:

- **Multiple Format Support**: Handles SEC1, PKCS#8, traditional RSA/EC formats
- **Public Key Derivation**: Derives EC public key from private key using elliptic curve multiplication
- **RFC 7638 Kid Generation**: Same kid calculation as JwtUtil for consistency
- **Public/Private Output**: Can output public-only JWK for ScotAccount registration

**Usage**:
```bash
# Generate public JWK for registration
mvn exec:java -Dexec.mainClass="scot.gov.scotaccountclient.JWKGenerator" \
  -Dexec.args="--file src/main/resources/keys/ec_private_key.pem --public-only"
```

### Logout Implementation

#### LogoutController.java
Three distinct logout flows with clear documentation:

1. **RP-Initiated Logout** (`/logout`): Standard front-channel logout
2. **Backchannel Logout** (`/logout/backchannel`): OIDC specification compliant server-to-server logout
3. **Application Logout** (`/logout/application`): Local session invalidation only

**Backchannel Logout Validation**:
- JWT signature verification
- Issuer, audience, iat validation
- Events claim verification
- Sub/sid presence check
- Nonce absence verification

### Error Handling

#### ErrorController.java
Provides user-friendly error pages with diagnostic information:

- **Token Exchange Errors**: Detailed diagnostics for 401 authentication failures
- **Scottish Government Styling**: Matches application design system
- **Debug Information**: Shows error details in development mode

## Version History

- **2.0.0**: Added EC key support (ES256), OIDC backchannel logout, JWK generator utility, improved error handling
- **1.2.0**: Added attribute verification flow and GPG45 support
- **1.1.0**: Enhanced security features and PKCE implementation
- **1.0.0**: Initial release with basic OAuth2/OIDC authentication

## License

This application is provided as reference implementation for Scottish Government digital services. Please refer to the license file for detailed terms and conditions.

---

**Note**: This application is designed for integration with ScotAccount's integration environment. For production deployment, ensure you have appropriate ScotAccount production credentials and follow Scottish Government security guidelines.
