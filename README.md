# ScotAccount Client Application

A Spring Boot application demonstrating secure integration with ScotAccount's OAuth2/OIDC authentication service for Scottish Government digital services.

## Overview

This application serves as a reference implementation for integrating with ScotAccount, the Scottish Government's digital identity service. It demonstrates secure authentication flows, verified attribute retrieval, and best practices for building trusted digital services.

## Key Features

- **OIDC Authentication**: Secure OpenID Connect authentication with ScotAccount
- **PKCE Security**: Proof Key for Code Exchange for enhanced security
- **Verified Attributes**: Retrieval and display of verified user claims
- **JWT Client Authentication**: Secure client assertion using RSA key pairs
- **Session Management**: Secure session handling with CSRF protection
- **GPG45 Compliance**: Support for Government identity assurance levels

## Prerequisites

Before running this application, ensure you have:

- **Java 21** or higher installed
- **Maven 3.6** or higher installed
- **ScotAccount client credentials** (client ID and secret)
- **RSA key pair** for JWT client assertions
- **Access to ScotAccount integration environment**

## Quick Start Guide

### 1. Download and Extract

```bash
# Clone or download the application
git clone [repository-url]
cd scotaccountMVP/scotaccountclient
```

### 2. Configure RSA Keys

Place your RSA key pair in the `src/main/resources/keys/` directory:

```bash
# Create the keys directory
mkdir -p src/main/resources/keys

# Copy your RSA keys (ensure they're in PEM format)
cp your-private-key.pem src/main/resources/keys/private.pem
cp your-public-key.pem src/main/resources/keys/public.pem
```

**Important**: Ensure your private key has restricted permissions:

```bash
chmod 600 src/main/resources/keys/private.pem
```

### 3. Configure Application Properties

Edit `src/main/resources/application.properties`:

```properties
# ScotAccount Client Configuration
spring.security.oauth2.client.registration.scotaccount.client-id=your-client-id
spring.security.oauth2.client.registration.scotaccount.client-secret=your-client-secret
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

# Run the application
mvn spring-boot:run
```

### 5. Access the Application

Open your web browser and navigate to:

```
http://localhost:8080
```

## Authentication Flow

The application implements the OAuth2 authorization code flow with PKCE:

1. **User Access**: User visits the application homepage
2. **Login Initiation**: User clicks "Login with ScotAccount"
3. **ScotAccount Authentication**: User is redirected to ScotAccount for authentication
4. **Authorization Code**: ScotAccount returns an authorization code
5. **Token Exchange**: Application exchanges code for access and ID tokens
6. **Attribute Retrieval**: Application fetches verified user attributes
7. **User Display**: Application displays user information and verified claims

## Security Features

### PKCE (Proof Key for Code Exchange)

- Prevents authorization code interception attacks
- Generates code verifier and challenge for each authentication request
- Ensures secure token exchange

### JWT Client Authentication

- Uses RSA key pairs for client assertions
- Signs JWT tokens for API authentication
- Validates tokens using ScotAccount's JWKS endpoint

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
│   ├── LogoutController.java                # Logout handling
│   ├── VerificationController.java          # Verification flow
│   ├── AttributeService.java                # User attribute fetching
│   ├── JwtUtil.java                        # JWT operations
│   └── CustomOAuth2AccessTokenResponseClient.java  # Token handling
├── src/main/resources/
│   ├── application.properties               # Application configuration
│   ├── templates/                           # Thymeleaf templates
│   │   ├── index.html                      # Main application view
│   │   └── error.html                      # Error page
│   └── keys/                               # RSA key pair
│       ├── private.pem                     # Private key for signing
│       └── public.pem                      # Public key for verification
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

#### 1. RSA Key Errors

**Problem**: `java.security.InvalidKeyException` or key loading failures
**Solution**:

- Ensure keys are in PEM format
- Check file permissions (private key should be 600)
- Verify key headers are correct

#### 2. Authentication Failures

**Problem**: 401 Unauthorized or authentication redirect loops
**Solution**:

- Verify client ID and secret are correct
- Check ScotAccount integration environment access
- Ensure redirect URI is registered with ScotAccount

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
- Verify CSRF token configuration
- Review browser cookie settings

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

## Version History

- **1.2.0**: Added attribute verification flow and GPG45 support
- **1.1.0**: Enhanced security features and PKCE implementation
- **1.0.0**: Initial release with basic OAuth2/OIDC authentication

## License

This application is provided as reference implementation for Scottish Government digital services. Please refer to the license file for detailed terms and conditions.

---

**Note**: This application is designed for integration with ScotAccount's integration environment. For production deployment, ensure you have appropriate ScotAccount production credentials and follow Scottish Government security guidelines.
