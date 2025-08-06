# Browser Interaction Flow with ScotAccount

This diagram shows the detailed interaction flow between the user's browser, the ScotAccount client application, and the ScotAccount services.

## Sequence Flow Diagram

```mermaid
sequenceDiagram
    participant Browser as User Browser
    participant Client as ScotAccount Client
    participant ScotAuth as ScotAccount Authorization
    participant ScotToken as ScotAccount Token Service
    participant ScotAttr as ScotAccount Attributes
    participant ScotJWKS as ScotAccount JWKS

    Note over Browser,ScotJWKS: Initial Application Access
    Browser->>Client: GET /
    Client->>Browser: Return index.html (login page)

    Note over Browser,ScotJWKS: User Initiates Login
    Browser->>Client: GET /oauth2/authorization/scotaccount
    Client->>Client: Generate PKCE code_verifier & code_challenge
    Client->>Client: Store state, nonce, code_verifier in session
    Client->>Browser: 302 Redirect to ScotAccount Authorization

    Note over Browser,ScotJWKS: ScotAccount Authentication
    Browser->>ScotAuth: GET /authorize?client_id=...&response_type=code&scope=openid scotaccount.address scotaccount.gpg45.medium scotaccount.email&state=...&code_challenge=...&code_challenge_method=S256&nonce=...&response_mode=form_post
    ScotAuth->>Browser: Return login form
    Browser->>ScotAuth: POST credentials (username/password)
    ScotAuth->>ScotAuth: Validate credentials
    ScotAuth->>Browser: 302 Redirect with authorization code

    Note over Browser,ScotJWKS: Authorization Code Return
    Browser->>Client: GET /login/oauth2/code/scotaccount?code=<auth_code>&state=<state>
    Client->>Client: Validate state parameter
    Client->>Client: Extract authorization code

    Note over Browser,ScotJWKS: Token Exchange
    Client->>ScotToken: POST /token
    Note right of Client: Headers: Content-Type: application/x-www-form-urlencoded<br/>Authorization: Basic <base64(client_id:client_secret)<br/>Body: grant_type=authorization_code&code=<auth_code>&redirect_uri=...&code_verifier=<pkce_verifier>
    ScotToken->>ScotToken: Validate authorization code and PKCE
    ScotToken->>Client: 200 OK
    Note right of ScotToken: {<br/>  "access_token": "eyJhbGciOiJSUzI1NiIs...",<br/>  "id_token": "eyJhbGciOiJSUzI1NiIs...",<br/>  "token_type": "Bearer",<br/>  "expires_in": 3600,<br/>  "scope": "openid scotaccount.address scotaccount.gpg45.medium scotaccount.email",<br/>  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."<br/>}

    Note over Browser,ScotJWKS: JWT Token Validation
    Client->>ScotJWKS: GET /jwks
    ScotJWKS->>Client: Return JSON Web Key Set
    Client->>Client: Validate JWT tokens using JWKS

    Note over Browser,ScotJWKS: User Attributes Retrieval
    Client->>ScotAttr: GET /attributes/values
    Note right of Client: Headers: Authorization: Bearer <access_token><br/>DIS-Client-Assertion: <client_assertion_jwt>
    ScotAttr->>ScotAttr: Validate access token and client assertion
    ScotAttr->>Client: 200 OK
    Note right of ScotAttr: {<br/>  "$schema": "https://schema.scotaccount.service.gov.scot/external/v2/scotaccount-verified-claims",<br/>  "iss": "https://issuer.main.integration.scotaccount.service.gov.scot/jwt",<br/>  "sub": "<subject_id>",<br/>  "iat": <timestamp>,<br/>  "verified_claims": [<br/>    {<br/>      "scope": "scotaccount.address",<br/>      "verification": {<br/>        "outcome": "VERIFIED_SUCCESSFULLY",<br/>        "trust_framework": "uk_tfida",<br/>        "validation_method": "credit_reference_agency",<br/>        "time": "2025-03-19T10:12:54Z",<br/>        "verifier": {<br/>          "organization": "DIS",<br/>          "txn": "e766b0f2-1873-4199-8f62-e6af182a7f47"<br/>        }<br/>      },<br/>      "claims": {<br/>        "address": {<br/>          "uprn": "132021690",<br/>          "buildingNumber": "5",<br/>          "streetName": "DALNAIR PLACE",<br/>          "dependentAddressLocality": "MILNGAVIE",<br/>          "addressLocality": "GLASGOW",<br/>          "postalCode": "G627RD"<br/>        }<br/>      }<br/>    },<br/>    {<br/>      "scope": "scotaccount.gpg45.medium",<br/>      "verification": {<br/>        "outcome": "VERIFIED_SUCCESSFULLY",<br/>        "trust_framework": "uk_tfida",<br/>        "assurance_policy": "GPG_45",<br/>        "confidence_level": "medium",<br/>        "time": "2025-03-19T10:12:54Z",<br/>        "verifier": {<br/>          "organization": "DIS",<br/>          "txn": "e766b0f2-1873-4199-8f62-e6af182a7f47"<br/>        }<br/>      },<br/>      "claims": {<br/>        "given_name": "David William",<br/>        "family_name": "Mcnabb",<br/>        "birth_date": "1976-08-24"<br/>      }<br/>    }<br/>  ]<br/>}

    Note over Browser,ScotJWKS: Display User Information
    Client->>Client: Process verified claims
    Client->>Client: Store user session
    Client->>Browser: 302 Redirect to /
    Browser->>Client: GET /
    Client->>Browser: Return index.html with user data
    Note right of Browser: Display:<br/>- User name and email<br/>- Verified address<br/>- Identity verification level<br/>- GPG45 confidence level

    Note over Browser,ScotJWKS: Logout Flow
    Browser->>Client: GET /logout
    Client->>Client: Clear session data
    Client->>Browser: 302 Redirect to ScotAccount logout
    Browser->>ScotAuth: GET /logout
    ScotAuth->>Browser: Clear ScotAccount session
    Browser->>Client: GET /
    Client->>Browser: Return index.html (login page)
```

## Key Security Features

### PKCE (Proof Key for Code Exchange)

- **Code Verifier**: Random string generated by client
- **Code Challenge**: SHA256 hash of code verifier
- **Purpose**: Prevents authorization code interception attacks

### JWT Token Validation

- **Access Token**: Bearer token for API access
- **ID Token**: Contains user identity information
- **JWKS**: JSON Web Key Set for token signature validation

### Client Assertion

- **Purpose**: Authenticates the client to ScotAccount APIs
- **Format**: JWT signed with client's private key
- **Claims**: Includes client ID, audience, expiration

### Session Management

- **Session Creation**: IF_REQUIRED policy
- **Session Fixation**: New session on login
- **Maximum Sessions**: 1 per user
- **CSRF Protection**: Cookie-based tokens

## Error Handling

### Authentication Errors

- Invalid credentials → ScotAccount returns 401
- Expired authorization code → Token service returns 400
- Invalid state parameter → Client redirects to error page

### Authorization Errors

- Missing required scopes → Client shows limited information
- Invalid access token → Attributes service returns 401
- Expired access token → Client uses refresh token

### Network Errors

- ScotAccount service unavailable → Client shows error page
- Timeout errors → Retry with exponential backoff
- SSL/TLS errors → Secure connection validation

## Data Flow Summary

1. **Browser Request** → Client processes and redirects to ScotAccount
2. **ScotAccount Authentication** → User provides credentials
3. **Authorization Code** → ScotAccount returns code to client
4. **Token Exchange** → Client exchanges code for access token
5. **Attribute Retrieval** → Client fetches verified user attributes
6. **User Display** → Client renders user information and verified claims
7. **Session Management** → Client maintains secure session state
