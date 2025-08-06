# High-Level ScotAccount Architecture

This diagram shows the high-level architecture focusing on the three main components: the Relaying Party application, ScotAccount endpoints, and the browser interactions.

## High-Level Architecture Diagram

```mermaid
graph TB
    %% User Layer
    subgraph "User Layer"
        Browser[User Browser]
    end

    %% Relying Party
    subgraph "Your Domain"
        RP[Your
        Application]
    end

    %% ScotAccount Services
    subgraph "ScotAccount Services"
        Auth[Authorization Endpoint /authorize]
        Token[Token Endpoint /token]
        Attributes[Attributes Endpoint /attributes/values]
        JWKS[JWKS Endpoint /jwks]
        UserInfo[UserInfo Endpoint /userinfo]
    end

    %% Styling
    classDef browserClass fill:#e1f5fe,stroke:#01579b,stroke-width:3px
    classDef rpClass fill:#f3e5f5,stroke:#4a148c,stroke-width:3px
    classDef scotClass fill:#fff3e0,stroke:#e65100,stroke-width:3px

    class Browser browserClass
    class RP rpClass
    class Auth,Token,Attributes,JWKS,UserInfo scotClass

        %% Browser-mediated flows (OAuth2 authorization code flow)
    Browser <--> RP
    Browser <--> Auth

    %% Direct server-to-server flows (backend API calls)
    RP <--> Token
    RP <--> Attributes
    RP <--> JWKS
    RP <--> UserInfo
```

## Component Overview

### User Layer

- **Browser**: The user's web browser that initiates authentication and displays the application

### Relaying Party Application

- **Spring Boot OAuth2 Client**: The ScotAccount client application that acts as a relaying party
- **Responsibilities**:
  - Handles user login requests
  - Manages OAuth2/OIDC flow
  - Processes authentication tokens
  - Fetches and displays user attributes
  - Manages user sessions

### ScotAccount Services

- **Authorization Endpoint (/authorize)**: Handles user authentication and authorization
- **Token Endpoint (/token)**: Exchanges authorization codes for access tokens
- **Attributes Endpoint (/attributes/values)**: Provides verified user attributes and claims
- **JWKS Endpoint (/jwks)**: Provides JSON Web Key Set for token validation
- **UserInfo Endpoint (/userinfo)**: Provides basic user information

## Authentication Flow

```mermaid
sequenceDiagram
    participant Browser as User Browser
    participant RP as Relaying Party
    participant Scot as ScotAccount Services

    Note over Browser,Scot: 1. User Access
    Browser->>RP: GET / (Application Home)
    RP->>Browser: Return login page

    Note over Browser,Scot: 2. Login Initiation
    Browser->>RP: GET /oauth2/authorization/scotaccount
    RP->>RP: Generate PKCE & state
    RP->>Browser: 302 Redirect to ScotAccount

    Note over Browser,Scot: 3. ScotAccount Authentication
    Browser->>Scot: GET /authorize (with OAuth2 params)
    Scot->>Browser: Return login form
    Browser->>Scot: POST credentials
    Scot->>Scot: Validate credentials
    Scot->>Browser: 302 Redirect with auth code

    Note over Browser,Scot: 4. Token Exchange
    Browser->>RP: GET /login/oauth2/code/scotaccount
    RP->>Scot: POST /token (exchange auth code)
    Scot->>RP: Return access token & ID token

    Note over Browser,Scot: 5. Attribute Retrieval
    RP->>Scot: GET /attributes/values (with access token)
    Scot->>RP: Return verified claims

    Note over Browser,Scot: 6. User Display
    RP->>Browser: Return user dashboard with attributes
```

## Key Interactions

### 1. **Browser ↔ Relaying Party**

- **Login Requests**: User initiates authentication
- **Session Management**: Browser maintains session cookies
- **User Interface**: Displays login forms and user information

### 2. **Relaying Party ↔ ScotAccount**

- **OAuth2 Flow**: Authorization code grant with PKCE
- **Token Management**: Access token and ID token handling
- **Attribute Fetching**: Retrieval of verified user claims
- **JWT Validation**: Token validation using JWKS

### 3. **Security Features**

- **PKCE**: Prevents authorization code interception
- **JWT Tokens**: Secure token-based authentication
- **Client Assertion**: JWT-based client authentication
- **HTTPS**: All communications over secure channels

## Data Flow Summary

1. **User initiates login** → Browser requests authentication
2. **OAuth2 authorization** → Relaying Party redirects to ScotAccount
3. **User authentication** → ScotAccount validates credentials
4. **Token exchange** → Relaying Party exchanges auth code for tokens
5. **Attribute retrieval** → Relaying Party fetches verified claims
6. **User display** → Relaying Party shows user information

## Benefits of This Architecture

- **Separation of Concerns**: Clear separation between client, identity provider, and user
- **Security**: OAuth2/OIDC standards with PKCE and JWT validation
- **Scalability**: Stateless token-based authentication
- **Compliance**: Follows government identity standards (GPG45)
- **User Experience**: Seamless authentication flow with verified attributes
