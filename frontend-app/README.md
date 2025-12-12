# Frontend App - Spring WebFlux OIDC Client

An application that implements OAuth2/OIDC (OpenID Connect) authorization code grant flow with support for Demonstration of Proof-of-Possession (DPoP).

## Architecture

### Core Components

#### OAuth2Client (`com.calendar.frontendapp.security.oauth2.OAuth2Client`)
Handles the OAuth2/OIDC flow:
- Generates authorization URLs with PKCE code challenge/verifier
- Exchanges authorization codes for access tokens
- Stores tokens in WebSession for subsequent requests
- Supports DPoP proof generation during token exchange

#### DPoPService (`com.calendar.frontendapp.security.oauth2.dpop.DPoPService`)
Manages Demonstration of Proof-of-Possession:
- Generates DPoP proofs for token requests
- Uses cryptographic key pairs to prove client possession of tokens
- Prevents token replay and substitution attacks
- Utilizes Keycloak's DPoP utilities and BouncyCastle for cryptography

#### SessionAuthenticationFilter (`com.calendar.frontendapp.security.SessionAuthenticationFilter`)
Reactive WebFilter for session-based authentication:
- Extracts OAuth2 access tokens from WebSession
- Establishes security context for authenticated requests
- Redirects unauthenticated users to login page
- Uses `ReactiveSecurityContextHolder` for reactive security context management

#### SecurityConfig (`com.calendar.frontendapp.security.SecurityConfig`)
Configures Spring Security with WebFlux:
- Dual security filter chains for API and web endpoints
- JWT validation for API requests
- Custom session-based authentication for web pages
- CSRF disabled for API endpoints

### Controllers

#### Frontend (`com.calendar.frontendapp.controller.Frontend`)
Handles OAuth2/OIDC flow endpoints:
- `GET /` - Redirects to login page
- `GET /login` - Login page with OAuth2 authorization initiation
- `POST /oauth2/authorize` - Initiates OAuth2 authorization request
- `GET /oauth2/callback` - Handles authorization code callback
- `GET /home` - Protected home page after successful authentication

#### RestApi (`com.calendar.frontendapp.controller.RestApi`)
Provides reactive API endpoints:
- `GET /api/calendar` - Returns calendar data (protected resource, requires authentication)

## OAuth2/OIDC Authorization Code Grant Flow

### Flow Diagram

```
User Agent                    Frontend App                  Authorization Server
    |                              |                               |
    |------- GET /login ---------->|                               |
    |                              |                               |
    |<--- login.html page ---------|                               |
    |                              |                               |
    |--- POST /oauth2/authorize -->|                               |
    |                              |--- GET /authorize/code ------>|
    |                              |   (state, code_challenge)     |
    |<--- Redirect to AuthServer --|                               |
    |                              |                               |
    |                    [User authenticates at Authorization Server]
    |                              |                               |
    |<--- Redirect with code ------|<--- POST /callback ----------|
    |                              |   (code, state)               |
    |                              |                               |
    |                              |--- POST /token_endpoint ----->|
    |                              |   (code, code_verifier,      |
    |                              |    client_id, redirect_uri)   |
    |                              |                               |
    |                              |<--- {access_token, ...} ------|
    |                              |                               |
    |<--- Redirect to /home -------|                               |
    |                              |                               |
    |--- GET /home ---------------->|                               |
    |<--- home.html (authenticated)|                               |
    |                              |                               |
```

### Implementation Details

1. **Authorization Request**
   - Generates random state parameter for CSRF protection
   - Creates PKCE code verifier and derives code challenge
   - Stores state and code_verifier in WebSession
   - Redirects user to authorization server's authorization endpoint

2. **Authorization Code Callback**
   - Receives authorization code from authorization server
   - Validates state parameter against session
   - Exchanges authorization code for access token using code_verifier

3. **Token Exchange**
   - Sends POST request to token endpoint with:
     - `grant_type`: authorization_code
     - `code`: Authorization code from callback
     - `code_verifier`: PKCE code verifier (stored in session)
     - `client_id`: OAuth2 client identifier
     - `client_secret`: OAuth2 client secret (if configured)
     - `redirect_uri`: Callback URL
     - `DPoP`: DPoP proof header (if DPoP is enabled)
   - Stores returned access_token, token_type, and expires_in in WebSession

4. **Session-Based Authentication**
   - SessionAuthenticationFilter intercepts all protected requests
   - Extracts access_token from WebSession
   - Creates OAuth2AuthenticationToken with token details
   - Establishes security context using ReactiveSecurityContextHolder

## Configuration

### application.yml

```yaml
server:
  port: 8081

spring:
  oauth2:
    client:
      id: your-client-id
      secret: your-client-secret
      redirect-uri: http://localhost:8081/oauth2/callback
      authorization-uri: https://auth-server.com/authorize
      token-uri: https://auth-server.com/token
      scope: openid profile email
      dpop: true  # Enable DPoP support
    resourceserver:
      jwt:
        issuer-uri: https://auth-server.com/realms/your-realm

  keycloak:
    policy-enforcer:
      enable: false  # Enable if using Keycloak policy enforcer
```

## Building and Running

### Prerequisites
- Java 17 or later
- Maven 3.6+
- Access to an OIDC-compliant authorization server (e.g., Keycloak)
- Public and private key files inside `ssh` directory for DPoP 

### Build

```bash
mvn clean package
```

### Run

```bash
java -jar target/frontend-app-1.0.0.jar
```

Or with Maven:

```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8081`

### Test
//Todo add integration and unit tests

## Endpoints

### Public Endpoints
- `GET /login` - Login page
- `POST /oauth2/authorize` - Initiate OAuth2 authorization
- `GET /oauth2/callback` - Authorization code callback handler

### Protected Endpoints (Require Authentication)
- `GET /home` - Home page. Needs an active session
- `GET /api/calendar` - Calendar data API. Checks for a valid JWT in Authorization header
