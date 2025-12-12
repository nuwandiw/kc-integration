# Frontend App - Spring WebFlux OIDC Client

A modern, reactive Spring WebFlux application that implements OAuth2/OIDC (OpenID Connect) authorization code grant flow with support for Demonstration of Proof-of-Possession (DPoP).

## Features

- **Spring WebFlux**: Non-blocking, reactive web framework for improved scalability and resource utilization
- **OAuth2/OIDC Authorization Code Grant Flow**: Full implementation with PKCE support for enhanced security
- **DPoP (Demonstration of Proof-of-Possession)**: Optional cryptographic proof mechanism to bind tokens to specific clients, preventing token misuse
- **WebSession**: Reactive session management using Spring WebFlux's WebSession instead of traditional HttpSession
- **WebClient**: Non-blocking HTTP client for all external API calls
- **Reactive Controllers**: Handler methods return `Mono<T>` and `Flux<T>` for true reactive pipelines

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

#### FrontendController (`com.calendar.frontendapp.controller.FrontendController`)
Handles OAuth2/OIDC flow endpoints:
- `GET /` - Redirects to login page
- `GET /login` - Login page with OAuth2 authorization initiation
- `POST /oauth2/authorize` - Initiates OAuth2 authorization request
- `GET /oauth2/callback` - Handles authorization code callback
- `GET /home` - Protected home page after successful authentication

#### RestController (`com.calendar.frontendapp.controller.RestController`)
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

## DPoP (Demonstration of Proof-of-Possession)

### Overview

DPoP is an OAuth2 security extension that binds access tokens to specific clients using cryptographic proofs. This prevents token misuse if tokens are intercepted or stolen.

### How It Works

1. **Key Pair Generation**
   - Client generates an asymmetric key pair (public/private)
   - Private key is kept secure on the client
   - Public key is included in the DPoP proof

2. **DPoP Proof Generation**
   - DPoP proof is a JWT with the following claims:
     - `jti`: Unique token identifier (prevents replay)
     - `htm`: HTTP method (POST for token requests)
     - `htu`: HTTP URI (token endpoint URL)
     - `iat`: Issued at timestamp
     - `exp`: Expiration time
   - Proof is signed with the client's private key

3. **Token Binding**
   - DPoP proof is sent in the `DPoP` header during token requests
   - Authorization server validates the proof
   - Access token is bound to the public key in the proof
   - Token can only be used by clients presenting valid DPoP proofs

### Using DPoPService

```java
// Inject DPoPService
@Autowired
private DPoPService dPoPService;

// Generate DPoP proof for token request
String dpopProof = dPoPService.generateDPoP(
    "POST",                                    // HTTP method
    "https://auth-server.com/token",          // Token endpoint URI
    null                                        // Optional claims
);

// Use DPoP proof in HTTP headers
headers.add("DPoP", dpopProof);
```

### Configuration

Enable DPoP in `application.yml`:

```yaml
spring:
  oauth2:
    client:
      dpop: true  # Set to false to disable DPoP
```

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

## Project Structure

```
frontend-app/
├── src/main/java/com/calendar/frontendapp/
│   ├── controller/
│   │   ├── FrontendController.java       # OIDC flow endpoints
│   │   └── RestController.java           # API endpoints
│   ├── security/
│   │   ├── SecurityConfig.java           # WebFlux security configuration
│   │   ├── OAuth2AuthenticationToken.java # Custom auth token
│   │   └── SessionAuthenticationFilter.java # Reactive session filter
│   └── security/oauth2/
│       ├── OAuth2Client.java             # OAuth2/OIDC client implementation
│       ├── OAuth2ClientConfig.java       # OAuth2 configuration
│       ├── OAuth2Properties.java         # Configuration properties
│       ├── OAuthUtil.java                # OAuth2 utility methods
│       ├── OAuth2AccessTokenRequest.java # Token request DTO
│       ├── OAuth2AccessTokenResponse.java # Token response DTO
│       └── dpop/
│           ├── DPoPService.java          # DPoP proof generation
│           ├── DPoPConfig.java           # DPoP configuration
│           └── KeyPairLoader.java        # Key pair loading utilities
├── src/main/resources/
│   ├── application.yml                   # Application configuration
│   ├── templates/
│   │   ├── login.html                    # Login page
│   │   └── home.html                     # Home page (authenticated)
└── pom.xml                               # Maven configuration
```

## Security Considerations

1. **PKCE (Proof Key for Authorization Code)**
   - Always enabled to prevent authorization code interception
   - Code verifier is cryptographically random and stored securely in WebSession
   - Code challenge is derived from code verifier

2. **State Parameter**
   - Random state is generated for each authorization request
   - Stored in WebSession to prevent CSRF attacks
   - Validated on callback (currently not validated - implement in production)

3. **DPoP (Optional)**
   - Prevents token substitution and replay attacks
   - Binds tokens to specific clients using cryptographic proofs
   - Enable in production for enhanced security

4. **Session Security**
   - Uses reactive WebSession with server-side storage
   - CSRF protection can be enabled in SecurityConfig
   - Tokens are never exposed to client-side JavaScript

5. **HTTPS**
   - Must use HTTPS in production
   - OAuth2/OIDC requires secure communication channels

## Building and Running

### Prerequisites
- Java 17 or later
- Maven 3.6+
- Access to an OIDC-compliant authorization server (e.g., Keycloak)

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

## Technologies Used

- **Spring Boot 3.2.10**: Application framework
- **Spring WebFlux**: Reactive web framework with Project Reactor
- **Spring Security**: Security framework with reactive support
- **Spring Cloud**: OAuth2/OIDC support
- **WebClient**: Non-blocking HTTP client
- **Thymeleaf**: Server-side template engine
- **Keycloak Libraries**: OIDC support and DPoP utilities
- **BouncyCastle**: Cryptography library
- **Project Reactor**: Reactive programming library (Mono, Flux)

## Endpoints

### Public Endpoints
- `GET /` - Redirects to login
- `GET /login` - Login page
- `POST /oauth2/authorize` - Initiate OAuth2 authorization
- `GET /oauth2/callback` - Authorization code callback handler

### Protected Endpoints (Require Authentication)
- `GET /home` - Home page
- `GET /api/calendar` - Calendar data API

## Reactive Programming Model

All components follow reactive programming patterns:

```java
// Controller methods return Mono<T>
@GetMapping("/home")
public Mono<String> home(WebSession session, Model model) {
    // Handler logic
    return Mono.just("home");
}

// OAuth2Client.tokenExchange() returns Mono<OAuth2AccessTokenResponse>
public Mono<OAuth2AccessTokenResponse> tokenExchange(WebSession session, String code) {
    return webClient.post()
            .uri(properties.getTokenUri())
            .retrieve()
            .bodyToMono(OAuth2AccessTokenResponse.class);
}

// Non-blocking session access
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return exchange.getSession()
            .flatMap(session -> {
                // Session processing
                return chain.filter(exchange);
            });
}
```

## Error Handling

The application handles errors gracefully:
- Missing or invalid authorization codes: Redirects to login with error message
- Token exchange failures: Redirects to login with error details
- Session expiration: Redirects to login
- Missing PKCE code verifier: Returns error response

## Future Enhancements

- [ ] State parameter validation on callback
- [ ] Token refresh implementation
- [ ] Logout endpoint with token revocation
- [ ] Additional OIDC scopes (id_token verification)
- [ ] Multi-tenant support
- [ ] Rate limiting for token endpoint
- [ ] Audit logging for security events

## Support

For issues or questions related to:
- **OIDC/OAuth2**: Refer to [RFC 6749 (OAuth 2.0)](https://tools.ietf.org/html/rfc6749) and [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- **PKCE**: Refer to [RFC 7636](https://tools.ietf.org/html/rfc7636)
- **DPoP**: Refer to [DPoP specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop)
- **Spring WebFlux**: Refer to [Spring WebFlux documentation](https://docs.spring.io/spring-framework/reference/web/webflux.html)

## License

[Add your license information here]
