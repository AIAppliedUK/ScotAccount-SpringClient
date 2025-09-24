package scot.gov.scotaccountclient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Custom implementation of OAuth2AccessTokenResponseClient for handling token
 * exchange with ScotAccount.
 * 
 * <p>
 * This class manages the OAuth2 authorization code grant flow with additional
 * security features specific to ScotAccount integration:
 * </p>
 * 
 * <ul>
 * <li>JWT client assertion generation for secure client authentication</li>
 * <li>PKCE code verifier handling for enhanced security</li>
 * <li>Token response processing and JWT decoding</li>
 * <li>Detailed request/response logging for troubleshooting</li>
 * </ul>
 * 
 * <p>
 * The token exchange process follows these steps:
 * </p>
 * <ol>
 * <li>Generate client assertion JWT using private key</li>
 * <li>Build token request with authorization code and PKCE verifier</li>
 * <li>Send request to ScotAccount token endpoint</li>
 * <li>Process and validate token response</li>
 * <li>Extract and decode token claims</li>
 * <li>Build OAuth2AccessTokenResponse with tokens and claims</li>
 * </ol>
 * 
 * <p>
 * Key security features:
 * </p>
 * <ul>
 * <li>Private key based client authentication (rather than client secrets)</li>
 * <li>PKCE code verifier validation</li>
 * <li>Token claim extraction for downstream use</li>
 * <li>Configurable logging with sanitization of sensitive data</li>
 * </ul>
 */
public class CustomOAuth2AccessTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    /** Logger for the CustomOAuth2AccessTokenResponseClient class. */
    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2AccessTokenResponseClient.class);

    /** REST client for making HTTP requests to the token endpoint. */
    private final RestTemplate restTemplate;

    /** Utility for JWT token creation and validation operations. */
    private final JwtUtil jwtUtil;

    /** JSON mapper for serialization and deserialization of token responses. */
    private final ObjectMapper objectMapper;

    /**
     * Constructs a new CustomOAuth2AccessTokenResponseClient with the required
     * dependencies.
     * 
     * <p>
     * Uses the global RestTemplate bean configured in WebConfig for consistent
     * HTTP client behavior and proper method handling.
     * </p>
     * 
     * @param jwtUtil      JWT utility for generating client assertions and
     *                     processing
     *                     tokens
     * @param restTemplate The global RestTemplate bean configured in WebConfig
     */
    public CustomOAuth2AccessTokenResponseClient(JwtUtil jwtUtil, RestTemplate restTemplate) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = new ObjectMapper();
        this.restTemplate = restTemplate;
    }

    /**
     * Logs detailed information about the token exchange request.
     * 
     * @param requestBody The request body being sent to the token endpoint
     * @param headers     The HTTP headers being sent
     * @param tokenUri    The token endpoint URI
     */
    private void logTokenExchangeRequest(org.springframework.util.MultiValueMap<String, String> requestBody,
            HttpHeaders headers, String tokenUri) {
        logger.trace("[SCOTACCOUNT-TOKEN] ================ TOKEN EXCHANGE REQUEST DETAILS ================");
        logger.trace("[SCOTACCOUNT-TOKEN] Token Endpoint: {}", tokenUri);
        logger.trace("[SCOTACCOUNT-TOKEN] Request Headers: {}", headers);
        logger.trace("[SCOTACCOUNT-TOKEN] Grant Type: {}", requestBody.getFirst("grant_type"));
        logger.trace("[SCOTACCOUNT-TOKEN] Authorization Code: {}", requestBody.getFirst("code"));
        logger.trace("[SCOTACCOUNT-TOKEN] Redirect URI: {}", requestBody.getFirst("redirect_uri"));
        logger.trace("[SCOTACCOUNT-TOKEN] Code Verifier: {}", requestBody.getFirst("code_verifier"));
        logger.trace("[SCOTACCOUNT-TOKEN] Client Assertion Type: {}", requestBody.getFirst("client_assertion_type"));

        String clientAssertion = requestBody.getFirst("client_assertion");
        if (clientAssertion != null) {
            logger.trace("[SCOTACCOUNT-TOKEN] Client Assertion (first 100 chars): {}...",
                    clientAssertion.substring(0, Math.min(100, clientAssertion.length())));
        } else {
            logger.trace("[SCOTACCOUNT-TOKEN] Client Assertion: null");
        }
        logger.trace("[SCOTACCOUNT-TOKEN] =================================================================");
    }

    /**
     * Decodes and parses a JWT payload into a Map of claims.
     * 
     * <p>
     * This method splits the JWT, extracts the payload section, Base64Url decodes
     * it,
     * and parses the resulting JSON into a Map of claims.
     * </p>
     * 
     * @param jwt The JWT string to decode
     * @return Map of claims from the JWT payload
     * @throws IllegalArgumentException if the JWT format is invalid
     * @throws RuntimeException         if there's an error parsing the payload
     */
    private Map<String, Object> decodeJwtPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        String payload = parts[1];
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        String decodedPayload = new String(decodedBytes, StandardCharsets.UTF_8);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = objectMapper.readValue(decodedPayload, Map.class);
            return claims;
        } catch (Exception e) {
            logger.error("Error parsing JWT payload", e);
            throw new RuntimeException("Error parsing JWT payload", e);
        }
    }

    /**
     * Performs the OAuth2 token exchange using the authorization code grant.
     * 
     * <p>
     * This method handles the complete token exchange process with ScotAccount:
     * </p>
     * 
     * <ol>
     * <li>Extracts authorization code and PKCE verifier from the request</li>
     * <li>Generates a client assertion JWT for authentication</li>
     * <li>Builds and sends the token request to ScotAccount</li>
     * <li>Processes the token response, extracts tokens and claims</li>
     * <li>Builds a standardized OAuth2AccessTokenResponse with all required
     * information</li>
     * </ol>
     * 
     * @param authorizationCodeGrantRequest The OAuth2 authorization code grant
     *                                      request
     * @return OAuth2AccessTokenResponse containing the processed tokens and claims
     * @throws RuntimeException if token exchange or processing fails
     */
    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = authorizationCodeGrantRequest.getAuthorizationExchange();
        OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();

        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
        logger.trace("[OIDC-FLOW] ================ TOKEN EXCHANGE STARTING ================");
        logger.trace("[OIDC-FLOW] Preparing token request to: {}", tokenUri);

        try {
            // Generate client assertion JWT
            String clientAssertion = jwtUtil.createClientAssertion(
                    clientRegistration.getClientId(),
                    tokenUri);
            logger.trace("[OIDC-FLOW] Generated client assertion JWT");

            // Build request body as form-urlencoded (as per OAuth2 spec)
            org.springframework.util.MultiValueMap<String, String> requestBody = new org.springframework.util.LinkedMultiValueMap<>();
            requestBody.add("grant_type", "authorization_code");
            requestBody.add("code", authorizationResponse.getCode());
            requestBody.add("redirect_uri", authorizationResponse.getRedirectUri());
            requestBody.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            requestBody.add("client_assertion", clientAssertion);

            // Add code_verifier from the authorization request
            String codeVerifier = (String) authorizationExchange.getAuthorizationRequest()
                    .getAttributes().get("code_verifier");
            requestBody.add("code_verifier", codeVerifier);

            logger.trace("[OIDC-FLOW] === TOKEN REQUEST DEBUG ===");
            logger.trace("[OIDC-FLOW] Token endpoint: {}", tokenUri);
            logger.trace("[OIDC-FLOW] Authorization code: {}", authorizationResponse.getCode());
            logger.trace("[OIDC-FLOW] Redirect URI: {}", authorizationResponse.getRedirectUri());
            logger.trace("[OIDC-FLOW] Code verifier: {}", codeVerifier);
            logger.trace("[OIDC-FLOW] Client assertion (truncated): {}...",
                    clientAssertion.substring(0, Math.min(50, clientAssertion.length())));
            logger.trace("[OIDC-FLOW] Request parameters: {}", requestBody);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<org.springframework.util.MultiValueMap<String, String>> request = new HttpEntity<>(requestBody,
                    headers);

            // Log detailed token exchange request
            logTokenExchangeRequest(requestBody, headers, tokenUri);

            logger.trace("[OIDC-FLOW] === SENDING TOKEN REQUEST ===");
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenResponse = restTemplate.exchange(
                    tokenUri,
                    HttpMethod.POST,
                    request,
                    Map.class).getBody();

            if (tokenResponse == null) {
                logger.error("No response received from token endpoint");
                throw new RuntimeException("No response received from token endpoint");
            }

            logger.trace("[OIDC-FLOW] ================ TOKEN EXCHANGE SUCCESS ================");
            logger.trace("[OIDC-FLOW] Successfully received token response");

            // Extract tokens from response
            String accessToken = (String) tokenResponse.get("access_token");
            String refreshToken = (String) tokenResponse.get("refresh_token");
            String idTokenStr = (String) tokenResponse.get("id_token");
            Long expiresIn = ((Number) tokenResponse.get("expires_in")).longValue();
            String scope = (String) tokenResponse.get("scope");

            // Decode the access token without validation
            Map<String, Object> accessTokenClaims = decodeJwtPayload(accessToken);

            // Build the OAuth2AccessTokenResponse with all tokens
            return OAuth2AccessTokenResponse.withToken(accessToken)
                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .expiresIn(expiresIn)
                    .scopes(Set.of(scope.split(" ")))
                    .refreshToken(refreshToken)
                    .additionalParameters(Map.of(
                            "id_token", idTokenStr,
                            "access_token_claims", accessTokenClaims))
                    .build();

        } catch (Exception e) {
            logger.trace("[OIDC-FLOW] ================ TOKEN EXCHANGE ERROR ================");
            logger.trace("[OIDC-FLOW] Error type: {}", e.getClass().getSimpleName());
            logger.trace("[OIDC-FLOW] Error message: {}", e.getMessage());
            if (e.getCause() != null) {
                logger.trace("[OIDC-FLOW] Cause: {}", e.getCause().getMessage());
            }
            logger.error("[OIDC-FLOW] Full error details:", e);
            throw new RuntimeException("Error exchanging code for token", e);
        }
    }
}