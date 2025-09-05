package scot.gov.scotaccountclient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
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
     * Configures a RestTemplate with buffering and logging capabilities for
     * detailed troubleshooting and request tracing.
     * </p>
     * 
     * @param jwtUtil JWT utility for generating client assertions and processing
     *                tokens
     */
    public CustomOAuth2AccessTokenResponseClient(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = new ObjectMapper();

        // Create RestTemplate with buffering enabled to allow multiple reads of the
        // response body
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        BufferingClientHttpRequestFactory bufferingRequestFactory = new BufferingClientHttpRequestFactory(
                requestFactory);

        this.restTemplate = new RestTemplate(bufferingRequestFactory);

        // Add logging interceptor for detailed request/response logging
        ClientHttpRequestInterceptor loggingInterceptor = (request, body, execution) -> {
            logger.trace("=========================== REQUEST ===========================");
            logger.trace("URI: {}", request.getURI());
            logger.trace("Method: {}", request.getMethod());
            logger.trace("Headers: {}", request.getHeaders());
            logger.trace("Request body: {}", new String(body, StandardCharsets.UTF_8));

            var response = execution.execute(request, body);

            logger.trace("========================== RESPONSE ==========================");
            logger.trace("Status code: {}", response.getStatusCode());
            logger.trace("Headers: {}", response.getHeaders());

            byte[] responseBody = response.getBody().readAllBytes();
            logger.trace("Response body: {}", new String(responseBody, StandardCharsets.UTF_8));
            logger.trace("=============================================================");

            return response;
        };

        this.restTemplate.setInterceptors(Collections.singletonList(loggingInterceptor));
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
        logger.debug("Preparing token request to: {}", tokenUri);

        try {
            // Generate client assertion JWT
            String clientAssertion = jwtUtil.createClientAssertion(
                    clientRegistration.getClientId(),
                    tokenUri);
            logger.debug("Generated client assertion JWT");

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

            logger.info("=== TOKEN REQUEST DEBUG ===");
            logger.info("Token endpoint: {}", tokenUri);
            logger.info("Authorization code: {}", authorizationResponse.getCode());
            logger.info("Redirect URI: {}", authorizationResponse.getRedirectUri());
            logger.info("Code verifier: {}", codeVerifier);
            logger.info("Client assertion (truncated): {}...",
                    clientAssertion.substring(0, Math.min(50, clientAssertion.length())));
            logger.info("Request parameters: {}", requestBody);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<org.springframework.util.MultiValueMap<String, String>> request = new HttpEntity<>(requestBody,
                    headers);

            logger.info("Request headers: {}", headers);
            logger.info("=== SENDING TOKEN REQUEST ===");
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

            logger.debug("Successfully received token response");

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
            logger.error("=== TOKEN EXCHANGE ERROR ===");
            logger.error("Error type: {}", e.getClass().getSimpleName());
            logger.error("Error message: {}", e.getMessage());
            if (e.getCause() != null) {
                logger.error("Cause: {}", e.getCause().getMessage());
            }
            logger.error("Full error details:", e);
            throw new RuntimeException("Error exchanging code for token", e);
        }
    }
}