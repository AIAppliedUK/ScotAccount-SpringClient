package scot.gov.scotaccountclient;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service class for fetching user attributes from ScotAccount API.
 * 
 * <p>
 * This service handles the communication with the ScotAccount attributes
 * endpoint
 * to retrieve user attributes based on an access token. It uses a client
 * assertion
 * JWT for API authentication.
 * </p>
 * 
 * <p>
 * The attributes are returned as a decoded JWT claims token from the response.
 * </p>
 */
@Service
public class AttributeService {
    /** Logger for the AttributeService class. */
    private static final Logger logger = LoggerFactory.getLogger(AttributeService.class);

    /** Template for making HTTP requests to the attributes endpoint. */
    private final RestTemplate restTemplate;

    /** Utility for JWT token operations. */
    private final JwtUtil jwtUtil;

    /** Mapper for JSON serialization and deserialization. */
    private final ObjectMapper objectMapper;

    /** OAuth2 client ID for authentication with ScotAccount. */
    @Value("${spring.security.oauth2.client.registration.scotaccount.client-id}")
    private String clientId;

    /** The endpoint URL for retrieving user attributes from ScotAccount. */
    @Value("${spring.security.oauth2.client.provider.scotaccount.user-info-uri}")
    private String attributesEndpoint;

    /**
     * Constructs an AttributeService with the necessary dependencies.
     *
     * @param restTemplate the RestTemplate used for HTTP requests
     * @param jwtUtil      the utility for JWT operations
     * @param objectMapper the mapper for JSON serialization/deserialization
     */
    public AttributeService(RestTemplate restTemplate, JwtUtil jwtUtil, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

    /**
     * Fetches user attributes from the ScotAccount API using the provided access
     * token.
     * 
     * <p>
     * This method:
     * </p>
     * <ol>
     * <li>Creates a client assertion JWT for API authentication</li>
     * <li>Makes a GET request to the attributes endpoint with proper headers</li>
     * <li>Extracts and decodes the JWT claims token from the response</li>
     * <li>Returns the decoded claims as a map of attributes</li>
     * </ol>
     *
     * <p>
     * If any errors occur during the process, the error is logged and null is
     * returned.
     * </p>
     *
     * @param accessToken the OAuth2 access token for the authenticated user
     * @return a map of user attributes, or null if the request fails
     */
    public Map<String, Object> fetchAttributes(String accessToken) {
        try {
            String clientAssertion = jwtUtil.createClientAssertion(clientId, attributesEndpoint);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            headers.set("DIS-Client-Assertion", clientAssertion);

            HttpEntity<?> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    attributesEndpoint,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> responseMap = objectMapper.readValue(response.getBody(), Map.class);
                logger.info("Raw response from endpoint: {}",
                        objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseMap));

                String claimsToken = (String) responseMap.get("claimsToken");
                logger.info("Claims token: {}", claimsToken);

                // Decode and parse the JWT claims
                String[] parts = claimsToken.split("\\.");
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                logger.info("Decoded payload: {}", payload);

                @SuppressWarnings("unchecked")
                Map<String, Object> claims = objectMapper.readValue(payload, Map.class);
                logger.info("Parsed claims: {}",
                        objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(claims));

                // Handle verified_claims more carefully
                Object verifiedClaims = claims.get("verified_claims");
                if (verifiedClaims != null) {
                    logger.info("Verified claims type: {}", verifiedClaims.getClass().getName());
                    logger.info("Verified claims content: {}",
                            objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(verifiedClaims));

                    // If verifiedClaims is not already a List, try to convert it
                    if (!(verifiedClaims instanceof List)) {
                        try {
                            // Try to convert to List if it's a single object
                            verifiedClaims = Collections.singletonList(verifiedClaims);
                            logger.info("Converted single verified claim to list");
                        } catch (Exception e) {
                            logger.error("Failed to convert verified claims to list", e);
                            verifiedClaims = Collections.emptyList();
                        }
                    }

                    claims.put("verified_claims", verifiedClaims);
                } else {
                    logger.warn("No verified claims found in the decoded payload");
                    claims.put("verified_claims", Collections.emptyList());
                }

                return claims;
            }

            logger.error("Failed to fetch attributes. Status: {}", response.getStatusCode());
            return null;
        } catch (Exception e) {
            logger.error("Error fetching attributes", e);
            return null;
        }
    }
}