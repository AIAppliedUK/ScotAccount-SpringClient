package scot.gov.scotaccountclient;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * Utility class for handling JWT operations in the ScotAccount client application.
 *
 * <p>This class provides OIDC-compliant JWT handling with proper support for:</p>
 * <ul>
 *   <li>EC (P-256/ES256) and RSA (RS256) key algorithms</li>
 *   <li>Client assertion JWT generation with proper kid header</li>
 *   <li>JWT validation using JWKS endpoint</li>
 *   <li>Public key caching for performance</li>
 * </ul>
 *
 * <p><b>OIDC Compliance:</b></p>
 * <ul>
 *   <li>Uses Nimbus JOSE+JWT for proper EC signature handling</li>
 *   <li>Includes 'kid' (key ID) in JWT header for JWK matching</li>
 *   <li>Supports both SEC1 and PKCS#8 EC key formats</li>
 *   <li>ES256 (ECDSA with P-256 and SHA-256) for EC keys</li>
 *   <li>RS256 (RSA with SHA-256) for RSA keys</li>
 * </ul>
 */
@Component
public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private final ScotAccountProperties scotAccountProperties;
    private final RestTemplate restTemplate;

    private PrivateKey privateKey;
    private String keyId; // Key ID for the kid header
    private Map<String, PublicKey> publicKeyCache = new HashMap<>();

    @Value("${spring.security.oauth2.client.provider.scotaccount.jwk-set-uri}")
    private String jwksUrl;

    public JwtUtil(ScotAccountProperties scotAccountProperties, RestTemplate restTemplate) {
        this.scotAccountProperties = scotAccountProperties;
        this.restTemplate = restTemplate;
    }

    /**
     * Loads a public key from JWKS for a specific key ID.
     */
    private PublicKey loadPublicKeyFromJwks(String keyId) throws Exception {
        if (publicKeyCache.containsKey(keyId)) {
            return publicKeyCache.get(keyId);
        }

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = restTemplate.getForEntity(jwksUrl, Map.class);
        @SuppressWarnings("rawtypes")
        Map responseBody = response.getBody();
        if (responseBody == null) {
            throw new IllegalStateException("JWKS response body is null");
        }
        @SuppressWarnings("unchecked")
        List<Map<String, String>> keys = (List<Map<String, String>>) responseBody.get("keys");

        for (Map<String, String> key : keys) {
            if (keyId.equals(key.get("kid"))) {
                String keyJson = new ObjectMapper().writeValueAsString(key);
                JWK jwk = JWK.parse(keyJson);

                PublicKey publicKey;
                if (jwk instanceof ECKey) {
                    publicKey = ((ECKey) jwk).toPublicKey();
                } else if (jwk instanceof RSAKey) {
                    publicKey = ((RSAKey) jwk).toPublicKey();
                } else {
                    throw new UnsupportedOperationException("Unsupported JWK key type: " + jwk.getKeyType());
                }

                publicKeyCache.put(keyId, publicKey);
                logger.trace("[JWT] Successfully loaded and cached public key for kid: {}", keyId);
                return publicKey;
            }
        }
        throw new IllegalArgumentException("No matching key found for kid: " + keyId);
    }

    /**
     * Loads the private key from the configured path.
     * Supports both PKCS#8 and SEC1 (traditional EC) formats.
     */
    public PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (privateKey != null) {
            return privateKey;
        }

        String privateKeyPath = scotAccountProperties.getPrivateKeyPath();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyPath)) {
            if (is == null) {
                throw new IOException("Private key file not found: " + privateKeyPath);
            }
            String privateKeyContent = new String(is.readAllBytes());

            // Use Nimbus JOSE+JWT to parse the key - it handles all formats properly
            try {
                JWK jwk = JWK.parseFromPEMEncodedObjects(privateKeyContent);

                if (jwk instanceof ECKey) {
                    ECKey ecKey = (ECKey) jwk;
                    privateKey = ecKey.toPrivateKey();
                    // Generate a key ID for this key
                    keyId = generateKeyId(ecKey);
                    logger.info("[JWT] Loaded EC private key successfully with kid: {}", keyId);
                } else if (jwk instanceof RSAKey) {
                    RSAKey rsaKey = (RSAKey) jwk;
                    privateKey = rsaKey.toPrivateKey();
                    // Generate a key ID for this key
                    keyId = generateKeyId(rsaKey);
                    logger.info("[JWT] Loaded RSA private key successfully with kid: {}", keyId);
                } else {
                    throw new UnsupportedOperationException("Unsupported key type: " + jwk.getKeyType());
                }

                return privateKey;
            } catch (JOSEException e) {
                logger.error("[JWT] Failed to parse private key using Nimbus JOSE+JWT", e);
                throw new IOException("Failed to parse private key: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Generates a key ID (kid) for a JWK.
     * Uses the JWK thumbprint (SHA-256 hash) as recommended by RFC 7638.
     */
    private String generateKeyId(JWK jwk) throws JOSEException {
        // Use JWK thumbprint as kid (RFC 7638 compliant)
        return jwk.computeThumbprint().toString();
    }

    /**
     * Creates a client assertion JWT for OAuth2 authentication using Nimbus JOSE+JWT.
     *
     * <p><b>OIDC Compliance:</b></p>
     * <ul>
     *   <li>Includes 'kid' header for JWK identification</li>
     *   <li>Uses ES256 for EC keys, RS256 for RSA keys</li>
     *   <li>Proper signature generation via Nimbus JOSE+JWT</li>
     * </ul>
     *
     * @param clientId      The OAuth2 client ID
     * @param tokenEndpoint The OAuth2 token endpoint URL
     * @return The generated client assertion JWT
     * @throws Exception if token creation fails
     */
    public String createClientAssertion(String clientId, String tokenEndpoint) throws Exception {
        PrivateKey privateKey = loadPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key not available");
        }

        // Build JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(tokenEndpoint)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300000)) // 5 minutes
                .build();

        // Determine algorithm and create signer
        JWSAlgorithm algorithm;
        JWSSigner signer;

        if (privateKey instanceof ECPrivateKey) {
            algorithm = JWSAlgorithm.ES256;
            signer = new ECDSASigner((ECPrivateKey) privateKey);
            logger.debug("[JWT] Creating client assertion with ES256 algorithm");
        } else if (privateKey instanceof RSAPrivateKey) {
            algorithm = JWSAlgorithm.RS256;
            signer = new RSASSASigner((RSAPrivateKey) privateKey);
            logger.debug("[JWT] Creating client assertion with RS256 algorithm");
        } else {
            throw new IllegalStateException("Unsupported private key type: " + privateKey.getClass());
        }

        // Build JWT header with kid
        JWSHeader header = new JWSHeader.Builder(algorithm)
                .keyID(keyId) // CRITICAL: kid header for JWK matching
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .build();

        // Create and sign JWT
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();
        logger.debug("[JWT] Created client assertion JWT with kid: {}", keyId);
        logger.trace("[JWT] JWT header: {}", signedJWT.getHeader());

        return jwt;
    }

    /**
     * Validates a JWT and returns its claims.
     * Uses JJWT for validation since it handles verification well.
     *
     * @param jwt The JWT to validate
     * @return The claims from the validated JWT
     * @throws Exception if the JWT is invalid or cannot be verified
     */
    public Claims validateJwt(String jwt) throws Exception {
        String keyId = extractKeyId(jwt);
        PublicKey publicKey = loadPublicKeyFromJwks(keyId);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    /**
     * Extracts the key ID from a JWT header.
     */
    private String extractKeyId(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> header = new ObjectMapper().readValue(headerJson, Map.class);
            String kid = header.get("kid");
            if (kid == null) {
                throw new IllegalArgumentException("No 'kid' found in JWT header");
            }
            return kid;
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JWT header", e);
        }
    }

    /**
     * Gets the key ID (kid) for the loaded private key.
     *
     * @return The key ID
     * @throws Exception if the key hasn't been loaded yet
     */
    public String getKeyId() throws Exception {
        if (keyId == null) {
            loadPrivateKey(); // Ensure key is loaded
        }
        return keyId;
    }
}
