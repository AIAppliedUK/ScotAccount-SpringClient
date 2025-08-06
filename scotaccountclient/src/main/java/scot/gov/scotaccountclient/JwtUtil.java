package scot.gov.scotaccountclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

/**
 * Utility class for handling JWT operations in the ScotAccount client
 * application.
 * 
 * <p>
 * This class provides functionality for:
 * </p>
 * <ul>
 * <li>Loading and managing RSA keys for JWT signing and validation</li>
 * <li>Generating client assertion JWTs for OAuth2 authentication</li>
 * <li>Validating JWTs using public keys from ScotAccount's JWKS endpoint</li>
 * <li>Caching public keys to improve performance</li>
 * </ul>
 * 
 * <p>
 * Key features:
 * </p>
 * <ul>
 * <li>Automatic JWKS key rotation handling</li>
 * <li>Public key caching to reduce JWKS endpoint calls</li>
 * <li>Support for RSA-256 signing algorithm</li>
 * <li>Proper key format handling (PKCS#8 for private, X.509 for public)</li>
 * </ul>
 * 
 * <p>
 * Usage example:
 * </p>
 * 
 * <pre>
 * JwtUtil jwtUtil = new JwtUtil();
 * String clientAssertion = jwtUtil.createClientAssertion(
 *         "client-id",
 *         "https://token-endpoint");
 * </pre>
 */
@Component
public class JwtUtil {
    /** Path to the private key file used for JWT signing. */
    private static final String PRIVATE_KEY_PATH = "keys/private.pem";

    /** HTTP client for making requests to the JWKS endpoint. */
    private final RestTemplate restTemplate;

    /** Cached private key for JWT signing. */
    private PrivateKey privateKey;

    /** Cache of public keys indexed by key ID for JWT verification. */
    private Map<String, PublicKey> publicKeyCache = new HashMap<>();

    /** URL of the JWKS endpoint for retrieving public keys. */
    @Value("${spring.security.oauth2.client.provider.scotaccount.jwk-set-uri}")
    private String jwksUrl;

    /**
     * Constructs a new JwtUtil instance with a default RestTemplate.
     */
    public JwtUtil() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Decodes a Base64URL-encoded string to a BigInteger.
     * Used for converting JWK components (n, e) to their BigInteger
     * representations.
     *
     * @param base64Url The Base64URL-encoded string to decode
     * @return The decoded value as a BigInteger
     * @throws IllegalArgumentException if the input is not valid Base64URL
     */
    private BigInteger base64UrlToBigInteger(String base64Url) {
        byte[] decoded = Base64.getUrlDecoder().decode(base64Url);
        return new BigInteger(1, decoded);
    }

    /**
     * Loads a public key from JWKS for a specific key ID.
     * 
     * <p>
     * This method first checks the internal cache. If the key is not found in the
     * cache,
     * it requests the JWKS from the configured endpoint and looks for a matching
     * key ID.
     * When found, the key is cached for future use.
     * </p>
     *
     * @param keyId the ID of the key to load
     * @return the public key corresponding to the given key ID
     * @throws Exception if the key cannot be found or loaded
     */
    private PublicKey loadPublicKeyFromJwks(String keyId) throws Exception {
        // Check cache first
        if (publicKeyCache.containsKey(keyId)) {
            return publicKeyCache.get(keyId);
        }

        ResponseEntity<Map> response = restTemplate.getForEntity(jwksUrl, Map.class);
        List<Map<String, String>> keys = (List<Map<String, String>>) response.getBody().get("keys");

        for (Map<String, String> key : keys) {
            if (keyId.equals(key.get("kid"))) {
                // Convert JWK parameters to RSA public key
                BigInteger modulus = base64UrlToBigInteger(key.get("n"));
                BigInteger exponent = base64UrlToBigInteger(key.get("e"));

                RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = factory.generatePublic(spec);

                // Cache the key
                publicKeyCache.put(keyId, publicKey);
                return publicKey;
            }
        }
        throw new IllegalArgumentException("No matching key found for kid: " + keyId);
    }

    /**
     * Loads the RSA private key from the configured path.
     * 
     * <p>
     * The key is loaded from the classpath and cached for subsequent calls.
     * </p>
     *
     * @return The loaded PrivateKey instance
     * @throws IOException              if the key file cannot be read
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeySpecException  if the key format is invalid
     */
    public PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (privateKey != null) {
            return privateKey;
        }

        try (InputStream is = getClass().getClassLoader().getResourceAsStream(PRIVATE_KEY_PATH)) {
            if (is == null) {
                throw new IOException("Private key file not found: " + PRIVATE_KEY_PATH);
            }
            String privateKeyPEM = new String(is.readAllBytes())
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        }
    }

    /**
     * Creates a JWT with the specified claims and expiration time.
     * 
     * <p>
     * The JWT is signed using the RSA private key with the RS256 algorithm.
     * </p>
     *
     * @param claims       The claims to include in the JWT
     * @param expirationMs The expiration time in milliseconds
     * @return The generated JWT string
     * @throws Exception if token creation fails
     */
    public String createJwt(Claims claims, long expirationMs) throws Exception {
        PrivateKey privateKey = loadPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key not available. Cannot create JWT without private key.");
        }
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Creates a client assertion JWT for OAuth2 authentication.
     * 
     * <p>
     * This method generates a JWT that can be used as a client assertion
     * in OAuth2 client authentication. The JWT includes standard claims
     * required for client authentication according to OAuth2 specifications.
     * </p>
     *
     * @param clientId      The OAuth2 client ID
     * @param tokenEndpoint The OAuth2 token endpoint URL
     * @return The generated client assertion JWT
     * @throws Exception if token creation fails
     */
    public String createClientAssertion(String clientId, String tokenEndpoint) throws Exception {
        Claims claims = Jwts.claims()
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(tokenEndpoint)
                .setId(UUID.randomUUID().toString());

        // Calculate 6 months in milliseconds
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 6);
        long expirationMs = calendar.getTimeInMillis() - System.currentTimeMillis();

        return createJwt(claims, expirationMs);
    }

    /**
     * Extracts the key ID from a JWT header.
     * 
     * <p>
     * This method parses the JWT header to extract the 'kid' (key ID) claim,
     * which is used to identify the correct public key for validation.
     * <
     *
     * @param jwt The JWT string to parse
     * @return The key ID extracted from the JWT header
     * @throws IllegalArgumentException if the JWT format is invalid or no key ID is
     *                                  found
     * @throws RuntimeException         if there's an error parsing the JWT header
     */
    private String extractKeyId(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        try {
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
     * Validates a JWT and returns its claims.
     * 
     * <p>
     * This method:
     * </p>
     * <ol>
     * <li>Extracts the key ID from the JWT header</li>
     * <li>Loads the corresponding public key from the JWKS endpoint</li>
     * <li>Verifies the JWT signature and validity</li>
     * <li>Returns the claims if the JWT is valid</li>
     * </ol>
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
     * Extracts verifier information from verification claims.
     * 
     * @param verification The verification claims map
     * @return A map containing verifier details, or an empty map if none are found
     */
    @SuppressWarnings("unchecked")
    private Map<String, String> extractVerifier(Map<String, Object> verification) {
        return (Map<String, String>) verification.getOrDefault("verifier", Collections.emptyMap());
    }
}