package scot.gov.scotaccountclient;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Utility class for handling JWT operations in the ScotAccount client
 * application.
 * 
 * <p>
 * This class provides functionality for:
 * </p>
 * <ul>
 * <li>Loading and managing EC keys for JWT signing and validation</li>
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
 * <li>Support for EC-256 signing algorithm</li>
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
    /** Logger for the JwtUtil class. */
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /** Configuration properties for ScotAccount integration. */
    private final ScotAccountProperties scotAccountProperties;

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
     * Constructs a new JwtUtil instance with the required dependencies.
     * 
     * @param scotAccountProperties Configuration properties for ScotAccount
     *                              integration
     * @param restTemplate          HTTP client for making requests to the JWKS
     *                              endpoint
     */
    public JwtUtil(ScotAccountProperties scotAccountProperties, RestTemplate restTemplate) {
        this.scotAccountProperties = scotAccountProperties;
        this.restTemplate = restTemplate;
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
                // Convert JWK to PublicKey using Nimbus JOSE+JWT
                try {
                    // Convert Map to JSON string for JWK parsing
                    String keyJson = new ObjectMapper().writeValueAsString(key);
                    JWK jwk = JWK.parse(keyJson);

                    // Convert JWK to PublicKey based on key type
                    PublicKey publicKey;
                    if (jwk instanceof ECKey) {
                        publicKey = ((ECKey) jwk).toPublicKey();
                    } else if (jwk instanceof RSAKey) {
                        publicKey = ((RSAKey) jwk).toPublicKey();
                    } else {
                        throw new UnsupportedOperationException("Unsupported JWK key type: " + jwk.getKeyType());
                    }

                    // Cache the public key for future use
                    publicKeyCache.put(keyId, publicKey);

                    logger.trace("[OIDC-FLOW] Successfully loaded and cached public key for kid: {}", keyId);
                    return publicKey;
                } catch (Exception e) {
                    logger.error("Failed to parse JWK for kid: {}", keyId, e);
                    throw new IllegalStateException("Failed to parse JWK for key ID: " + keyId, e);
                }
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

        String privateKeyPath = scotAccountProperties.getPrivateKeyPath();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyPath)) {
            if (is == null) {
                throw new IOException("Private key file not found: " + privateKeyPath);
            }
            String privateKeyContent = new String(is.readAllBytes());

            if (privateKeyContent.contains("-----BEGIN EC PRIVATE KEY-----")) {
                // Handle EC Private Key format (including files with EC PARAMETERS)
                logger.trace("[OIDC-FLOW] Loading EC private key");

                // Extract only the EC PRIVATE KEY section, ignoring EC PARAMETERS if present
                String[] sections = privateKeyContent.split("-----BEGIN EC PRIVATE KEY-----");
                if (sections.length < 2) {
                    throw new IOException("Invalid EC private key format - missing EC PRIVATE KEY section");
                }

                String ecPrivateKeyPEM = sections[1]
                        .split("-----END EC PRIVATE KEY-----")[0]
                        .replaceAll("\\s", "");

                try {
                    byte[] ecEncoded = Base64.getDecoder().decode(ecPrivateKeyPEM);

                    // Try PKCS#8 format first (most common and reliable)
                    try {
                        KeyFactory keyFactory = KeyFactory.getInstance("EC");
                        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(ecEncoded);
                        privateKey = keyFactory.generatePrivate(keySpec);
                        logger.trace("[OIDC-FLOW] Successfully loaded EC private key as PKCS#8");
                        return privateKey;
                    } catch (InvalidKeySpecException e) {
                        logger.trace("[OIDC-FLOW] PKCS#8 parsing failed, trying legacy EC format");
                    }

                    // Fallback to legacy EC format parsing
                    // The legacy EC format is a simple ASN.1 structure containing just the private
                    // key value
                    // For P-256 curve, the private key is typically 32 bytes
                    // The ASN.1 structure is: SEQUENCE { INTEGER privateKey }
                    if (ecEncoded.length >= 3 && ecEncoded[0] == 0x30) { // SEQUENCE
                        int offset = 2; // Skip SEQUENCE tag and length
                        if (ecEncoded[offset] == 0x02) { // INTEGER
                            offset++; // Skip INTEGER tag
                            int keyLength = ecEncoded[offset] & 0xFF;
                            offset++; // Skip length

                            // Extract the private key value
                            byte[] keyBytes = new byte[keyLength];
                            System.arraycopy(ecEncoded, offset, keyBytes, 0, keyLength);

                            // Create ECPrivateKeySpec for P-256 curve
                            BigInteger privateKeyValue = new BigInteger(1, keyBytes);

                            // For P-256 curve, we'll use a simpler approach
                            // Create the curve parameters manually for secp256r1
                            java.security.spec.ECFieldFp field = new java.security.spec.ECFieldFp(
                                    new BigInteger(
                                            "115792089210356248762697446949407573530086143415290314195533631308867097853951"));
                            java.security.spec.ECPoint g = new java.security.spec.ECPoint(
                                    new BigInteger(
                                            "48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                                    new BigInteger(
                                            "36134250956749795798585127919587881956611106672985015071877198253568414405109"));
                            java.security.spec.ECParameterSpec ecParams = new java.security.spec.ECParameterSpec(
                                    new java.security.spec.EllipticCurve(field,
                                            new BigInteger(
                                                    "115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                                            new BigInteger(
                                                    "41058363725152142129326129780047268409114441015993725554835256314039467401291")),
                                    g,
                                    new BigInteger(
                                            "115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                                    1);

                            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(privateKeyValue, ecParams);
                            KeyFactory keyFactory = KeyFactory.getInstance("EC");
                            privateKey = keyFactory.generatePrivate(keySpec);

                            logger.trace("[OIDC-FLOW] Successfully loaded EC private key in legacy format");
                            return privateKey;
                        }
                    }

                    logger.error("Failed to parse EC private key in any supported format");
                    throw new IOException("Unable to parse EC private key - unsupported format");

                } catch (IllegalArgumentException e) {
                    logger.error("Failed to decode Base64 for EC private key");
                    throw new IOException("Invalid Base64 encoding in EC private key", e);
                }

            } else if (privateKeyContent.contains("-----BEGIN PRIVATE KEY-----")) {
                // Handle PKCS#8 format (works for both RSA and EC keys)
                logger.trace("[OIDC-FLOW] Loading private key in PKCS#8 format");
                String privateKeyPEM = privateKeyContent
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");

                try {
                    byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
                    String keyType = detectKeyType(encoded);
                    logger.trace("[OIDC-FLOW] Detected key type: {}", keyType);

                    KeyFactory keyFactory = KeyFactory.getInstance(keyType);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
                    privateKey = keyFactory.generatePrivate(keySpec);
                    logger.trace("[OIDC-FLOW] Successfully loaded {} private key", keyType);
                    return privateKey;
                } catch (IllegalArgumentException e) {
                    logger.error("Failed to decode Base64 for PKCS#8 private key");
                    throw new IOException("Invalid Base64 encoding in PKCS#8 private key", e);
                }

            } else if (privateKeyContent.contains("-----BEGIN RSA PRIVATE KEY-----")) {
                // Handle RSA Private Key in the old format (for backward compatibility)
                logger.trace("[OIDC-FLOW] Loading RSA private key in old format");
                String rsaPrivateKeyPEM = privateKeyContent
                        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                        .replace("-----END RSA PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");

                try {
                    byte[] rsaEncoded = Base64.getDecoder().decode(rsaPrivateKeyPEM);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(rsaEncoded);
                    privateKey = keyFactory.generatePrivate(keySpec);
                    logger.trace("[OIDC-FLOW] Successfully loaded RSA private key");
                    return privateKey;
                } catch (IllegalArgumentException e) {
                    logger.error("Failed to decode Base64 for RSA private key");
                    throw new IOException("Invalid Base64 encoding in RSA private key", e);
                }

            } else {
                throw new IOException("Unsupported private key format. Expected one of: " +
                        "EC PRIVATE KEY, PRIVATE KEY, or RSA PRIVATE KEY format.");
            }
        }
    }

    /**
     * Detects the key type based on the decoded key bytes.
     * EC keys start with specific byte patterns that differ from RSA keys.
     *
     * @param keyBytes The decoded key bytes
     * @return The key type ("EC" or "RSA")
     */
    private String detectKeyType(byte[] keyBytes) {
        // EC keys have the object identifier for id-ecPublicKey (1.2.840.10045.2.1)
        // This appears as: 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
        if (keyBytes.length > 10 &&
                keyBytes[0] == 0x30 && // SEQUENCE
                keyBytes[2] == 0x30 && // SEQUENCE
                keyBytes[4] == 0x06 && // OBJECT IDENTIFIER
                keyBytes[5] == 0x07 && // length 7
                keyBytes[6] == 0x2A && // 1.2
                keyBytes[7] == (byte) 0x86 && // 840
                keyBytes[8] == 0x48 && // 10045
                keyBytes[9] == (byte) 0xCE && // 2.1
                keyBytes[10] == 0x3D) {
            return "EC";
        }

        // RSA keys have the object identifier for rsaEncryption (1.2.840.113549.1.1.1)
        // This appears as: 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        // 0x01
        if (keyBytes.length > 10 &&
                keyBytes[0] == 0x30 && // SEQUENCE
                keyBytes[2] == 0x30 && // SEQUENCE
                keyBytes[4] == 0x06 && // OBJECT IDENTIFIER
                keyBytes[5] == 0x09 && // length 9
                keyBytes[6] == 0x2A && // 1.2
                keyBytes[7] == (byte) 0x86 && // 840
                keyBytes[8] == 0x48 && // 113549
                keyBytes[9] == (byte) 0x86 && // 1.1.1
                keyBytes[10] == (byte) 0xF7) {
            return "RSA";
        }

        // Default to RSA if we can't determine (for backward compatibility)
        return "RSA";
    }

    /**
     * Creates a JWT with the specified claims and expiration time.
     * 
     * <p>
     * The JWT is signed using the private key with the appropriate algorithm (ES256
     * for EC, RS256 for RSA).
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

        // Choose the appropriate signing algorithm based on key type
        SignatureAlgorithm algorithm = (privateKey instanceof ECPrivateKey) ? SignatureAlgorithm.ES256
                : SignatureAlgorithm.RS256;

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .setHeaderParam("typ", "JWT") // Explicitly set JWT type
                .signWith(privateKey, algorithm)
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
        Claims claims = Jwts.claims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(tokenEndpoint);
        claims.setId(UUID.randomUUID().toString());

        // Set issued at time
        Date now = new Date();
        claims.setIssuedAt(now);

        // Set expiration to 5 minutes from now (standard for client assertions)
        Date expiration = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes
        claims.setExpiration(expiration);

        // Don't use the createJwt method since it would overwrite iat and exp
        PrivateKey privateKey = loadPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key not available. Cannot create JWT without private key.");
        }

        // Choose the appropriate signing algorithm based on key type
        SignatureAlgorithm algorithm = (privateKey instanceof ECPrivateKey) ? SignatureAlgorithm.ES256
                : SignatureAlgorithm.RS256;

        return Jwts.builder()
                .setClaims(claims)
                .setHeaderParam("typ", "JWT")
                .signWith(privateKey, algorithm)
                .compact();
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
     * Generates a JWK (JSON Web Key) from the loaded private key.
     * 
     * <p>
     * This method is useful for registering the client's public key with
     * ScotAccount
     * or for sharing the public key in JWK format. The generated JWK includes
     * standard metadata like key ID, usage, and issue time.
     * </p>
     *
     * @param keyUse     The intended use of the key ("sig" for signature, "enc" for
     *                   encryption)
     * @param publicOnly Whether to include only the public key (exclude private
     *                   key)
     * @return The JWK in JSON format
     * @throws Exception if JWK generation fails
     */
    public String generateJWK(String keyUse, boolean publicOnly) throws Exception {
        PrivateKey privateKey = loadPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key not available. Cannot generate JWK without private key.");
        }

        try {
            if (privateKey instanceof ECPrivateKey) {
                return generateECJWK((ECPrivateKey) privateKey, keyUse, publicOnly);
            } else if (privateKey instanceof RSAPrivateKey) {
                return generateRSAJWK((RSAPrivateKey) privateKey, keyUse, publicOnly);
            } else {
                throw new UnsupportedOperationException(
                        "Unsupported key type: " + privateKey.getClass().getSimpleName());
            }
        } catch (Exception e) {
            logger.error("Failed to generate JWK", e);
            throw new IllegalStateException("Failed to generate JWK", e);
        }
    }

    /**
     * Generates an EC JWK from an EC private key.
     * 
     * @param privateKey The EC private key
     * @param keyUse     The intended use of the key
     * @param publicOnly Whether to include only the public key
     * @return The EC JWK in JSON format
     * @throws Exception if JWK generation fails
     */
    private String generateECJWK(ECPrivateKey privateKey, String keyUse, boolean publicOnly) throws Exception {
        // This would use similar logic to JWKGenerator.convertECKeyToJWK
        // For now, we'll use a simplified approach
        throw new UnsupportedOperationException(
                "EC JWK generation not yet implemented in JwtUtil. Use JWKGenerator utility instead.");
    }

    /**
     * Generates an RSA JWK from an RSA private key.
     * 
     * @param privateKey The RSA private key
     * @param keyUse     The intended use of the key
     * @param publicOnly Whether to include only the public key
     * @return The RSA JWK in JSON format
     * @throws Exception if JWK generation fails
     */
    private String generateRSAJWK(RSAPrivateKey privateKey, String keyUse, boolean publicOnly) throws Exception {
        // This would use similar logic to JWKGenerator.convertRSAKeyToJWK
        // For now, we'll use a simplified approach
        throw new UnsupportedOperationException(
                "RSA JWK generation not yet implemented in JwtUtil. Use JWKGenerator utility instead.");
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

}