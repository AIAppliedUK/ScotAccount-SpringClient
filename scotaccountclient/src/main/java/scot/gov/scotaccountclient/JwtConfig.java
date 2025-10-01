package scot.gov.scotaccountclient;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.StreamUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Configuration class for JWT-related beans and settings.
 * Provides beans for JWT decoding and validation using both Elliptic Curve and
 * RSA keys.
 * Automatically detects the key type and creates the appropriate decoder.
 */
@Configuration
public class JwtConfig {

    /** Path to the public key file used for JWT validation. */
    @Value("${scotaccount.public-key-path:keys/public.pem}")
    private String publicKeyPath;

    /**
     * Default constructor for JwtConfig.
     * 
     * <p>
     * This constructor is used by Spring's dependency injection to create
     * the JWT configuration bean.
     * </p>
     */
    public JwtConfig() {
        // Default constructor required by Spring
    }

    /**
     * Creates a PublicKey bean by loading the public key from the classpath.
     * Automatically detects whether the key is EC or RSA based on the key format.
     *
     * @return The public key for JWT validation (either EC or RSA)
     * @throws Exception if the key cannot be loaded or parsed
     */
    @Bean
    public PublicKey publicKey() throws Exception {
        ClassPathResource resource = new ClassPathResource(publicKeyPath);
        String key = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        // Detect key type based on the first few bytes
        String keyType = detectKeyType(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance(keyType);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Creates a JwtDecoder bean configured with the appropriate public key.
     * Automatically handles both EC and RSA keys using a custom decoder.
     *
     * @param publicKey The public key for JWT validation
     * @return A configured JwtDecoder instance
     */
    @Bean
    public JwtDecoder jwtDecoder(PublicKey publicKey) {
        return new CustomJwtDecoder(publicKey);
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
     * Custom JWT decoder that supports both EC and RSA keys.
     * This implementation uses the Nimbus JOSE library to handle both key types.
     */
    private static class CustomJwtDecoder implements JwtDecoder {
        private final JWSVerifier verifier;

        public CustomJwtDecoder(PublicKey publicKey) {
            this.verifier = createVerifier(publicKey);
        }

        @Override
        public Jwt decode(String token) throws JwtException {
            try {
                SignedJWT signedJWT = SignedJWT.parse(token);

                // Verify the signature
                if (!signedJWT.verify(verifier)) {
                    throw new JwtException("Invalid JWT signature");
                }

                // Get the claims
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                // Convert to Spring Security Jwt
                return Jwt.withTokenValue(token)
                        .header("alg", signedJWT.getHeader().getAlgorithm().getName())
                        .header("typ", "JWT")
                        .subject(claimsSet.getSubject())
                        .issuer(claimsSet.getIssuer())
                        .issuedAt(claimsSet.getIssueTime().toInstant())
                        .expiresAt(claimsSet.getExpirationTime().toInstant())
                        .claim("scope", claimsSet.getStringClaim("scope"))
                        .build();

            } catch (Exception e) {
                throw new JwtException("Failed to decode JWT", e);
            }
        }

        /**
         * Creates the appropriate JWS verifier based on the key type.
         *
         * @param publicKey The public key
         * @return The appropriate JWS verifier
         */
        private JWSVerifier createVerifier(PublicKey publicKey) {
            try {
                if (publicKey instanceof RSAPublicKey) {
                    return new RSASSAVerifier((RSAPublicKey) publicKey);
                } else if (publicKey instanceof ECPublicKey) {
                    return new ECDSAVerifier((ECPublicKey) publicKey);
                } else {
                    throw new IllegalArgumentException("Unsupported key type: " + publicKey.getClass().getSimpleName());
                }
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to create JWS verifier", e);
            }
        }
    }
}