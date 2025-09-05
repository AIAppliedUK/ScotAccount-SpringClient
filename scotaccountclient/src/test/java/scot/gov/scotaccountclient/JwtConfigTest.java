package scot.gov.scotaccountclient;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

/**
 * Unit tests for JwtConfig class.
 * Tests key detection and loading functionality for both EC and RSA keys.
 */
class JwtConfigTest {

    private JwtConfig jwtConfig;

    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
    }

    /**
     * Test that the public key can be loaded and is detected as an EC key.
     */
    @Test
    void testLoadPublicKeyAsEC() throws Exception {
        // Load the public key from the filesystem to get the actual EC key
        String keyPath = "src/main/resources/keys/public.pem";
        String keyContent = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(keyPath)),
                StandardCharsets.UTF_8);

        String key = keyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        // Test key type detection
        String keyType = detectKeyType(decoded);
        assertEquals("EC", keyType, "Key should be detected as EC");

        // Test key loading
        KeyFactory keyFactory = KeyFactory.getInstance(keyType);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        assertTrue(publicKey instanceof ECPublicKey, "Public key should be an ECPublicKey");

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        assertEquals("EC", ecPublicKey.getAlgorithm(), "Algorithm should be EC");
        assertNotNull(ecPublicKey.getParams(), "EC parameters should not be null");
        assertNotNull(ecPublicKey.getParams().getCurve(), "EC curve should not be null");
    }

    /**
     * Test that a JWT decoder can be created with the public key.
     */
    @Test
    void testCreateJwtDecoder() throws Exception {
        // Load the public key from the filesystem to get the actual EC key
        String keyPath = "src/main/resources/keys/public.pem";
        String keyContent = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(keyPath)),
                StandardCharsets.UTF_8);

        String key = keyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        String keyType = detectKeyType(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(keyType);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Test that a JWT decoder can be created
        assertDoesNotThrow(() -> {
            jwtConfig.jwtDecoder(publicKey);
        }, "JWT decoder should be created without exception");
    }

    /**
     * Test key type detection with known EC key pattern.
     */
    @Test
    void testDetectKeyTypeEC() {
        // This is a sample EC key header pattern (id-ecPublicKey: 1.2.840.10045.2.1)
        byte[] ecKeyPattern = {
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
                0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        };

        String keyType = detectKeyType(ecKeyPattern);
        assertEquals("EC", keyType, "EC key pattern should be detected as EC");
    }

    /**
     * Test key type detection with known RSA key pattern.
     */
    @Test
    void testDetectKeyTypeRSA() {
        // This is a sample RSA key header pattern (rsaEncryption: 1.2.840.113549.1.1.1)
        byte[] rsaKeyPattern = {
                0x30, (byte) 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86,
                (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00
        };

        String keyType = detectKeyType(rsaKeyPattern);
        assertEquals("RSA", keyType, "RSA key pattern should be detected as RSA");
    }

    /**
     * Test key detection with the actual EC key from filesystem.
     */
    @Test
    void testDetectKeyTypeWithActualECKey() throws Exception {
        // Read the EC key directly from the filesystem
        String keyPath = "src/main/resources/keys/public.pem";
        String keyContent = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(keyPath)),
                StandardCharsets.UTF_8);

        String key = keyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        System.out.println("EC Key content: " + key);

        byte[] decoded = Base64.getDecoder().decode(key);

        System.out.println("EC Key length: " + decoded.length);
        System.out.print("EC Key first 20 bytes: ");
        for (int i = 0; i < Math.min(20, decoded.length); i++) {
            System.out.printf("0x%02X ", decoded[i]);
        }
        System.out.println();

        String keyType = detectKeyType(decoded);
        assertEquals("EC", keyType, "Actual EC key should be detected as EC");

        // Verify it can be loaded as an EC key
        KeyFactory keyFactory = KeyFactory.getInstance(keyType);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        assertTrue(publicKey instanceof ECPublicKey, "Public key should be an ECPublicKey");
    }

    /**
     * Debug test to print the actual key bytes for analysis.
     */
    @Test
    void testDebugKeyBytes() throws Exception {
        // Load the public key from the main resources using absolute path
        ClassPathResource resource = new ClassPathResource("keys/public.pem");
        String key = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        System.out.println("Raw key content: " + key);

        byte[] decoded = Base64.getDecoder().decode(key);

        System.out.println("Key length: " + decoded.length);
        System.out.print("First 20 bytes: ");
        for (int i = 0; i < Math.min(20, decoded.length); i++) {
            System.out.printf("0x%02X ", decoded[i]);
        }
        System.out.println();

        // Print the specific bytes we're checking
        if (decoded.length > 10) {
            System.out.println("Byte 0: 0x" + String.format("%02X", decoded[0]));
            System.out.println("Byte 2: 0x" + String.format("%02X", decoded[2]));
            System.out.println("Byte 4: 0x" + String.format("%02X", decoded[4]));
            System.out.println("Byte 5: 0x" + String.format("%02X", decoded[5]));
            System.out.println("Byte 6: 0x" + String.format("%02X", decoded[6]));
            System.out.println("Byte 7: 0x" + String.format("%02X", decoded[7]));
            System.out.println("Byte 8: 0x" + String.format("%02X", decoded[8]));
            System.out.println("Byte 9: 0x" + String.format("%02X", decoded[9]));
            System.out.println("Byte 10: 0x" + String.format("%02X", decoded[10]));
        }

        String keyType = detectKeyType(decoded);
        System.out.println("Detected key type: " + keyType);
    }

    /**
     * Helper method to detect key type (copied from JwtConfig for testing).
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
}
