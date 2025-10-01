package scot.gov.scotaccountclient;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

/**
 * Command line utility for converting private key files to JSON Web Keys (JWK)
 * format.
 * 
 * <p>
 * This utility reads existing RSA or Elliptic Curve private key files (PEM
 * format)
 * and converts them to JWK format with proper metadata including key ID, usage,
 * and
 * issue time, following the exact patterns described in the Nimbus JOSE+JWT
 * documentation.
 * </p>
 * 
 * <p>
 * Usage:
 * <ul>
 * <li>java JWKGenerator --file private-key.pem --use sig</li>
 * <li>java JWKGenerator --file ec-private-key.pem --use enc</li>
 * <li>java JWKGenerator --file rsa-private-key.pem --use sig --public-only</li>
 * </ul>
 * </p>
 * 
 * @author ScotAccount Team
 * @version 2.0
 */
public class JWKGenerator {

    /**
     * Main method for the JWK converter command line utility.
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        try {
            JWKGenerator generator = new JWKGenerator();
            generator.parseArgumentsAndConvert(args);
        } catch (Exception e) {
            System.err.println("Error converting key to JWK: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Parses command line arguments and performs the key conversion.
     * 
     * @param args Command line arguments
     * @throws Exception if parsing or conversion fails
     */
    private void parseArgumentsAndConvert(String[] args) throws Exception {
        String keyFile = null;
        String keyUse = "sig"; // Default to signature use
        boolean publicOnly = false;

        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--file":
                case "-f":
                    if (i + 1 < args.length) {
                        keyFile = args[++i];
                    } else {
                        throw new IllegalArgumentException("--file requires a file path");
                    }
                    break;
                case "--use":
                case "-u":
                    if (i + 1 < args.length) {
                        keyUse = args[++i];
                    } else {
                        throw new IllegalArgumentException("--use requires a value (sig or enc)");
                    }
                    break;
                case "--public-only":
                case "-p":
                    publicOnly = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown argument: " + args[i]);
            }
        }

        if (keyFile == null) {
            throw new IllegalArgumentException("Key file is required. Use --file <path>");
        }

        if (!keyUse.equals("sig") && !keyUse.equals("enc")) {
            throw new IllegalArgumentException("Key use must be 'sig' or 'enc'");
        }

        // Load and convert the private key
        convertPrivateKeyToJWK(keyFile, keyUse, publicOnly);
    }

    /**
     * Loads a private key from a file and converts it to JWK format.
     * 
     * @param keyFile    Path to the private key file
     * @param keyUse     The intended use of the key ("sig" for signature, "enc" for
     *                   encryption)
     * @param publicOnly Whether to output only the public key
     * @throws Exception if key loading or conversion fails
     */
    private void convertPrivateKeyToJWK(String keyFile, String keyUse, boolean publicOnly) throws Exception {
        PrivateKey privateKey = loadPrivateKeyFromFile(keyFile);

        if (privateKey instanceof RSAPrivateKey) {
            convertRSAKeyToJWK((RSAPrivateKey) privateKey, keyUse, publicOnly);
        } else if (privateKey instanceof ECPrivateKey) {
            convertECKeyToJWK((ECPrivateKey) privateKey, keyUse, publicOnly);
        } else {
            throw new UnsupportedOperationException("Unsupported key type: " + privateKey.getClass().getSimpleName());
        }
    }

    /**
     * Loads a private key from a PEM file.
     * Supports both PKCS#8 format and traditional EC/RSA formats.
     * 
     * @param keyFile Path to the private key file
     * @return The loaded private key
     * @throws Exception if the key cannot be loaded
     */
    private PrivateKey loadPrivateKeyFromFile(String keyFile) throws Exception {
        File file = new File(keyFile);
        if (!file.exists()) {
            throw new IllegalArgumentException("Key file does not exist: " + keyFile);
        }

        String keyContent = new String(Files.readAllBytes(Paths.get(keyFile)));

        // Check the key format by looking at the PEM headers
        boolean isTraditionalEC = keyContent.contains("-----BEGIN EC PRIVATE KEY-----");
        boolean isPKCS8 = keyContent.contains("-----BEGIN PRIVATE KEY-----");
        boolean isTraditionalRSA = keyContent.contains("-----BEGIN RSA PRIVATE KEY-----");

        try {
            if (isTraditionalEC) {
                // Handle traditional EC format
                return loadTraditionalECKey(keyContent);
            } else if (isTraditionalRSA) {
                // Handle traditional RSA format
                return loadTraditionalRSAKey(keyContent);
            } else if (isPKCS8) {
                // Handle PKCS#8 format (both RSA and EC)
                return loadPKCS8Key(keyContent);
            } else {
                throw new IllegalArgumentException(
                        "Unrecognized key format. Expected PKCS#8, traditional EC, or traditional RSA format.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to parse private key file. Please ensure it's a valid PEM-encoded private key file.",
                    e);
        }
    }

    /**
     * Loads a traditional EC private key from PEM content.
     * 
     * @param keyContent The full PEM file content
     * @return The loaded EC private key
     * @throws Exception if the key cannot be loaded
     */
    private PrivateKey loadTraditionalECKey(String keyContent) throws Exception {
        // Extract only the EC PRIVATE KEY section (ignore EC PARAMETERS)
        byte[] keyBytes = extractKeySection(keyContent, "-----BEGIN EC PRIVATE KEY-----",
                "-----END EC PRIVATE KEY-----");

        // Parse the traditional EC private key using BouncyCastle
        org.bouncycastle.asn1.sec.ECPrivateKey ecPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey
                .getInstance(keyBytes);

        // Get the private key value
        java.math.BigInteger privateKeyValue = ecPrivateKey.getKey();

        // For traditional EC keys, we need to determine the curve parameters
        // We'll use P-256 as the default since that's what the standard OpenSSL command
        // generates
        java.security.spec.ECParameterSpec ecParams = getP256Parameters();

        // Create the private key spec
        java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(privateKeyValue,
                ecParams);

        // Generate the private key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads a traditional RSA private key from PEM content.
     * 
     * @param keyContent The full PEM file content
     * @return The loaded RSA private key
     * @throws Exception if the key cannot be loaded
     */
    private PrivateKey loadTraditionalRSAKey(String keyContent) throws Exception {
        // Extract the RSA PRIVATE KEY section
        byte[] keyBytes = extractKeySection(keyContent, "-----BEGIN RSA PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----");

        // Parse the traditional RSA private key using BouncyCastle
        org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey
                .getInstance(keyBytes);

        // Convert to Java format
        java.security.spec.RSAPrivateKeySpec keySpec = new java.security.spec.RSAPrivateKeySpec(
                rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads a PKCS#8 private key from PEM content.
     * 
     * @param keyContent The full PEM file content
     * @return The loaded private key
     * @throws Exception if the key cannot be loaded
     */
    private PrivateKey loadPKCS8Key(String keyContent) throws Exception {
        // Extract the PRIVATE KEY section
        byte[] keyBytes = extractKeySection(keyContent, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Try RSA first
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            // Try EC if RSA fails
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(keySpec);
        }
    }

    /**
     * Extracts a specific key section from a PEM file.
     * 
     * @param keyContent  The full PEM file content
     * @param beginMarker The BEGIN marker for the section
     * @param endMarker   The END marker for the section
     * @return The decoded key bytes
     * @throws Exception if the section cannot be extracted or decoded
     */
    private byte[] extractKeySection(String keyContent, String beginMarker, String endMarker) throws Exception {
        int beginIndex = keyContent.indexOf(beginMarker);
        int endIndex = keyContent.indexOf(endMarker);

        if (beginIndex == -1 || endIndex == -1) {
            throw new IllegalArgumentException(
                    "Could not find key section markers: " + beginMarker + " / " + endMarker);
        }

        // Extract the content between the markers
        String sectionContent = keyContent.substring(beginIndex + beginMarker.length(), endIndex);

        // Remove whitespace and decode Base64
        sectionContent = sectionContent.replaceAll("\\s", "");
        return Base64.getDecoder().decode(sectionContent);
    }

    /**
     * Gets the P-256 curve parameters.
     * 
     * @return The P-256 EC parameter specification
     */
    private java.security.spec.ECParameterSpec getP256Parameters() {
        // Use BouncyCastle to get P-256 parameters
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        // Convert to Java format
        java.security.spec.ECPoint generator = new java.security.spec.ECPoint(
                bcSpec.getG().getAffineXCoord().toBigInteger(),
                bcSpec.getG().getAffineYCoord().toBigInteger());

        return new java.security.spec.ECParameterSpec(
                new java.security.spec.EllipticCurve(
                        new java.security.spec.ECFieldFp(bcSpec.getCurve().getField().getCharacteristic()),
                        bcSpec.getCurve().getA().toBigInteger(),
                        bcSpec.getCurve().getB().toBigInteger()),
                generator,
                bcSpec.getN(),
                bcSpec.getH().intValue());
    }

    /**
     * Converts an RSA private key to JWK format.
     * 
     * @param privateKey The RSA private key
     * @param keyUse     The intended use of the key ("sig" for signature, "enc" for
     *                   encryption)
     * @param publicOnly Whether to output only the public key
     * @throws Exception if key conversion fails
     */
    private void convertRSAKeyToJWK(RSAPrivateKey privateKey, String keyUse, boolean publicOnly) throws Exception {
        // Extract the public key from the private key
        java.security.interfaces.RSAPublicKey publicKey = (java.security.interfaces.RSAPublicKey) java.security.KeyFactory
                .getInstance("RSA").generatePublic(
                        new java.security.spec.RSAPublicKeySpec(
                                privateKey.getModulus(),
                                privateKey.getPrivateExponent()));

        RSAKey jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.parse(keyUse)) // indicate the intended use of the key (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .build();

        // Generate kid using JWK thumbprint (RFC 7638) - same method as JwtUtil
        String kid = jwk.computeThumbprint().toString();

        // Rebuild with the computed kid
        jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.parse(keyUse))
                .keyID(kid)
                .issueTime(new Date())
                .build();

        // Output the private and public RSA JWK parameters
        if (publicOnly) {
            System.out.println("Public RSA JWK:");
            System.out.println(jwk.toPublicJWK());
        } else {
            System.out.println("RSA JWK (Private and Public):");
            System.out.println(jwk);
            System.out.println("\nPublic RSA JWK only:");
            System.out.println(jwk.toPublicJWK());
        }
    }

    /**
     * Converts an EC private key to JWK format.
     * 
     * @param privateKey The EC private key
     * @param keyUse     The intended use of the key ("sig" for signature, "enc" for
     *                   encryption)
     * @param publicOnly Whether to output only the public key
     * @throws Exception if key conversion fails
     */
    private void convertECKeyToJWK(ECPrivateKey privateKey, String keyUse, boolean publicOnly) throws Exception {
        // Get the curve from the private key parameters
        Curve curve = Curve.forECParameterSpec(privateKey.getParams());

        // For EC keys, we need to derive the public key coordinates from the private
        // key
        // The public key is calculated as: publicKey = privateKey * generatorPoint
        java.security.interfaces.ECPublicKey publicKey = derivePublicKeyFromPrivate(privateKey);

        // Get the public key coordinates
        Base64URL publicKeyX = Base64URL.encode(publicKey.getW().getAffineX().toByteArray());
        Base64URL publicKeyY = Base64URL.encode(publicKey.getW().getAffineY().toByteArray());

        // Convert EC private key to JWK format with proper public key coordinates
        ECKey jwk = new ECKey.Builder(curve, publicKeyX, publicKeyY)
                .privateKey(privateKey)
                .keyUse(KeyUse.parse(keyUse)) // indicate the intended use of the key (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .build();

        // Generate kid using JWK thumbprint (RFC 7638) - same method as JwtUtil
        String kid = jwk.computeThumbprint().toString();

        // Rebuild with the computed kid
        jwk = new ECKey.Builder(curve, publicKeyX, publicKeyY)
                .privateKey(privateKey)
                .keyUse(KeyUse.parse(keyUse))
                .keyID(kid)
                .issueTime(new Date())
                .build();

        // Output the private and public EC JWK parameters
        if (publicOnly) {
            System.out.println("Public EC JWK:");
            System.out.println(jwk.toPublicJWK());
        } else {
            System.out.println("EC JWK (Private and Public):");
            System.out.println(jwk);
            System.out.println("\nPublic EC JWK only:");
            System.out.println(jwk.toPublicJWK());
        }
    }

    /**
     * Derives the public key from an EC private key using BouncyCastle for proper
     * elliptic curve point multiplication.
     * 
     * @param privateKey The EC private key
     * @return The corresponding EC public key
     * @throws Exception if public key derivation fails
     */
    private java.security.interfaces.ECPublicKey derivePublicKeyFromPrivate(ECPrivateKey privateKey) throws Exception {
        // Get the curve parameters
        java.security.spec.ECParameterSpec params = privateKey.getParams();
        java.math.BigInteger privateKeyS = privateKey.getS();

        // Map Java EC parameters to BouncyCastle curve name
        String curveName = getBouncyCastleCurveName(params);
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(curveName);

        // Get the generator point from BouncyCastle
        ECPoint generator = bcSpec.getG();

        // Perform elliptic curve point multiplication: publicKey = privateKey *
        // generator
        ECPoint publicKeyPoint = generator.multiply(privateKeyS);

        // Normalize the point to get affine coordinates
        publicKeyPoint = publicKeyPoint.normalize();

        // Convert BouncyCastle ECPoint to Java ECPoint
        java.security.spec.ECPoint javaPublicKeyPoint = new java.security.spec.ECPoint(
                publicKeyPoint.getAffineXCoord().toBigInteger(),
                publicKeyPoint.getAffineYCoord().toBigInteger());

        // Create the public key spec
        java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(javaPublicKeyPoint,
                params);

        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (java.security.interfaces.ECPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Maps Java EC parameters to BouncyCastle curve names.
     * 
     * @param params The Java EC parameters
     * @return The corresponding BouncyCastle curve name
     * @throws Exception if the curve is not supported
     */
    private String getBouncyCastleCurveName(java.security.spec.ECParameterSpec params) throws Exception {
        // Get the curve order to identify the curve
        java.math.BigInteger order = params.getOrder();

        // Map common curves by their order
        if (order.equals(new java.math.BigInteger(
                "115792089210356248762697446949407573529996955224135760342422259061068512044369"))) {
            return "secp256r1"; // P-256
        } else if (order.equals(new java.math.BigInteger(
                "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"))) {
            return "secp384r1"; // P-384
        } else if (order.equals(new java.math.BigInteger(
                "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"))) {
            return "secp521r1"; // P-521
        } else {
            throw new UnsupportedOperationException("Unsupported curve with order: " + order);
        }
    }

    /**
     * Prints usage information for the JWK converter utility.
     */
    private static void printUsage() {
        System.out.println("JWK Converter - Convert private key files to JSON Web Keys (JWK) format");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java JWKGenerator --file <KEY_FILE> [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --file, -f <FILE>     Path to the private key file (PEM format)");
        System.out
                .println("  --use, -u <USE>       Key usage: 'sig' for signature, 'enc' for encryption (default: sig)");
        System.out.println("  --public-only, -p     Output only the public key part");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java JWKGenerator --file private-key.pem --use sig");
        System.out.println("  java JWKGenerator --file ec-private-key.pem --use enc");
        System.out.println("  java JWKGenerator --file rsa-private-key.pem --use sig --public-only");
        System.out.println();
        System.out.println("Supported key types and formats:");
        System.out.println("  - RSA private keys (PKCS#8 or traditional RSA format)");
        System.out.println("  - Elliptic Curve private keys (PKCS#8 or traditional EC format)");
        System.out.println();
        System.out.println("Key format detection:");
        System.out.println("  - PKCS#8: -----BEGIN PRIVATE KEY----- (works for both RSA and EC)");
        System.out.println("  - Traditional RSA: -----BEGIN RSA PRIVATE KEY-----");
        System.out.println("  - Traditional EC: -----BEGIN EC PRIVATE KEY-----");
        System.out.println();
        System.out.println("Examples of supported OpenSSL commands:");
        System.out.println("  # Traditional EC key (automatically detected):");
        System.out.println("  openssl ecparam -genkey -name prime256v1 -out ec-private.pem");
        System.out.println("  # PKCS#8 EC key:");
        System.out.println("  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-private.pem");
        System.out.println("  # Traditional RSA key:");
        System.out.println("  openssl genrsa -out rsa-private.pem 2048");
    }
}