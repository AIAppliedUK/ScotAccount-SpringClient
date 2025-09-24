package scot.gov.scotaccountclient;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the JWKGenerator command line utility.
 * 
 * Tests cover:
 * - Command line argument parsing for file conversion
 * - Error handling for invalid arguments and files
 * - Usage display functionality
 * 
 * @author ScotAccount Team
 * @version 1.0
 */
class JWKGeneratorTest {

    private JWKGenerator generator;
    private ByteArrayOutputStream outputStream;
    private ByteArrayOutputStream errorStream;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        generator = new JWKGenerator();
        outputStream = new ByteArrayOutputStream();
        errorStream = new ByteArrayOutputStream();
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(outputStream));
        System.setErr(new PrintStream(errorStream));
    }

    @AfterEach
    void tearDown() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    @DisplayName("Should show usage when no arguments provided")
    void shouldShowUsageWhenNoArgumentsProvided() {
        // Act
        JWKGenerator.main(new String[] {});

        // Assert
        String output = outputStream.toString();
        assertTrue(output.contains("JWK Converter - Convert private key files to JSON Web Keys (JWK) format"));
        assertTrue(output.contains("Usage:"));
        assertTrue(output.contains("--file <FILE>"));
    }

    @Test
    @DisplayName("Should show usage when help flag is provided")
    void shouldShowUsageWhenHelpFlagIsProvided() {
        // Act
        JWKGenerator.main(new String[] { "--help" });

        // Assert
        String output = outputStream.toString();
        assertTrue(output.contains("JWK Converter - Convert private key files to JSON Web Keys (JWK) format"));
        assertTrue(output.contains("Usage:"));
    }

    @Test
    @DisplayName("Should handle invalid arguments gracefully")
    void shouldHandleInvalidArgumentsGracefully() throws Exception {
        // Act & Assert
        Method parseMethod = JWKGenerator.class.getDeclaredMethod("parseArgumentsAndConvert", String[].class);
        parseMethod.setAccessible(true);

        Exception exception = assertThrows(Exception.class, () -> {
            parseMethod.invoke(generator, (Object) new String[] { "--invalid", "argument" });
        });

        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    @DisplayName("Should handle missing file argument")
    void shouldHandleMissingFileArgument() throws Exception {
        // Act & Assert
        Method parseMethod = JWKGenerator.class.getDeclaredMethod("parseArgumentsAndConvert", String[].class);
        parseMethod.setAccessible(true);

        Exception exception = assertThrows(Exception.class, () -> {
            parseMethod.invoke(generator, (Object) new String[] { "--use", "sig" });
        });

        assertTrue(exception.getCause() instanceof IllegalArgumentException);
        assertTrue(exception.getCause().getMessage().contains("--file is required"));
    }

    @Test
    @DisplayName("Should handle non-existent file")
    void shouldHandleNonExistentFile() throws Exception {
        // Act & Assert
        Method parseMethod = JWKGenerator.class.getDeclaredMethod("parseArgumentsAndConvert", String[].class);
        parseMethod.setAccessible(true);

        Exception exception = assertThrows(Exception.class, () -> {
            parseMethod.invoke(generator, (Object) new String[] { "--file", "non-existent-file.pem" });
        });

        assertTrue(exception.getCause() instanceof IllegalArgumentException);
        assertTrue(exception.getCause().getMessage().contains("Key file does not exist"));
    }
}
