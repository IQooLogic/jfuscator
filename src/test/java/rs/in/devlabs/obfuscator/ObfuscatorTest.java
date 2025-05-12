package rs.in.devlabs.obfuscator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscatorTest {

    @Test
    void testBasicObfuscationCycle() throws ObfuscatorException {
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);
        Obfuscator obfuscator = new Obfuscator(passphrase);

        String originalText = "Hello, World!";
        String obfuscated = obfuscator.obfuscate(originalText);

        assertNotEquals(originalText, obfuscated, "Obfuscated text should be different from original");

        String unobfuscated = obfuscator.unobfuscate(obfuscated);
        assertEquals(originalText, unobfuscated, "Unobfuscated text should match original");
    }

    @ParameterizedTest
    @MethodSource("provideVariousInputs")
    void testVariousInputs(String input) throws ObfuscatorException {
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);
        Obfuscator obfuscator = new Obfuscator(passphrase);

        String obfuscated = obfuscator.obfuscate(input);
        String unobfuscated = obfuscator.unobfuscate(obfuscated);

        assertEquals(input, unobfuscated, "Unobfuscated text should match original input");
    }

    private static Stream<Arguments> provideVariousInputs() {
        return Stream.of(
                Arguments.of(""),
                Arguments.of("Simple text"),
                Arguments.of("Special chars: !@#$%^&*()"),
                Arguments.of("Unicode: 你好，世界！"),
                Arguments.of("Very long text that is more than just a few words and contains multiple sentences. " +
                        "It also has some numbers 12345 and special characters !@#$%.")
        );
    }

    @Test
    void testRandomization() throws ObfuscatorException {
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);
        Obfuscator obfuscator = new Obfuscator(passphrase);
        String input = "Same input text";

        String first = obfuscator.obfuscate(input);
        String second = obfuscator.obfuscate(input);

        assertNotEquals(first, second, "Expected different obfuscated outputs for same input");
    }

    @Test
    void testCustomSaltLength() throws ObfuscatorException {
        int customSaltLength = 16;
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);

        ObfuscatorConfig config = ObfuscatorConfig.builder(passphrase)
                .withSaltLength(customSaltLength)
                .build();

        Obfuscator obfuscator = new Obfuscator(passphrase, config);

        String obfuscated = obfuscator.obfuscate("Test text");
        String[] parts = obfuscated.split(Obfuscator.DEFAULT_SEPARATOR);

        // Check if we have all parts (might include an empty first part)
        assertTrue(parts.length >= 4, "Expected at least 4 parts in obfuscated string");

        // Determine the starting index (might be 0 or 1 depending on if there's an empty part)
        int startIndex = parts[0].isEmpty() ? 1 : 0;

        byte[] saltBytes = Base64.getDecoder().decode(parts[startIndex + 1]);
        assertEquals(customSaltLength, saltBytes.length, "Expected custom salt length");
    }

    @Test
    void testCustomSeparator() throws ObfuscatorException {
        String customSeparator = "#";
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);

        ObfuscatorConfig config = ObfuscatorConfig.builder(passphrase)
                .withSeparator(customSeparator)
                .build();

        Obfuscator obfuscator = new Obfuscator(passphrase, config);

        String input = "Test text";
        String obfuscated = obfuscator.obfuscate(input);

        assertTrue(obfuscated.startsWith(customSeparator), "Expected obfuscated text to start with separator");
        assertEquals(4, obfuscated.chars().filter(ch -> ch == customSeparator.charAt(0)).count(),
                "Expected 4 separators");

        String unobfuscated = obfuscator.unobfuscate(obfuscated);
        assertEquals(input, unobfuscated, "Expected unobfuscated text to match input");
    }

    @Test
    void testWrongPassphrase() throws ObfuscatorException {
        byte[] correctPassphrase = "correctPassphrase".getBytes(StandardCharsets.UTF_8);
        byte[] wrongPassphrase = "wrongPassphrase".getBytes(StandardCharsets.UTF_8);

        Obfuscator originalObfuscator = new Obfuscator(correctPassphrase);
        Obfuscator wrongObfuscator = new Obfuscator(wrongPassphrase);

        String input = "Secret message";
        String obfuscated = originalObfuscator.obfuscate(input);

        assertThrows(ObfuscatorException.class, () -> wrongObfuscator.unobfuscate(obfuscated),
                "Expected error when using wrong passphrase");
    }

    @ParameterizedTest
    @MethodSource("provideInvalidObfuscatedText")
    void testInvalidObfuscatedText(String invalidInput) {
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);
        Obfuscator obfuscator = new Obfuscator(passphrase);

        assertThrows(ObfuscatorException.class, () -> obfuscator.unobfuscate(invalidInput),
                "Expected error for invalid input");
    }

    private static Stream<Arguments> provideInvalidObfuscatedText() {
        return Stream.of(
                Arguments.of("invalid$format$string"),
                Arguments.of("$invalid$format"),
                Arguments.of("$o1$not$enough"),
                Arguments.of(""),
                Arguments.of("$o1$not-valid-base64$validiv$validcipher"),
                Arguments.of("$o1$" + Base64.getEncoder().encodeToString("salt".getBytes()) +
                        "$not-valid-base64$validcipher"),
                Arguments.of("$o1$" + Base64.getEncoder().encodeToString("salt".getBytes()) + "$" +
                        Base64.getEncoder().encodeToString("iv".getBytes()) + "$not-valid-base64")
        );
    }

    @Test
    void testUnsupportedVersion() {
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);
        Obfuscator obfuscator = new Obfuscator(passphrase);
        String invalidVersionText = "$o2$salt$iv$ciphertext";

        ObfuscatorException exception = assertThrows(ObfuscatorException.class,
                () -> obfuscator.unobfuscate(invalidVersionText),
                "Expected UnsupportedVersion error");

        assertTrue(exception.getMessage().contains("Unsupported obfuscator version"),
                "Expected proper error message");
    }

    @Test
    void testMultipleOptions() throws ObfuscatorException {
        int customSaltLength = 16;
        String customSeparator = "#";
        byte[] passphrase = "testPassphrase123".getBytes(StandardCharsets.UTF_8);

        ObfuscatorConfig config = ObfuscatorConfig.builder(passphrase)
                .withSaltLength(customSaltLength)
                .withSeparator(customSeparator)
                .build();

        Obfuscator obfuscator = new Obfuscator(passphrase, config);

        String input = "Test with multiple options";
        String obfuscated = obfuscator.obfuscate(input);

        assertTrue(obfuscated.contains(customSeparator), "Expected custom separator in output");

        String[] parts = obfuscated.split(customSeparator);
        int startIndex = parts.length > 0 && parts[0].isEmpty() ? 1 : 0;

        byte[] saltBytes = Base64.getDecoder().decode(parts[startIndex + 1]);
        assertEquals(customSaltLength, saltBytes.length, "Expected custom salt length");

        String unobfuscated = obfuscator.unobfuscate(obfuscated);
        assertEquals(input, unobfuscated, "Expected unobfuscated text to match input");
    }

    @Test
    void testNilPassphrase() {
        assertThrows(IllegalArgumentException.class, () -> new Obfuscator(null),
                "Expected exception with null passphrase");
    }

    @Test
    void testZeroSaltLength() {
        byte[] passphrase = "test".getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalArgumentException.class,
                () -> ObfuscatorConfig.builder(passphrase).withSaltLength(0).build(),
                "Expected exception with zero salt length");
    }
}
