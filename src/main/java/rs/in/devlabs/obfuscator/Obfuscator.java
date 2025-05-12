package rs.in.devlabs.obfuscator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Obfuscator class enables encoding and decoding sensitive values such as passwords.
 * This can be used to store these values in configuration files.
 */
public class Obfuscator {
    /**
     * The default length for the cryptographic salt used in key derivation or obfuscation processes.
     * This value is set to 8 bytes, which is typically enough for ensuring
     * randomness and security in most cryptographic operations.
     */
    public static final int DEFAULT_SALT_LENGTH = 8;
    /**
     * The default separator used to delimit components in obfuscated strings.
     * This value is used to maintain consistency when splitting or joining
     * obfuscated elements within the application's functionality.
     */
    public static final String DEFAULT_SEPARATOR = "$";
    /**
     * Specifies the current version of the Obfuscator.
     * This constant can be used to identify the implementation version of the class,
     * providing information about its features or compatibility.
     */
    public static final String VERSION = "o1";

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 1000;

    private final ObfuscatorConfig config;

    /**
     * Creates a new Obfuscator with the given passphrase and default settings.
     *
     * @param passphrase The passphrase used for obfuscation
     * @throws IllegalArgumentException if the passphrase is null
     */
    public Obfuscator(byte[] passphrase) {
        if (passphrase == null) {
            throw new IllegalArgumentException("Passphrase must not be null");
        }
        this.config = new ObfuscatorConfig(passphrase);
    }

    /**
     * Creates a new Obfuscator with the given passphrase and configuration.
     *
     * @param passphrase The passphrase used for obfuscation
     * @param config The configuration for this obfuscator
     * @throws IllegalArgumentException if the passphrase is null
     */
    public Obfuscator(byte[] passphrase, ObfuscatorConfig config) {
        if (passphrase == null) {
            throw new IllegalArgumentException("Passphrase must not be null");
        }

        this.config = new ObfuscatorConfig(passphrase);

        if (config.getSaltLength() != null) {
            this.config.setSaltLength(config.getSaltLength());
        }

        if (config.getSeparator() != null) {
            this.config.setSeparator(config.getSeparator());
        }
    }

    /**
     * Obfuscates the given text.
     *
     * @param text The text to obfuscate
     * @return The obfuscated text
     * @throws ObfuscatorException if obfuscation fails
     */
    public String obfuscate(String text) throws ObfuscatorException {
        try {
            byte[] salt = generateRandomBytes(config.getSaltLength());
            byte[] iv = generateRandomBytes(GCM_IV_LENGTH);
            byte[] key = deriveKey(config.getPassphrase(), salt);

            byte[] cipherText = encrypt(text.getBytes(StandardCharsets.UTF_8), key, iv);

            String encodedSalt = Base64.getEncoder().encodeToString(salt);
            String encodedIv = Base64.getEncoder().encodeToString(iv);
            String encodedCipherText = Base64.getEncoder().encodeToString(cipherText);

            return String.format("%s%s%s%s%s%s%s%s",
                    config.getSeparator(), VERSION,
                    config.getSeparator(), encodedSalt,
                    config.getSeparator(), encodedIv,
                    config.getSeparator(), encodedCipherText);
        } catch (Exception e) {
            throw new ObfuscatorException("Failed to obfuscate text", e);
        }
    }

    /**
     * Unobfuscates the given text.
     *
     * @param obfuscatedText The text to unobfuscate
     * @return The unobfuscated text
     * @throws ObfuscatorException if unobfuscation fails
     */
    public String unobfuscate(String obfuscatedText) throws ObfuscatorException {
        String[] parts = obfuscatedText.split(Pattern.quote(config.getSeparator()));

        // The first split might create an empty first element
        int startIndex = parts.length > 0 && parts[0].isEmpty() ? 1 : 0;

        // Check if we have all the required parts
        if (parts.length - startIndex < 4) {
            throw new ObfuscatorException("Invalid obfuscated string");
        }

        String version = parts[startIndex];

        if (!VERSION.equals(version)) {
            throw new ObfuscatorException("Unsupported obfuscator version: " + version);
        }

        try {
            byte[] salt = Base64.getDecoder().decode(parts[startIndex + 1]);
            byte[] iv = Base64.getDecoder().decode(parts[startIndex + 2]);
            byte[] cipherText = Base64.getDecoder().decode(parts[startIndex + 3]);

            byte[] key = deriveKey(config.getPassphrase(), salt);
            byte[] plainText = decrypt(cipherText, key, iv);

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new ObfuscatorException("Invalid Base64 encoding in obfuscated string", e);
        } catch (Exception e) {
            throw new ObfuscatorException("Failed to unobfuscate text", e);
        }
    }

    /**
     * Encrypts the given plain text using AES/GCM/NoPadding.
     *
     * @param plainText The text to encrypt
     * @param key The encryption key
     * @param iv The initialization vector
     * @return The encrypted text
     * @throws Exception if encryption fails
     */
    private byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(plainText);
    }

    /**
     * Decrypts the given cipher text using AES/GCM/NoPadding.
     *
     * @param cipherText The text to decrypt
     * @param key The decryption key
     * @param iv The initialization vector
     * @return The decrypted text
     * @throws Exception if decryption fails
     */
    private byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(cipherText);
    }

    /**
     * Derives a cryptographic key from the passphrase and salt using PBKDF2WithHmacSHA256.
     *
     * @param passphrase The passphrase to derive the key from
     * @param salt The salt to use in key derivation
     * @return The derived key
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private byte[] deriveKey(byte[] passphrase, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
                new String(passphrase, StandardCharsets.UTF_8).toCharArray(),
                salt,
                ITERATION_COUNT,
                KEY_LENGTH
        );
        SecretKey secretKey = factory.generateSecret(spec);
        return secretKey.getEncoded();
    }

    /**
     * Generates a random byte array of the specified length.
     *
     * @param length The length of the byte array to generate
     * @return A random byte array
     */
    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
