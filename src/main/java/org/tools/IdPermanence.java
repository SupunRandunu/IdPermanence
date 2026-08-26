package org.tools;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

/**
 * ID Permanence Encryption/Decryption Tool.
 *
 * Generates permanent, unique, and reproducible encrypted IDs for Open Banking / CDR compliance.
 * Uses AES encryption to produce consistent masked IDs based on:
 *   - Software Product ID (identifies the data recipient)
 *   - Resource ID (e.g., account ID)
 *   - Customer ID (the consenting user)
 *
 * Input values are read from a properties file (config.properties).
 */
public class IdPermanence {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) {

        String propertiesFile = "src/main/resources/config.properties";
        if (args.length > 0) {
            propertiesFile = args[0];
        }

        Properties properties = loadProperties(propertiesFile);
        if (properties == null) {
            System.err.println("Failed to load properties file: " + propertiesFile);
            System.exit(1);
        }

        String operation = properties.getProperty("operation", "ENCRYPT").trim().toUpperCase();
        String secretKey = properties.getProperty("secretKey", "").trim();
        String softwareProductId = properties.getProperty("softwareProductId", "").trim();
        String resourceId = properties.getProperty("resourceId", "").trim();
        String customerId = properties.getProperty("customerId", "").trim();
        String separator = properties.getProperty("separator", ":").trim();

        if (secretKey.isEmpty()) {
            System.err.println("Error: 'secretKey' must be provided in the properties file.");
            System.exit(1);
        }

        System.out.println("============================================");
        System.out.println("       ID Permanence Tool");
        System.out.println("============================================");
        System.out.println("Operation       : " + operation);
        System.out.println("Secret Key      : " + secretKey);
        System.out.println("Software Product: " + softwareProductId);
        System.out.println("Resource ID     : " + resourceId);
        System.out.println("Customer ID     : " + customerId);
        System.out.println("Separator       : " + separator);
        System.out.println("--------------------------------------------");

        try {
            if ("ENCRYPT".equals(operation)) {
                // Build the plaintext: softwareProductId + separator + resourceId + separator + customerId
                String plainText = softwareProductId + separator + resourceId + separator + customerId;
                System.out.println("Plain Text      : " + plainText);

                String encrypted = encrypt(plainText, secretKey);
                System.out.println("Encrypted ID    : " + encrypted);

            } else if ("DECRYPT".equals(operation)) {
                // For decryption, the resourceId field holds the encrypted value
                String encryptedValue = resourceId;
                System.out.println("Encrypted Input : " + encryptedValue);

                String decrypted = decrypt(encryptedValue, secretKey);
                System.out.println("Decrypted Value : " + decrypted);

                // Parse the decrypted components
                String[] parts = decrypted.split(separator.equals(":") ? ":" : separator);
                if (parts.length >= 3) {
                    System.out.println("  -> Software Product ID : " + parts[0]);
                    System.out.println("  -> Resource ID         : " + parts[1]);
                    System.out.println("  -> Customer ID         : " + parts[2]);
                }
            } else {
                System.err.println("Error: Invalid operation '" + operation + "'. Use ENCRYPT or DECRYPT.");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error during " + operation + ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println("============================================");
    }

    /**
     * Encrypts the given plain text using AES with the provided secret key.
     *
     * @param plainText the text to encrypt
     * @param secretKey the secret key string
     * @return Base64-encoded encrypted string (URL-safe)
     */
    public static String encrypt(String plainText, String secretKey) throws Exception {
        SecretKeySpec keySpec = generateKey(secretKey);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given Base64-encoded encrypted text using AES with the provided secret key.
     *
     * @param encryptedText the Base64-encoded encrypted text
     * @param secretKey     the secret key string
     * @return the decrypted plain text
     */
    public static String decrypt(String encryptedText, String secretKey) throws Exception {
        SecretKeySpec keySpec = generateKey(secretKey);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Support both standard and URL-safe Base64
        byte[] decodedBytes;
        try {
            decodedBytes = Base64.getUrlDecoder().decode(encryptedText);
        } catch (IllegalArgumentException e) {
            decodedBytes = Base64.getDecoder().decode(encryptedText);
        }

        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Generates an AES SecretKeySpec from the given key string.
     * Uses SHA-256 to hash the key and takes the first 16 bytes (AES-128).
     *
     * @param secretKey the secret key string
     * @return a SecretKeySpec suitable for AES encryption
     */
    private static SecretKeySpec generateKey(String secretKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(secretKey.getBytes(StandardCharsets.UTF_8));
        // Use first 16 bytes for AES-128
        keyBytes = Arrays.copyOf(keyBytes, 16);
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    /**
     * Loads properties from a file path. Falls back to classpath if file not found.
     *
     * @param filePath the path to the properties file
     * @return the loaded Properties object, or null on failure
     */
    private static Properties loadProperties(String filePath) {
        Properties properties = new Properties();

        // Try loading from file system first
        try (FileInputStream fis = new FileInputStream(filePath)) {
            properties.load(fis);
            return properties;
        } catch (IOException e) {
            // Fall back to classpath
        }

        // Try loading from classpath
        try (InputStream is = IdPermanence.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (is != null) {
                properties.load(is);
                return properties;
            }
        } catch (IOException e) {
            // Ignore
        }

        return null;
    }
}
