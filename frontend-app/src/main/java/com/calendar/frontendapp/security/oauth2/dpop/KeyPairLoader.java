package com.calendar.frontendapp.security.oauth2.dpop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility class for loading SSH RSA keypair from PEM-formatted files.
 * Handles both OpenSSH format (id_rsa) and standard public key format (id_rsa.pub)
 */
public class KeyPairLoader {

    private static final Logger logger = LoggerFactory.getLogger(KeyPairLoader.class);

    public static KeyPair loadKeyPair(String privateKeyPath, String publicKeyPath) throws Exception {
        logger.info("Loading KeyPair from files: privateKey={}, publicKey={}", privateKeyPath, publicKeyPath);

        PublicKey publicKey = loadPublicKey(publicKeyPath);
        PrivateKey privateKey = loadOpenSSHPrivateKey(privateKeyPath);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        logger.info("KeyPair loaded successfully from SSH files");
        return keyPair;
    }

    private static PublicKey loadPublicKey(String filePath) throws Exception {
        String keyContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8).trim();

        String[] parts = keyContent.split(" ");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid SSH public key format");
        }
        byte[] publicKeyBytes = Base64.getDecoder().decode(parts[1]);

        int offset = 0;

        int typeLen = ((publicKeyBytes[offset] & 0xFF) << 24)
                | ((publicKeyBytes[offset + 1] & 0xFF) << 16)
                | ((publicKeyBytes[offset + 2] & 0xFF) << 8)
                | (publicKeyBytes[offset + 3] & 0xFF);
        offset += 4 + typeLen;

        int eLen = ((publicKeyBytes[offset] & 0xFF) << 24)
                | ((publicKeyBytes[offset + 1] & 0xFF) << 16)
                | ((publicKeyBytes[offset + 2] & 0xFF) << 8)
                | (publicKeyBytes[offset + 3] & 0xFF);
        offset += 4;

        byte[] e = new byte[eLen];
        System.arraycopy(publicKeyBytes, offset, e, 0, eLen);
        offset += eLen;

        int nLen = ((publicKeyBytes[offset] & 0xFF) << 24)
                | ((publicKeyBytes[offset + 1] & 0xFF) << 16)
                | ((publicKeyBytes[offset + 2] & 0xFF) << 8)
                | (publicKeyBytes[offset + 3] & 0xFF);
        offset += 4;

        byte[] n = new byte[nLen];
        System.arraycopy(publicKeyBytes, offset, n, 0, nLen);

        // Create RSAPublicKeySpec and generate public key
        java.math.BigInteger exponent = new java.math.BigInteger(1, e);
        java.math.BigInteger modulus = new java.math.BigInteger(1, n);
        java.security.spec.RSAPublicKeySpec keySpec = new java.security.spec.RSAPublicKeySpec(modulus, exponent);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey loadOpenSSHPrivateKey(String filePath) throws Exception {
        try {
            // Try to use the Bouncy Castle provider which supports OpenSSH format
            return loadOpenSSHPrivateKeyWithBouncyCastle(filePath);
        } catch (Exception bcEx) {
            throw new RuntimeException("BouncyCastle failed to load OpenSSH key: {}, trying conversion method", bcEx);
        }
    }

    private static PrivateKey loadOpenSSHPrivateKeyWithBouncyCastle(String filePath) throws Exception {
        try {
            logger.info("Attempting to load OpenSSH private key using BouncyCastle");

            // Verify BouncyCastle is available
            try {
                Class.forName("org.bouncycastle.openssl.PEMParser");
                logger.info("BouncyCastle PEMParser found on classpath");
            } catch (ClassNotFoundException ex) {
                logger.error("BouncyCastle PEMParser not found on classpath", ex);
                throw new RuntimeException("BouncyCastle not available. Ensure org.bouncycastle:bcprov-jdk15on and bcpkix-jdk15on are in classpath", ex);
            }

            // Use reflection to load BouncyCastle classes
            Class<?> pemParserClass = Class.forName("org.bouncycastle.openssl.PEMParser");
            Class<?> keyPairClass = Class.forName("org.bouncycastle.openssl.PEMKeyPair");
            Class<?> privateKeyInfoClass = Class.forName("org.bouncycastle.asn1.pkcs.PrivateKeyInfo");
            Class<?> jcaPEMKeyConverterClass = Class.forName("org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter");

            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                Object pemParser = pemParserClass.getConstructor(java.io.Reader.class).newInstance(reader);
                Object object = pemParserClass.getMethod("readObject").invoke(pemParser);
                pemParserClass.getMethod("close").invoke(pemParser);

                logger.debug("Parsed object type: {}", object.getClass().getName());

                Object converter = jcaPEMKeyConverterClass.getConstructor().newInstance();

                if (keyPairClass.isInstance(object)) {
                    logger.info("OpenSSH private key parsed as PEMKeyPair");
                    Object privateKeyInfo = keyPairClass.getMethod("getPrivateKeyInfo").invoke(object);
                    return (PrivateKey) jcaPEMKeyConverterClass.getMethod("getPrivateKey", privateKeyInfoClass)
                            .invoke(converter, privateKeyInfo);
                } else if (privateKeyInfoClass.isInstance(object)) {
                    logger.info("OpenSSH private key parsed as PrivateKeyInfo");
                    return (PrivateKey) jcaPEMKeyConverterClass.getMethod("getPrivateKey", privateKeyInfoClass)
                            .invoke(converter, object);
                } else {
                    throw new RuntimeException("Unexpected object type: " + object.getClass().getName());
                }
            }
        } catch (ClassNotFoundException ex) {
            logger.error("BouncyCastle class not found", ex);
            throw new RuntimeException("BouncyCastle not available. Ensure org.bouncycastle:bcprov-jdk15on and bcpkix-jdk15on are in classpath", ex);
        } catch (Exception ex) {
            logger.error("Failed to parse OpenSSH private key: {}", ex.getMessage(), ex);
            throw new RuntimeException("Unable to parse OpenSSH private key format: " + ex.getMessage(), ex);
        }
    }
}
