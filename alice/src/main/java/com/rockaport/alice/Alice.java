package com.rockaport.alice;

import okio.Buffer;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Alice {
    private static final int IV_LENGTH = 16;
    private final AliceContext context;
    private final Cipher cipher;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Initializes a new {@code Alice} object for encryption and decryption. See {@link com.rockaport.alice.AliceContext}
     * for an explanation of options.
     *
     * @param context an {@link com.rockaport.alice.AliceContext}
     */
    public Alice(AliceContext context) {
        try {
            if (context == null ||
                    context.getAlgorithm() == null ||
                    context.getMode() == null ||
                    context.getPadding() == null) {

                throw new IllegalArgumentException("Context, algorithm, mode, or padding is null");
            }

            this.context = context;

            cipher = Cipher.getInstance(context.getAlgorithm() + "/" + context.getMode() + "/" + context.getPadding());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Performs a narrowing byte-to-char conversion
     *
     * @param chars input
     * @return byte conversion
     */
    private static byte[] toBytes(char[] chars) {
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i < chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    /**
     * Generates an AES key
     *
     * @param keyLength length of key
     * @return a byte array
     */
    public static byte[] generateKey(AliceContext.KeyLength keyLength) {
        try {
            if (keyLength == null) {
                throw new IllegalArgumentException("KeyLength is null");
            }

            KeyGenerator keyGenerator = KeyGenerator.getInstance(AliceContext.Algorithm.AES.toString());

            keyGenerator.init(keyLength.bits());

            return keyGenerator.generateKey().getEncoded();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets a {@link javax.crypto.Mac} instance
     *
     * @param password a password
     * @return an initialized {@link javax.crypto.Mac}
     */
    public static Mac getMac(AliceContext.MacAlgorithm macAlgorithm, char[] password) {
        try {
            if (macAlgorithm == null) {
                throw new IllegalArgumentException("Algorithm is null");
            }

            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password is null or empty");
            }

            Mac mac = Mac.getInstance(macAlgorithm.toString());

            mac.init(new SecretKeySpec(toBytes(password), macAlgorithm.toString()));

            return mac;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Derives an AES {@link javax.crypto.spec.SecretKeySpec} using a password and iteration count (if needed).
     *
     * @param password             the password
     * @param initializationVector used for PBKDF
     * @return an AES {@link javax.crypto.spec.SecretKeySpec}
     */
    private SecretKey deriveKey(char[] password, byte[] initializationVector) {
        try {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password is either null or empty");
            }

            byte[] key = new byte[context.getKeyLength().bytes()];

            if (context.getPbkdf() == AliceContext.Pbkdf.NONE) {
                System.arraycopy(toBytes(password), 0,
                        key, 0,
                        Math.min(context.getKeyLength().bytes(), password.length));
            } else if (context.getPbkdf() == AliceContext.Pbkdf.SHA_1 ||
                    context.getPbkdf() == AliceContext.Pbkdf.SHA_224 ||
                    context.getPbkdf() == AliceContext.Pbkdf.SHA_256 ||
                    context.getPbkdf() == AliceContext.Pbkdf.SHA_384 ||
                    context.getPbkdf() == AliceContext.Pbkdf.SHA_512) {
                byte[] hashedPassword = MessageDigest.getInstance(context.getPbkdf().toString()).digest(toBytes(password));
                System.arraycopy(hashedPassword, 0,
                        key, 0,
                        Math.min(context.getKeyLength().bytes(), hashedPassword.length));
            } else if (context.getPbkdf() == AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_1 ||
                    context.getPbkdf() == AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_256 ||
                    context.getPbkdf() == AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_384 ||
                    context.getPbkdf() == AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512) {
                key = SecretKeyFactory.getInstance(context.getPbkdf().toString())
                        .generateSecret(new PBEKeySpec(password, initializationVector, context.getIterations(), context.getKeyLength().bits()))
                        .getEncoded();
            }

            return new SecretKeySpec(key, "AES");
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts a byte array using the supplied password
     *
     * @param input    the byte array input
     * @param password the password
     * @return an encrypted byte array
     */
    public synchronized byte[] encrypt(byte[] input, char[] password) {
        try {
            if (input == null || input.length == 0) {
                throw new IllegalArgumentException("Input is either null or empty");
            }

            // generate the initialization vector
            byte[] initializationVector = generateInitializationVector();

            // initialize the cipher
            cipher.init(Cipher.ENCRYPT_MODE,
                    deriveKey(password, initializationVector),
                    new IvParameterSpec(initializationVector));

            // encrypt
            byte[] encryptedBytes = cipher.doFinal(input);

            // construct the output (IV || CIPHER)
            Buffer output = new Buffer();

            output.write(cipher.getIV());
            output.write(encryptedBytes);

            // compute the MAC if needed and append the MAC (IV || CIPHER || MAC)
            if (context.getMacAlgorithm() != AliceContext.MacAlgorithm.NONE) {
                output.write(getMac(context.getMacAlgorithm(), password).doFinal(encryptedBytes));
            }

            return output.readByteArray();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts a byte array using the supplied password
     *
     * @param input    the byte array input
     * @param password the password
     * @return a decrypted byte array
     */
    public synchronized byte[] decrypt(byte[] input, char[] password) {
        try {
            if (input == null || input.length == 0) {
                throw new IllegalArgumentException("Input is either null or empty");
            }

            // deconstruct the input
            byte[] initializationVector = Arrays.copyOfRange(input, 0, IV_LENGTH);

            byte[] cipherText;

            // extract the MAC if needed
            if (context.getMacAlgorithm() == AliceContext.MacAlgorithm.NONE) {
                cipherText = Arrays.copyOfRange(input, IV_LENGTH, input.length);
            } else {
                Mac mac = getMac(context.getMacAlgorithm(), password);

                cipherText = Arrays.copyOfRange(input, IV_LENGTH, input.length - mac.getMacLength());
                byte[] recMac = Arrays.copyOfRange(input, input.length - mac.getMacLength(), input.length);

                // compute the mac
                byte[] macBytes = mac.doFinal(cipherText);

                // verify the macs are the same
                if (!Arrays.equals(recMac, macBytes)) {
                    throw new GeneralSecurityException("Received mac is different from calculated");
                }
            }

            // decrypt
            cipher.init(Cipher.DECRYPT_MODE,
                    deriveKey(password, initializationVector),
                    new IvParameterSpec(initializationVector));

            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates an initialization vector using {@link java.security.SecureRandom} as the number generator
     *
     * @return a byte array
     */
    private byte[] generateInitializationVector() {
        byte[] initializationVector = new byte[IV_LENGTH];

        secureRandom.nextBytes(initializationVector);

        return initializationVector;
    }
}