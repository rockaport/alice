package com.rockaport.alice;

import okio.Buffer;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * The main Alice API for encryption and decryption of byte arrays and files.
 */
public class Alice {
    private final AliceContext context;
    private final Cipher cipher;
    private final int ivLength;

    /**
     * Initializes a new {@code Alice} object for encryption and decryption. See
     * {@link com.rockaport.alice.AliceContext} for an explanation of options.
     *
     * @param context an {@link com.rockaport.alice.AliceContext}
     */
    @SuppressWarnings("WeakerAccess")
    public Alice(AliceContext context) {
        if (context == null ||
                context.getAlgorithm() == null ||
                context.getMode() == null ||
                context.getPadding() == null) {

            throw new IllegalArgumentException("Context, algorithm, mode, or padding is null");
        }

        this.context = context;

        switch (context.getAlgorithm()) {
            case AES:
                ivLength = 16;
                break;
            case DES:
                ivLength = 8;
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm");
        }

        try {
            cipher = Cipher.getInstance(context.getAlgorithm() + "/" + context.getMode() + "/" + context.getPadding());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates an AES key
     *
     * @param algorithm the key will be used with
     * @param keyLength length of key
     * @return a byte array
     * @throws GeneralSecurityException if either initialization or generation fails
     */
    @SuppressWarnings("WeakerAccess")
    public static byte[] generateKey(AliceContext.Algorithm algorithm, AliceContext.KeyLength keyLength)
            throws GeneralSecurityException {
        if (algorithm == null || keyLength == null) {
            throw new IllegalArgumentException("Algorithm or keyLength is null");
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm.toString());

        int actualKeyLength = keyLength.bits();
        if (keyLength == AliceContext.KeyLength.BITS_64) {
            actualKeyLength -= 8;
        }

        keyGenerator.init(actualKeyLength);

        return keyGenerator.generateKey().getEncoded();
    }

    /**
     * Gets a {@link javax.crypto.Mac} instance
     *
     * @param macAlgorithm the {@link com.rockaport.alice.AliceContext.MacAlgorithm}
     * @param password     a password
     * @return an initialized {@link javax.crypto.Mac}
     * @throws GeneralSecurityException if MAC initialization fails
     */
    @SuppressWarnings("WeakerAccess")
    public static Mac getMac(AliceContext.MacAlgorithm macAlgorithm, char[] password) throws GeneralSecurityException {
        if (macAlgorithm == null) {
            throw new IllegalArgumentException("Algorithm is null");
        }

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is null or empty");
        }

        Mac mac = Mac.getInstance(macAlgorithm.toString());

        mac.init(new SecretKeySpec(toBytes(password), macAlgorithm.toString()));

        return mac;
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
     * Encrypts a byte array using the supplied password
     *
     * @param input    the byte array input
     * @param password the password
     * @return an encrypted byte array
     * @throws GeneralSecurityException if initialization or encryption fails
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized byte[] encrypt(byte[] input, char[] password) throws GeneralSecurityException {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is either null or empty");
        }

        // generate the initialization vector
        byte[] initializationVector = generateInitializationVector();

        // initialize the cipher
        cipher.init(Cipher.ENCRYPT_MODE,
                deriveKey(password, initializationVector),
                getAlgorithmParameterSpec(context.getMode(), initializationVector));

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
    }

    /**
     * Encrypts the input file using the supplied password
     *
     * @param input    the input file
     * @param output   the output file
     * @param password the password
     * @throws GeneralSecurityException if initialization or encryption fails
     * @throws IOException              if there's a failure to read/write from/to the input/output file
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized void encrypt(File input, File output, char[] password)
            throws GeneralSecurityException, IOException {
        if (input == null || !input.exists() || input.length() <= 0) {
            throw new IllegalArgumentException("Input file is either null or does not exist");
        }

        BufferedInputStream bufferedInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;

        try {
            // generate the initialization vector
            byte[] initializationVector = generateInitializationVector();

            // initialize the cipher
            cipher.init(Cipher.ENCRYPT_MODE,
                    deriveKey(password, initializationVector),
                    getAlgorithmParameterSpec(context.getMode(), initializationVector));

            // initialize the mac if needed
            Mac mac = null;

            if (context.getMacAlgorithm() != AliceContext.MacAlgorithm.NONE) {
                mac = getMac(context.getMacAlgorithm(), password);
            }

            // allocate variables
            int bytesRead;
            byte[] encryptedBytes;
            byte[] inputStreamBuffer = new byte[4096];

            // setup streams
            bufferedInputStream = new BufferedInputStream(new FileInputStream(input));
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(output));

            // write the initialization vector
            bufferedOutputStream.write(initializationVector);

            while ((bytesRead = bufferedInputStream.read(inputStreamBuffer)) > 0) {
                // encrypt
                encryptedBytes = cipher.update(inputStreamBuffer, 0, bytesRead);

                bufferedOutputStream.write(encryptedBytes);

                // compute the mac if needed
                if (mac != null) {
                    mac.update(encryptedBytes, 0, bytesRead);
                }
            }

            // finalize and write the cipher
            bufferedOutputStream.write(cipher.doFinal());

            // write the mac
            if (mac != null) {
                bufferedOutputStream.write(mac.doFinal());
            }
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException ignored) {
                }
            }

            if (bufferedOutputStream != null) {
                try {
                    bufferedOutputStream.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Decrypts a byte array using the supplied password
     *
     * @param input    the byte array input
     * @param password the password
     * @return a decrypted byte array
     * @throws GeneralSecurityException if initialization, decryption, or the MAC comparison fails
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized byte[] decrypt(byte[] input, char[] password) throws GeneralSecurityException {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is either null or empty");
        }

        // deconstruct the input
        byte[] initializationVector = Arrays.copyOfRange(input, 0, ivLength);

        byte[] cipherText;

        // extract the MAC if needed
        if (context.getMacAlgorithm() == AliceContext.MacAlgorithm.NONE) {
            cipherText = Arrays.copyOfRange(input, ivLength, input.length);
        } else {
            Mac mac = getMac(context.getMacAlgorithm(), password);

            cipherText = Arrays.copyOfRange(input, ivLength, input.length - mac.getMacLength());
            byte[] recMac = Arrays.copyOfRange(input, input.length - mac.getMacLength(), input.length);

            // compute the mac
            byte[] macBytes = mac.doFinal(cipherText);

            // verify the macs are the same
            if (!Arrays.equals(recMac, macBytes)) {
                throw new GeneralSecurityException("Received mac is different from calculated");
            }
        }

        // initialize the cipher
        cipher.init(Cipher.DECRYPT_MODE,
                deriveKey(password, initializationVector),
                getAlgorithmParameterSpec(context.getMode(), initializationVector));

        return cipher.doFinal(cipherText);
    }

    /**
     * Decrypts an input file using the supplied password
     *
     * @param input    the input file
     * @param output   the output file
     * @param password the password
     * @throws GeneralSecurityException if initialization or decryption fails
     * @throws IOException              if there's a failure to read/write from/to the input/output file
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized void decrypt(File input, File output, char[] password)
            throws GeneralSecurityException, IOException {
        if (input == null || !input.exists() || input.length() <= 0) {
            throw new IllegalArgumentException("Input file is either null or does not exist");
        }

        BufferedInputStream bufferedInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;

        try {
            // read the mac if needed
            Mac mac = null;
            byte[] recMac = null;

            if (context.getMacAlgorithm() != AliceContext.MacAlgorithm.NONE) {
                mac = getMac(context.getMacAlgorithm(), password);

                recMac = new byte[mac.getMacLength()];

                RandomAccessFile randomAccessFile = new RandomAccessFile(input, "r");

                randomAccessFile.seek(randomAccessFile.length() - mac.getMacLength());
                randomAccessFile.read(recMac);

                randomAccessFile.close();
            }

            // setup streams
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(output));
            bufferedInputStream = new BufferedInputStream(new FileInputStream(input));

            // read the initialization vector
            byte[] initializationVector = new byte[ivLength];

            int ivBytesRead = bufferedInputStream.read(initializationVector);

            if (ivBytesRead < ivLength) {
                throw new IOException("File doesn't contain an IV");
            }

            // initialize the cipher
            cipher.init(Cipher.DECRYPT_MODE,
                    deriveKey(password, initializationVector),
                    getAlgorithmParameterSpec(context.getMode(), initializationVector));

            // allocate loop buffers and variables
            int bytesRead;
            int numBytesToProcess;
            byte[] inputStreamBuffer = new byte[4096];
            long bytesLeft = input.length() - ivLength;

            // subtract the mac length if enabled
            if (mac != null) {
                bytesLeft -= mac.getMacLength();
            }

            // decrypt
            while ((bytesRead = bufferedInputStream.read(inputStreamBuffer)) > 0) {
                numBytesToProcess = (bytesRead < bytesLeft) ? bytesRead : (int) bytesLeft;

                bufferedOutputStream.write(cipher.update(inputStreamBuffer, 0, numBytesToProcess));

                // reduce the number of bytes left
                bytesLeft -= numBytesToProcess;

                // compute the mac if needed
                if (mac != null) {
                    mac.update(inputStreamBuffer, 0, numBytesToProcess);
                }
            }

            // finalize the cipher
            bufferedOutputStream.write(cipher.doFinal());

            // compare the mac
            if (mac != null && !Arrays.equals(recMac, mac.doFinal())) {
                throw new GeneralSecurityException("Received mac is different from calculated");
            }
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException ignored) {
                }
            }

            if (bufferedOutputStream != null) {
                try {
                    bufferedOutputStream.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Derives an AES {@link javax.crypto.spec.SecretKeySpec} using a password and iteration count (if needed).
     *
     * @param password             the password
     * @param initializationVector used for PBKDF
     * @return an AES {@link javax.crypto.spec.SecretKeySpec}
     * @throws GeneralSecurityException if initialization, decryption, or the MAC comparison fails
     */
    private SecretKey deriveKey(char[] password, byte[] initializationVector) throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is either null or empty");
        }

        byte[] key = null;

        switch (context.getPbkdf()) {
            case NONE:
                key = new byte[context.getKeyLength().bytes()];

                System.arraycopy(toBytes(password), 0,
                        key, 0,
                        Math.min(context.getKeyLength().bytes(), password.length));
                break;
            case SHA_1:
            case SHA_224:
            case SHA_256:
            case SHA_384:
            case SHA_512:
                key = new byte[context.getKeyLength().bytes()];

                byte[] hashedPassword = MessageDigest.getInstance(context.getPbkdf().toString())
                        .digest(toBytes(password));

                System.arraycopy(hashedPassword, 0,
                        key, 0,
                        Math.min(context.getKeyLength().bytes(), hashedPassword.length));
                break;
            case PBKDF_2_WITH_HMAC_SHA_1:
            case PBKDF_2_WITH_HMAC_SHA_256:
            case PBKDF_2_WITH_HMAC_SHA_384:
            case PBKDF_2_WITH_HMAC_SHA_512:
                key = SecretKeyFactory.getInstance(context.getPbkdf().toString())
                        .generateSecret(
                                new PBEKeySpec(
                                        password,
                                        initializationVector,
                                        context.getIterations(),
                                        context.getKeyLength().bits()))
                        .getEncoded();
                break;
        }

        return new SecretKeySpec(key, context.getAlgorithm().toString());
    }

    private AlgorithmParameterSpec getAlgorithmParameterSpec(AliceContext.Mode mode, byte[] initializationVector) {
        if (mode == null || initializationVector == null || initializationVector.length <= 0) {
            throw new IllegalArgumentException("Mode or initialization vector is either null or empty");
        }

        switch (mode) {
            case CBC:
            case CTR:
                return new IvParameterSpec(initializationVector);
            case GCM:
                return new GCMParameterSpec(ivLength << 3, initializationVector);
        }

        throw new IllegalArgumentException("Unknown mode");
    }

    /**
     * Generates an initialization vector using {@link java.security.SecureRandom} as the number generator
     *
     * @return a byte array
     */
    private byte[] generateInitializationVector() {
        byte[] initializationVector = new byte[ivLength];

        new SecureRandom().nextBytes(initializationVector);

        return initializationVector;
    }
}