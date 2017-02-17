package com.rockaport.alice;

/**
 * Context passed into {@link com.rockaport.alice.Alice}. You should use {@link com.rockaport.alice.AliceContextBuilder}
 * to create this class as it contains many defaults.
 */
public class AliceContext {
    private Algorithm algorithm;
    private Mode mode;
    private Padding padding;
    private KeyLength keyLength;
    private Pbkdf pbkdf;
    private MacAlgorithm macAlgorithm;
    private int ivLength;
    private GcmTagLength gcmTagLength;
    private int iterations;

    /**
     * Initializes a new {@code AliceContext} for use with {@link com.rockaport.alice.Alice}. Most of the inputs are
     * described in the <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html">
     * Java Cryptography Architecture Standard Algorithm Name Documentation for JDK 8</a>.
     *
     * @param algorithm    the {@link Algorithm}
     * @param mode         the {@link Mode}
     * @param padding      the {@link Padding}
     * @param keyLength    the {@link KeyLength}
     * @param pbkdf        the {@link Pbkdf}
     * @param macAlgorithm the {@link MacAlgorithm}
     * @param ivLength     the length of the initialization vector
     * @param gcmTagLength the {@link GcmTagLength}
     * @param iterations   the number of iterations used for PBKDF modes
     */
    @SuppressWarnings("WeakerAccess")
    public AliceContext(Algorithm algorithm,
                        Mode mode,
                        Padding padding,
                        KeyLength keyLength,
                        Pbkdf pbkdf,
                        MacAlgorithm macAlgorithm,
                        int ivLength, GcmTagLength gcmTagLength,
                        int iterations) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.keyLength = keyLength;
        this.pbkdf = pbkdf;
        this.macAlgorithm = macAlgorithm;
        this.ivLength = ivLength;
        this.gcmTagLength = gcmTagLength;
        this.iterations = iterations;
    }

    @SuppressWarnings("WeakerAccess")
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @SuppressWarnings("WeakerAccess")
    public Mode getMode() {
        return mode;
    }

    @SuppressWarnings("WeakerAccess")
    public Padding getPadding() {
        return padding;
    }

    @SuppressWarnings("WeakerAccess")
    public KeyLength getKeyLength() {
        return keyLength;
    }

    @SuppressWarnings("WeakerAccess")
    public Pbkdf getPbkdf() {
        return pbkdf;
    }

    @SuppressWarnings("WeakerAccess")
    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    @SuppressWarnings("WeakerAccess")
    public int getIvLength() {
        return ivLength;
    }

    @SuppressWarnings("WeakerAccess")
    public GcmTagLength getGcmTagLength() {
        return gcmTagLength;
    }

    @SuppressWarnings("WeakerAccess")
    public int getIterations() {
        return iterations;
    }

    /**
     * Algorithm used for the {@link javax.crypto.Cipher}
     */
    public enum Algorithm {
        /**
         * Advanced Encryption Standard as specified by NIST in <a href="http://csrc.nist.gov/publications/PubsFIPS.html">
         * FIPS 197</a>. Also known as the Rijndael algorithm by Joan Daemen and Vincent Rijmen, AES is a 128-bit block
         * cipher supporting keys of 128, 192, and 256 bits.
         */
        AES("AES"),
        /**
         * The Digital Encryption Standard as described in
         * <a href="http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf">FIPS PUB 46-3</a>
         */
        DES("DES"),
        /**
         * Triple DES Encryption (also known as DES-EDE, 3DES, or Triple-DES). Data is encrypted using the DES
         * algorithm three separate times. It is first encrypted using the first subkey, then decrypted with the second
         * subkey, and encrypted with the third subkey.
         */
        DESede("DESede");

        private String value;

        Algorithm(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Mode used for the {@link javax.crypto.Cipher}
     */
    public enum Mode {
        /**
         * Cipher Block Chaining Mode, as defined in <a href="http://csrc.nist.gov/publications/fips/fips81/fips81.htm">FIPS PUB
         * 81</a>
         */
        CBC("CBC"),
        /**
         * Counter/CBC Mode, as defined in <a href="http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf">
         * NIST Special Publication SP 800-38C</a>
         */
        CTR("CTR"),
        /**
         * Galois/Counter Mode, as defined in
         * <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">NIST Special Publication SP 800-38D</a>.
         */
        GCM("GCM");

        private String value;

        Mode(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Cipher algorithm padding
     */
    public enum Padding {
        /**
         * No padding
         */
        NO_PADDING("NoPadding"),
        /**
         * The padding scheme described in <a href="http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-5-password-based-cryptography-standard.htm">
         * RSA Laboratories, "PKCS #5: Password-Based Encryption Standard," version 1.5, November 1993</a>
         */
        PKCS5_PADDING("PKCS5Padding");

        private String value;

        Padding(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Cipher key length
     */
    public enum KeyLength {
        BITS_64(64),
        BITS_128(128),
        BITS_192(192),
        BITS_256(256);

        private int bits;

        KeyLength(int bits) {
            this.bits = bits;
        }

        public int bits() {
            return bits;
        }

        public int bytes() {
            return bits >> 3;
        }
    }

    /**
     * Supported Password Based Key Derivation Function (PBKDF) algorithms.
     */
    public enum Pbkdf {
        /**
         * Use password as is.
         */
        NONE("None"),
        /**
         * SHA-1 hash the password
         */
        SHA_1("SHA-1"),
        /**
         * SHA-224 hash the password
         */
        SHA_224("SHA-224"),
        /**
         * SHA-256 hash the password
         */
        SHA_256("SHA-256"),
        /**
         * SHA-384 hash the password
         */
        SHA_384("SHA-384"),
        /**
         * SHA-512 hash the password
         */
        SHA_512("SHA-512"),
        /**
         * Password-based key-derivation algorithm found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_1("PBKDF2WithHmacSHA1"),
        /**
         * Password-based key-derivation algorithm found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_256("PBKDF2WithHmacSHA256"),
        /**
         * Password-based key-derivation algorithm found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_384("PBKDF2WithHmacSHA384"),
        /**
         * Password-based key-derivation algorithm found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_512("PBKDF2WithHmacSHA512");

        private final String value;

        Pbkdf(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Supported Messsage Authentication Algorithms (MAC).
     * The HmacSHA* algorithms as defined in <a href="http://www.ietf.org/rfc/rfc2104.txt">RFC 2104</a> "HMAC:
     * Keyed-Hashing for Message Authentication" (February 1997) with SHA-* as the message digest algorithm.
     */
    public enum MacAlgorithm {
        NONE("None"),
        HMAC_SHA_1("HmacSHA1"),
        HMAC_SHA_256("HmacSHA256"),
        HMAC_SHA_384("HmacSHA384"),
        HMAC_SHA_512("HmacSHA512");

        private final String value;

        MacAlgorithm(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Supported GCM tag lengths.
     * Please see <a href="http://www.ietf.org/rfc/rfc5116.txt">RFC 5116</a> for more information on the Authenticated
     * Encryption with Associated Data (AEAD) algorithm, and
     * <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">NIST Special Publication 800-38D</a>,
     * "NIST Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC."
     */
    public enum GcmTagLength {
        BITS_96(96),
        BITS_104(104),
        BITS_112(112),
        BITS_120(120),
        BITS_128(128);

        private int bits;

        GcmTagLength(int bits) {
            this.bits = bits;
        }

        public int bits() {
            return bits;
        }
    }
}
