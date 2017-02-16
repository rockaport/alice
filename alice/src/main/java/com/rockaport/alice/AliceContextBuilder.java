package com.rockaport.alice;

/**
 * Used to build an {@link com.rockaport.alice.AliceContext}.
 */
public class AliceContextBuilder {
    private AliceContext.Algorithm algorithm = AliceContext.Algorithm.AES;
    private AliceContext.Mode mode = AliceContext.Mode.CTR;
    private AliceContext.Padding padding = AliceContext.Padding.NO_PADDING;
    private AliceContext.KeyLength keyLength = AliceContext.KeyLength.BITS_256;
    private AliceContext.Pbkdf pbkdf = AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512;
    private AliceContext.MacAlgorithm macAlgorithm = AliceContext.MacAlgorithm.HMAC_SHA_512;
    private int ivLength = 16;
    private AliceContext.GcmTagLength gcmTagLength = AliceContext.GcmTagLength.BITS_128;
    private int iterations = 10000;

    /**
     * Sets the cipher algorithm. Defaults to {@code AES} and is the only supported algorithm
     *
     * @param algorithm the {@link com.rockaport.alice.AliceContext.Algorithm}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setAlgorithm(AliceContext.Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the cipher algorithm mode. Defaults to {@code CTR}
     *
     * @param mode the {@link com.rockaport.alice.AliceContext.Mode}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setMode(AliceContext.Mode mode) {
        this.mode = mode;
        return this;
    }

    /**
     * Sets the cipher algorithm padding. Defaults to {@code NoPadding}
     *
     * @param padding the {@link com.rockaport.alice.AliceContext.Padding}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setPadding(AliceContext.Padding padding) {
        this.padding = padding;
        return this;
    }

    /**
     * Sets the cipher key length. Defaults to {@code 256}
     *
     * @param keyLength the {@link com.rockaport.alice.AliceContext.KeyLength}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setKeyLength(AliceContext.KeyLength keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    /**
     * Sets the Pbkdf algorithm. Defaults to {@code PBKDF2WithHmacSHA512}
     *
     * @param pbkdf the {@link com.rockaport.alice.AliceContext.Pbkdf}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setPbkdf(AliceContext.Pbkdf pbkdf) {
        this.pbkdf = pbkdf;
        return this;
    }

    /**
     * Sets the MAC algorithm. Defaults to {@code HmacSHA512}
     *
     * @param macAlgorithm the {@link com.rockaport.alice.AliceContext.MacAlgorithm}
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setMacAlgorithm(AliceContext.MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
        return this;
    }

    /**
     * Sets the initialization vector. Defaults to {@code 16}
     * See {@link javax.crypto.spec.IvParameterSpec} or {@link javax.crypto.spec.GCMParameterSpec}
     *
     * @param ivLength the length of the initialization vector
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setIvLength(int ivLength) {
        this.ivLength = ivLength;
        return this;
    }

    /**
     * Sets the GCM tag length. Defaults to {@code 128}
     *
     * @param gcmTagLength the tag length used for GCM modes of operation
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setGcmTagLength(AliceContext.GcmTagLength gcmTagLength) {
        this.gcmTagLength = gcmTagLength;
        return this;
    }

    /**
     * Sets the iterations for the Pbkdf algorithm. Defaults to {@code 10000}
     *
     * @param iterations the iterations used with the Pbkdf algorithm
     * @return {@link com.rockaport.alice.AliceContextBuilder}
     */
    public AliceContextBuilder setIterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    /**
     * Creates an {@link com.rockaport.alice.AliceContext} with the arguments supplied to this builder.
     *
     * @return {@link com.rockaport.alice.AliceContext}
     */
    public AliceContext build() {
        return new AliceContext(algorithm, mode, padding, keyLength, pbkdf, macAlgorithm, ivLength, gcmTagLength, iterations);
    }
}