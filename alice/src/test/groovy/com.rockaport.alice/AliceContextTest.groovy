package com.rockaport.alice

import spock.lang.Specification

class AliceContextTest extends Specification {
    def "Algorithm valueOf returns correct string"() {
        expect:
        AliceContext.Algorithm.valueOf(input) == output

        where:
        input || output
        "AES" || AliceContext.Algorithm.AES
        "DES" || AliceContext.Algorithm.DES
    }

    def "Mode valueOf returns correct string"() {
        expect:
        AliceContext.Mode.valueOf(input) == output

        where:
        input || output
        "CBC" || AliceContext.Mode.CBC
        "CTR" || AliceContext.Mode.CTR
        "GCM" || AliceContext.Mode.GCM
    }

    def "Padding valueOf returns correct string"() {
        expect:
        AliceContext.Padding.valueOf(input) == output

        where:
        input           || output
        "NO_PADDING"    || AliceContext.Padding.NO_PADDING
        "PKCS5_PADDING" || AliceContext.Padding.PKCS5_PADDING
    }

    def "KeyLength valueOf returns correct string"() {
        expect:
        AliceContext.KeyLength.valueOf(input) == output

        where:
        input      || output
        "BITS_64"  || AliceContext.KeyLength.BITS_64
        "BITS_128" || AliceContext.KeyLength.BITS_128
        "BITS_192" || AliceContext.KeyLength.BITS_192
        "BITS_256" || AliceContext.KeyLength.BITS_256
    }

    def "Pbkdf valueOf returns correct string"() {
        expect:
        AliceContext.Pbkdf.valueOf(input) == output

        where:
        input                       || output
        "NONE"                      || AliceContext.Pbkdf.NONE
        "SHA_1"                     || AliceContext.Pbkdf.SHA_1
        "SHA_224"                   || AliceContext.Pbkdf.SHA_224
        "SHA_256"                   || AliceContext.Pbkdf.SHA_256
        "SHA_384"                   || AliceContext.Pbkdf.SHA_384
        "SHA_512"                   || AliceContext.Pbkdf.SHA_512
        "PBKDF_2_WITH_HMAC_SHA_1"   || AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_1
        "PBKDF_2_WITH_HMAC_SHA_256" || AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_256
        "PBKDF_2_WITH_HMAC_SHA_384" || AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_384
        "PBKDF_2_WITH_HMAC_SHA_512" || AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512
    }

    def "MacAlgorithm valueOf returns correct string"() {
        expect:
        AliceContext.MacAlgorithm.valueOf(input) == output

        where:
        input          || output
        "NONE"         || AliceContext.MacAlgorithm.NONE
        "HMAC_SHA_1"   || AliceContext.MacAlgorithm.HMAC_SHA_1
        "HMAC_SHA_256" || AliceContext.MacAlgorithm.HMAC_SHA_256
        "HMAC_SHA_384" || AliceContext.MacAlgorithm.HMAC_SHA_384
        "HMAC_SHA_512" || AliceContext.MacAlgorithm.HMAC_SHA_512
    }

    def "GcmTagLength valueOf returns correct string"() {
        expect:
        AliceContext.GcmTagLength.valueOf(input) == output

        where:
        input      || output
        "BITS_96"  || AliceContext.GcmTagLength.BITS_96
        "BITS_104" || AliceContext.GcmTagLength.BITS_104
        "BITS_112" || AliceContext.GcmTagLength.BITS_112
        "BITS_120" || AliceContext.GcmTagLength.BITS_120
        "BITS_128" || AliceContext.GcmTagLength.BITS_128
    }
}
