package com.rockaport.alice

import com.rockaport.alice.AliceContext
import org.apache.commons.io.FileUtils
import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification

class AliceTest extends Specification {
    @Shared
            password = "password".chars
    @Shared
            badPassword = "badPassword".chars
    @Shared
            plainText = RandomStringUtils.randomAscii(16384).bytes
    @Shared
            inputFileName = "input.dat"
    @Shared
            encryptedFileName = "encrypted.dat"
    @Shared
            decryptedFileName = "decrypted.dat"
    @Shared
            emptyFileName = "empty.dat"
    @Shared
            nonExistentFileName = "nonExistent.dat"
    @Shared
            invalidFileName = "invalid.dat"

    def "Instantiation throws an exception with null inputs and parameters"() {
        when:
        new Alice(input)

        then:
        thrown(expectedException)

        where:
        input                                                   || expectedException
        null                                                    || IllegalArgumentException
        new AliceContextBuilder().setAlgorithm(null).build()    || IllegalArgumentException
        new AliceContextBuilder().setMode(null).build()         || IllegalArgumentException
        new AliceContextBuilder().setPadding(null).build()      || IllegalArgumentException
        new AliceContextBuilder().setKeyLength(null).build()    || IllegalArgumentException
        new AliceContextBuilder().setPbkdf(null).build()        || IllegalArgumentException
        new AliceContextBuilder().setMacAlgorithm(null).build() || IllegalArgumentException
    }

    def "Instantiation throws an exception with invalid DES inputs"() {
        when:
        new Alice(new AliceContextBuilder().setAlgorithm(AliceContext.Algorithm.DES).setIvLength(1).build())

        then:
        thrown(IllegalArgumentException)
    }

    def "Instantiation throws an exception with invalid CBC/CTR inputs"() {
        when:
        new Alice(new AliceContextBuilder()
                .setAlgorithm(AliceContext.Algorithm.AES)
                .setMode(input)
                .setIvLength(1)
                .build())

        then:
        thrown(expectedException)

        where:
        input                 || expectedException
        AliceContext.Mode.CBC || IllegalArgumentException
        AliceContext.Mode.CTR || IllegalArgumentException
    }

    def "Instantiation throws an exception with invalid GCM inputs"() {
        when:
        new Alice(new AliceContextBuilder()
                .setAlgorithm(AliceContext.Algorithm.AES)
                .setMode(AliceContext.Mode.GCM)
                .setIvLength(ivLength)
                .setGcmTagLength(gcmTagLength)
                .build())

        then:
        thrown(expectedException)

        where:
        ivLength | gcmTagLength                      || expectedException
        -1       | null                              || IllegalArgumentException
        -1       | AliceContext.GcmTagLength.BITS_96 || IllegalArgumentException
        0        | null                              || IllegalArgumentException
        0        | AliceContext.GcmTagLength.BITS_96 || IllegalArgumentException
        1        | null                              || IllegalArgumentException
    }

    def "Instantiation throws an exception with invalid PBKDF iterations"() {
        when:
        new Alice(new AliceContextBuilder()
                .setIterations(iterations)
                .build())

        then:
        thrown(expectedException)

        where:
        iterations || expectedException
        -1         || IllegalArgumentException
        0          || IllegalArgumentException
    }

    def "Byte encryption throws with invalid inputs"() {
        when:
        new Alice(new AliceContextBuilder().build()).encrypt(inputBytes as byte[], inputPassword as char[])

        then:
        thrown(expectedException)

        where:
        inputBytes  | inputPassword || expectedException
        null        | null          || IllegalArgumentException
        null        | new char[0]   || IllegalArgumentException
        null        | new char[1]   || IllegalArgumentException

        new byte[0] | null          || IllegalArgumentException
        new byte[0] | new char[0]   || IllegalArgumentException
        new byte[0] | new char[1]   || IllegalArgumentException

        new byte[1] | null          || IllegalArgumentException
        new byte[1] | new char[0]   || IllegalArgumentException
    }

    def "Byte decryption throws with invalid inputs"() {
        when:
        new Alice(new AliceContextBuilder().build()).decrypt(inputBytes as byte[], inputPassword as char[])

        then:
        thrown(expectedException)

        where:
        inputBytes  | inputPassword || expectedException
        null        | null          || IllegalArgumentException
        null        | new char[0]   || IllegalArgumentException
        null        | new char[1]   || IllegalArgumentException

        new byte[0] | null          || IllegalArgumentException
        new byte[0] | new char[0]   || IllegalArgumentException
        new byte[0] | new char[1]   || IllegalArgumentException

        new byte[1] | null          || IllegalArgumentException
        new byte[1] | new char[0]   || IllegalArgumentException
    }

    def "File encryption throws with invalid inputs"() {
        setup:
        def inputFile = new File(inputFileName)
        def emptyFile = new File(emptyFileName)
        def encryptedFile = new File(encryptedFileName)
        def nonExistentFile = new File(nonExistentFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)
        emptyFile.createNewFile()

        when:
        new Alice(new AliceContextBuilder().build()).encrypt(input as File, output as File, inputPassword)

        then:
        thrown(expectedException)

        cleanup:
        inputFile.delete()
        emptyFile.delete()
        encryptedFile.delete()
        nonExistentFile.delete()

        where:
        input                         | output                      | inputPassword || expectedException
        null                          | null                        | null          || IllegalArgumentException
        null                          | null                        | new char[0]   || IllegalArgumentException
        null                          | null                        | new char[1]   || IllegalArgumentException

        null                          | new File(encryptedFileName) | null          || IllegalArgumentException
        null                          | new File(encryptedFileName) | new char[0]   || IllegalArgumentException
        null                          | new File(encryptedFileName) | new char[1]   || IllegalArgumentException

        new File(nonExistentFileName) | null                        | null          || IllegalArgumentException
        new File(nonExistentFileName) | null                        | new char[0]   || IllegalArgumentException
        new File(nonExistentFileName) | null                        | new char[1]   || IllegalArgumentException

        new File(nonExistentFileName) | new File(encryptedFileName) | null          || IllegalArgumentException
        new File(nonExistentFileName) | new File(encryptedFileName) | new char[0]   || IllegalArgumentException
        new File(nonExistentFileName) | new File(encryptedFileName) | new char[1]   || IllegalArgumentException

        new File(emptyFileName)       | null                        | null          || IllegalArgumentException
        new File(emptyFileName)       | null                        | new char[0]   || IllegalArgumentException
        new File(emptyFileName)       | null                        | new char[1]   || IllegalArgumentException

        new File(emptyFileName)       | new File(encryptedFileName) | null          || IllegalArgumentException
        new File(emptyFileName)       | new File(encryptedFileName) | new char[0]   || IllegalArgumentException
        new File(emptyFileName)       | new File(encryptedFileName) | new char[1]   || IllegalArgumentException

        new File(inputFileName)       | null                        | null          || IllegalArgumentException
        new File(inputFileName)       | null                        | new char[0]   || IllegalArgumentException
        new File(inputFileName)       | null                        | new char[1]   || IllegalArgumentException

        new File(inputFileName)       | new File(encryptedFileName) | null          || IllegalArgumentException
        new File(inputFileName)       | new File(encryptedFileName) | new char[0]   || IllegalArgumentException
    }

    def "File decryption throws with invalid inputs"() {
        setup:
        def inputFile = new File(inputFileName)
        def emptyFile = new File(emptyFileName)
        def invalidFile = new File(invalidFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)
        FileUtils.writeByteArrayToFile(invalidFile, "0".bytes)

        emptyFile.createNewFile()

        new Alice(new AliceContextBuilder().build()).encrypt(inputFile, encryptedFile, password)

        when:
        new Alice(new AliceContextBuilder().build()).decrypt(input as File, output as File, inputPassword)

        then:
        thrown(expectedException)

        cleanup:
        inputFile.delete()
        emptyFile.delete()
        invalidFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()

        where:
        input                         | output                      | inputPassword || expectedException
        null                          | null                        | null          || IllegalArgumentException
        null                          | null                        | new char[0]   || IllegalArgumentException
        null                          | null                        | new char[1]   || IllegalArgumentException

        null                          | new File(decryptedFileName) | null          || IllegalArgumentException
        null                          | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
        null                          | new File(decryptedFileName) | new char[1]   || IllegalArgumentException

        new File(nonExistentFileName) | null                        | null          || IllegalArgumentException
        new File(nonExistentFileName) | null                        | new char[0]   || IllegalArgumentException
        new File(nonExistentFileName) | null                        | new char[1]   || IllegalArgumentException

        new File(nonExistentFileName) | new File(decryptedFileName) | null          || IllegalArgumentException
        new File(nonExistentFileName) | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
        new File(nonExistentFileName) | new File(decryptedFileName) | new char[1]   || IllegalArgumentException

        new File(emptyFileName)       | null                        | null          || IllegalArgumentException
        new File(emptyFileName)       | null                        | new char[0]   || IllegalArgumentException
        new File(emptyFileName)       | null                        | new char[1]   || IllegalArgumentException

        new File(emptyFileName)       | new File(decryptedFileName) | null          || IllegalArgumentException
        new File(emptyFileName)       | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
        new File(emptyFileName)       | new File(decryptedFileName) | new char[1]   || IllegalArgumentException

        new File(invalidFileName)     | null                        | null          || IllegalArgumentException
        new File(invalidFileName)     | null                        | new char[0]   || IllegalArgumentException
        new File(invalidFileName)     | null                        | new char[1]   || IllegalArgumentException

        new File(invalidFileName)     | new File(decryptedFileName) | null          || IllegalArgumentException
        new File(invalidFileName)     | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
        new File(invalidFileName)     | new File(decryptedFileName) | new char[1]   || IOException

        new File(encryptedFileName)   | null                        | null          || IllegalArgumentException
        new File(encryptedFileName)   | null                        | new char[0]   || IllegalArgumentException
        new File(encryptedFileName)   | null                        | new char[1]   || IllegalArgumentException

        new File(encryptedFileName)   | new File(decryptedFileName) | null          || IllegalArgumentException
        new File(encryptedFileName)   | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
    }

    def "Stream encryption throws with invalid inputs"() {
        when:
        Alice alice = new Alice(new AliceContextBuilder().setMacAlgorithm(mac).build())
        alice.encrypt(inputStream as InputStream, outputStream as OutputStream, inputPassword)

        then:
        thrown(expectedException)

        where:
        inputStream                | outputStream                | inputPassword | mac                                    || expectedException
        null                       | null                        | null          | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | null          | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | null                        | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | null                        | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | null                        | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | null                        | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | null                        | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | null                        | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException
    }

    def "Stream decryption throws with invalid inputs"() {
        when:
        Alice alice = new Alice(new AliceContextBuilder().setMacAlgorithm(mac).build())
        alice.decrypt(inputStream as InputStream, outputStream as OutputStream, inputPassword)

        then:
        thrown(expectedException)

        where:
        inputStream                | outputStream                | inputPassword | mac                                    || expectedException
        null                       | null                        | null          | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | null          | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | null                        | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | null                        | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | null                        | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        null                       | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        null                       | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | null                        | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | null                        | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | null                        | new char[1]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | null                        | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.NONE         || IllegalArgumentException
        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[0]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException

        new ByteArrayInputStream() | new ByteArrayOutputStream() | new char[1]   | AliceContext.MacAlgorithm.HMAC_SHA_512 || IllegalArgumentException
    }

    def "Generate key throws with invalid arguments"() {
        when:
        Alice.generateKey(algorithm, keyLength)

        then:
        thrown(expectedException)

        where:
        algorithm                  | keyLength                      || expectedException
        null                       | null                           || IllegalArgumentException
        null                       | AliceContext.KeyLength.BITS_64 || IllegalArgumentException
        AliceContext.Algorithm.AES | null                           || IllegalArgumentException
    }

    def "Generate key returns keys of expected length"() {
        expect:
        Alice.generateKey(algorithm, keyLength).length == outputLength

        where:
        algorithm                  | keyLength                       || outputLength
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_128 || AliceContext.KeyLength.BITS_128.bytes()
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_192 || AliceContext.KeyLength.BITS_192.bytes()
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_256 || AliceContext.KeyLength.BITS_256.bytes()

        AliceContext.Algorithm.DES | AliceContext.KeyLength.BITS_64  || AliceContext.KeyLength.BITS_64.bytes()
    }

    def "AES CBC/CTR bytes encryption"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "AES GCM bytes encryption"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length *
                gcmTagLengths.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length * gcmTagLengths.length) % pbkdfs.length
            int cidx = i.intdiv(gcmTagLengths.length) % macAlgorithms.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "AES CBC/CTR file encryption"() {
        setup:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .build())

            alice.encrypt(inputFile, encryptedFile, password)
            alice.decrypt(encryptedFile, decryptedFile, password)

            success &= Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))
        }

        then:
        success

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "AES GCM file encryption"() {
        setup:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length *
                gcmTagLengths.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length * gcmTagLengths.length) % pbkdfs.length
            int cidx = i.intdiv(gcmTagLengths.length) % macAlgorithms.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            alice.encrypt(inputFile, encryptedFile, password)
            alice.decrypt(encryptedFile, decryptedFile, password)

            success &= Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))
        }

        then:
        success

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "AES CBC/CTR stream encryption"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(16)
                    .build())

            ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
            alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
            alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, password)

            byte[] decryptedBytes = decryptedStream.toByteArray()

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "AES GCM stream encryption"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                gcmTagLengths.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(gcmTagLengths.length) % pbkdfs.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
            alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
            alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, password)

            byte[] decryptedBytes = decryptedStream.toByteArray()

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "AES CBC/CTR bytes encryption fails with invalid password"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "AES GCM bytes encryption fails with invalid password"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length *
                gcmTagLengths.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length * gcmTagLengths.length) % pbkdfs.length
            int cidx = i.intdiv(gcmTagLengths.length) % macAlgorithms.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "AES CBC/CTR file encryption fails with invalid password"() {
        setup:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .build())

            try {
                alice.encrypt(inputFile, encryptedFile, password)
                alice.decrypt(encryptedFile, decryptedFile, badPassword)

                if (!Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "AES GCM file encryption fails with invalid password"() {
        setup:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length *
                gcmTagLengths.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length * gcmTagLengths.length) % pbkdfs.length
            int cidx = i.intdiv(gcmTagLengths.length) % macAlgorithms.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            try {
                alice.encrypt(inputFile, encryptedFile, password)
                alice.decrypt(encryptedFile, decryptedFile, badPassword)

                if (!Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "AES CBC/CTR stream encryption fails with invalid password"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(16)
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "AES GCM stream encryption fails with invalid password"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.GCM]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.GcmTagLength[] gcmTagLengths = AliceContext.GcmTagLength.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                gcmTagLengths.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * gcmTagLengths.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * gcmTagLengths.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * gcmTagLengths.length) % keyLengths.length
            int bidx = i.intdiv(gcmTagLengths.length) % pbkdfs.length
            int gidx = i % gcmTagLengths.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.AES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(16)
                    .setGcmTagLength(gcmTagLengths[gidx])
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "DES CBC/CTR bytes encryption"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "DES CBC/CTR file encryption"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            alice.encrypt(inputFile, encryptedFile, password)
            alice.decrypt(encryptedFile, decryptedFile, password)

            success &= Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))
        }

        then:
        success

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }


    def "DES CBC/CTR stream encryption"() {
        setup:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(8)
                    .build())

            ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
            alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
            alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, password)

            byte[] decryptedBytes = decryptedStream.toByteArray()

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "DES CBC/CTR bytes encryption fails with invalid password"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "DES CBC/CTR file encryption fails with invalid password"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            try {
                alice.encrypt(inputFile, encryptedFile, password)
                alice.decrypt(encryptedFile, decryptedFile, badPassword)

                if (!Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "DES CBC/CTR stream encryption fails with invalid password"() {
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DES)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(8)
                    .build())

            try {
                ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
                alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

                ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
                alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, badPassword)

                byte[] decryptedBytes = decryptedStream.toByteArray()

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "3DES CBC/CTR bytes encryption"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "3DES CBC/CTR file encryption"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            alice.encrypt(inputFile, encryptedFile, password)
            alice.decrypt(encryptedFile, decryptedFile, password)

            success &= Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))
        }

        then:
        success

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "3DES CBC/CTR stream encryption"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(8)
                    .build())

            ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
            alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
            alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, password)

            byte[] decryptedBytes = decryptedStream.toByteArray()

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "3DES CBC/CTR bytes encryption fails with invalid password"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            try {
                byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), badPassword)

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }

    def "3DES CBC/CTR file encryption fails with invalid password"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length * macAlgorithms.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length * macAlgorithms.length) % keyLengths.length
            int bidx = i.intdiv(macAlgorithms.length) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .setIvLength(8)
                    .build())

            try {
                alice.encrypt(inputFile, encryptedFile, password)
                alice.decrypt(encryptedFile, decryptedFile, badPassword)

                if (!Arrays.equals(plainText, FileUtils.readFileToByteArray(decryptedFile))) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations

        cleanup:
        inputFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }

    def "3DES CBC/CTR stream encryption fails with invalid password"() {
        given:
        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_192]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        def totalIterations = modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int midx = i.intdiv(paddings.length * keyLengths.length * pbkdfs.length) % modes.length
            int pidx = i.intdiv(keyLengths.length * pbkdfs.length) % paddings.length
            int kidx = i.intdiv(pbkdfs.length) % keyLengths.length
            int bidx = i % pbkdfs.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(AliceContext.Algorithm.DESede)
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                    .setIvLength(8)
                    .build())

            try {
                ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream()
                alice.encrypt(new ByteArrayInputStream(plainText), encryptedStream, password)

                ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream()
                alice.decrypt(new ByteArrayInputStream(encryptedStream.toByteArray()), decryptedStream, badPassword)

                byte[] decryptedBytes = decryptedStream.toByteArray()

                if (!Arrays.equals(plainText, decryptedBytes)) {
                    failures++
                }
            } catch (ignored) {
                failures++
            }
        }

        then:
        failures == totalIterations
    }
}