package com.rockaport.alice

import com.rockaport.alice.AliceContext
import org.apache.commons.io.FileUtils
import spock.lang.Shared
import spock.lang.Specification

class AliceTest extends Specification {
    @Shared
            password = "password".chars
    @Shared
            badPassword = "badPassword".chars
    @Shared
            plainText = "Some message to ".bytes
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

    def "Throws exception with null inputs"() {
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
        new AliceContextBuilder().setMacAlgorithm(null).build() || IllegalArgumentException
        new AliceContextBuilder().setKeyLength(null).build()    || IllegalArgumentException
    }

    def "Byte encryption throws with invalid inputs"() {
        when:
        Alice alice = new Alice(new AliceContextBuilder().build())
        alice.encrypt(inputBytes as byte[], inputPassword as char[])

        then:
        thrown(expectedException)

        where:
        inputBytes  | inputPassword || expectedException
        new byte[0] | new char[0]   || IllegalArgumentException
        new byte[0] | new char[1]   || IllegalArgumentException
        new byte[1] | new char[0]   || IllegalArgumentException
        new byte[0] | null          || IllegalArgumentException
        null        | new char[0]   || IllegalArgumentException
        null        | null          || IllegalArgumentException
    }

    def "Byte decryption throws with invalid inputs"() {
        when:
        Alice alice = new Alice(new AliceContextBuilder().build())
        alice.decrypt(inputBytes as byte[], inputPassword as char[])

        then:
        thrown(expectedException)

        where:
        inputBytes  | inputPassword || expectedException
        new byte[0] | new char[0]   || IllegalArgumentException
        new byte[0] | new char[1]   || IllegalArgumentException
        new byte[1] | new char[0]   || IllegalArgumentException
        new byte[0] | null          || IllegalArgumentException
        null        | new char[0]   || IllegalArgumentException
        null        | null          || IllegalArgumentException
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
        new Alice(new AliceContextBuilder().build()).encrypt(input, output, inputPassword)

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
        null                          | new File(encryptedFileName) | new char[1]   || IllegalArgumentException
        new File(nonExistentFileName) | new File(encryptedFileName) | new char[1]   || IllegalArgumentException
        new File(emptyFileName)       | new File(encryptedFileName) | new char[1]   || IllegalArgumentException
        new File(inputFileName)       | null                        | null          || IllegalArgumentException
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
        new Alice(new AliceContextBuilder().build()).decrypt(input, output, inputPassword)

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
        null                          | new File(decryptedFileName) | new char[1]   || IllegalArgumentException
        new File(nonExistentFileName) | new File(decryptedFileName) | new char[1]   || IllegalArgumentException
        new File(emptyFileName)       | new File(decryptedFileName) | new char[1]   || IllegalArgumentException
        new File(encryptedFileName)   | null                        | null          || IllegalArgumentException
        new File(encryptedFileName)   | new File(decryptedFileName) | null          || IllegalArgumentException
        new File(encryptedFileName)   | new File(decryptedFileName) | new char[0]   || IllegalArgumentException
        new File(invalidFileName)     | new File(decryptedFileName) | new char[1]   || IOException
    }

    def "Invalid iterations throws exception"() {
        when:
        Alice alice = new Alice(new AliceContextBuilder()
                .setIterations(iterations)
                .build())

        alice.encrypt(plainText, password)

        then:
        thrown(expectedException)

        where:
        iterations || expectedException
        -1         || IllegalArgumentException
        0          || IllegalArgumentException
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

    def "Generate key"() {
        expect:
        Alice.generateKey(algorithm, keyLength).length == outputLength

        where:
        algorithm                  | keyLength                       || outputLength
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_128 || AliceContext.KeyLength.BITS_128.bytes()
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_192 || AliceContext.KeyLength.BITS_192.bytes()
        AliceContext.Algorithm.AES | AliceContext.KeyLength.BITS_256 || AliceContext.KeyLength.BITS_256.bytes()

        AliceContext.Algorithm.DES | AliceContext.KeyLength.BITS_64  || AliceContext.KeyLength.BITS_64.bytes()
    }

    def "AES bytes encryption"() {
        setup:
        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.AES]

        AliceContext.Mode[] modes = AliceContext.Mode.values()

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "AES file encryption"() {
        setup:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.AES]

        AliceContext.Mode[] modes = AliceContext.Mode.values()

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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

    def "AES bytes encryption fails with invalid password"() {
        given:
        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.AES]

        AliceContext.Mode[] modes = AliceContext.Mode.values()

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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

    def "AES file encryption fails with invalid password"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.AES]

        AliceContext.Mode[] modes = AliceContext.Mode.values()

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [
                AliceContext.KeyLength.BITS_128,
                AliceContext.KeyLength.BITS_192,
                AliceContext.KeyLength.BITS_256
        ]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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

    def "DES bytes encryption"() {
        given:
        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.DES]

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
                    .build())

            byte[] decryptedBytes = alice.decrypt(alice.encrypt(plainText, password), password)

            success &= Arrays.equals(plainText, decryptedBytes)
        }

        then:
        success
    }

    def "DES file encryption"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.DES]

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def success = true
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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

    def "DES bytes encryption fails with invalid password"() {
        given:
        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.DES]

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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

    def "DES file encryption fails with invalid password"() {
        given:
        def inputFile = new File(inputFileName)
        def encryptedFile = new File(encryptedFileName)
        def decryptedFile = new File(decryptedFileName)

        FileUtils.writeByteArrayToFile(inputFile, plainText)

        AliceContext.Algorithm[] algorithms = [AliceContext.Algorithm.DES]

        AliceContext.Mode[] modes = [AliceContext.Mode.CBC, AliceContext.Mode.CTR]

        AliceContext.Padding[] paddings = AliceContext.Padding.values()

        AliceContext.KeyLength[] keyLengths = [AliceContext.KeyLength.BITS_64]

        AliceContext.Pbkdf[] pbkdfs = AliceContext.Pbkdf.values()

        AliceContext.MacAlgorithm[] macAlgorithms = AliceContext.MacAlgorithm.values()

        def totalIterations = algorithms.length *
                modes.length *
                paddings.length *
                keyLengths.length *
                pbkdfs.length *
                macAlgorithms.length

        when:
        def failures = 0
        for (int i = 0; i < totalIterations; i++) {
            int aidx = ((int) i / (modes.length * paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % algorithms.length
            int midx = ((int) i / (paddings.length * keyLengths.length * pbkdfs.length * macAlgorithms.length)) % modes.length
            int pidx = ((int) i / (keyLengths.length * pbkdfs.length * macAlgorithms.length)) % paddings.length
            int kidx = ((int) i / (pbkdfs.length * macAlgorithms.length)) % keyLengths.length
            int bidx = ((int) i / (macAlgorithms.length)) % pbkdfs.length
            int cidx = i % macAlgorithms.length

            Alice alice = new Alice(new AliceContextBuilder()
                    .setAlgorithm(algorithms[aidx])
                    .setMode(modes[midx])
                    .setPadding(paddings[pidx])
                    .setKeyLength(keyLengths[kidx])
                    .setPbkdf(pbkdfs[bidx])
                    .setMacAlgorithm(macAlgorithms[cidx])
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
}