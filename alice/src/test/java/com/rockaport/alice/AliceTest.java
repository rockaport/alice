package com.rockaport.alice;

import okio.ByteString;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class AliceTest {
    private static final char[] password = "somePassword".toCharArray();
    private static final char[] badPassword = "someBadPassword".toCharArray();

    private static final ByteString message = ByteString.encodeUtf8("Some message to ");

    private String emptyFileName = "empty.dat";
    private String originalFileName = "original.dat";
    private String encryptedFileName = "encrypted.dat";
    private String decryptedFileName = "decrypted.dat";
    private File emptyFile, originalFile, encryptedFile, decryptedFile;

    @BeforeEach
    public void beforeEach() throws Exception {
        emptyFile = new File(emptyFileName);
        originalFile = new File(originalFileName);
        encryptedFile = new File(encryptedFileName);
        decryptedFile = new File(decryptedFileName);

        if (!emptyFile.exists() && !emptyFile.createNewFile()) {
            throw new RuntimeException("Unable to create empty file");
        }

        FileUtils.writeStringToFile(originalFile, message.utf8(), StandardCharsets.UTF_8);
    }

    @AfterEach
    public void afterEach() throws Exception {
        if (emptyFile.exists() && !emptyFile.delete()) {
            throw new RuntimeException("Unable to delete empty file");
        }
        if (originalFile.exists() && !originalFile.delete()) {
            throw new RuntimeException("Unable to delete original file");
        }
        if (encryptedFile.exists() && !encryptedFile.delete()) {
            throw new RuntimeException("Unable to delete encrypted file");
        }
        if (decryptedFile.exists() && !decryptedFile.delete()) {
            throw new RuntimeException("Unable to delete decrypted file");
        }
    }

    @Nested
    @DisplayName("Instantiation")
    class Instantiation {
        @Test
        @DisplayName("Null context")
        void nullContext(TestInfo testInfo) {
            assertAll("Instantiation should throw with null context",
                    () -> assertThrows(RuntimeException.class, () -> new Alice(null)));
        }

        @Test
        @DisplayName("Null algorithm")
        void nullAlgorithm(TestInfo testInfo) {
            assertAll("Instantiation should throw with null algorithm",
                    () -> assertThrows(RuntimeException.class, () -> new Alice(new AliceContextBuilder().setAlgorithm(null).build())));
        }

        @Test
        @DisplayName("Null mode")
        void nullMode(TestInfo testInfo) {
            assertAll("Instantiation should throw with null mode",
                    () -> assertThrows(RuntimeException.class, () -> new Alice(new AliceContextBuilder().setMode(null).build())));
        }

        @Test
        @DisplayName("Null padding")
        void nullPadding(TestInfo testInfo) {
            assertAll("Instantiation should throw with null padding",
                    () -> assertThrows(RuntimeException.class, () -> new Alice(new AliceContextBuilder().setPadding(null).build())));
        }
    }

    @Nested
    @DisplayName("AES bytes")
    class AesBytes {
        @Nested
        @DisplayName("Bad arguments")
        class BadArguments {
            @Test
            @DisplayName("Bad iterations (0)")
            void badIterations(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setIterations(0)
                        .build());

                assertThrows(RuntimeException.class, () -> alice.decrypt(alice.encrypt(message.toByteArray(), password), password));
            }

            @Nested
            @DisplayName("Bad password")
            class BadPassword {
                @Test
                @DisplayName("null")
                void badPasswordNull(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on null password",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(message.toByteArray(), null)),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(message.toByteArray(), null)));
                }

                @Test
                @DisplayName("empty")
                void badPasswordEmpty(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on empty password",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(message.toByteArray(), new char[]{})),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(message.toByteArray(), new char[]{})));
                }
            }

            @Nested
            @DisplayName("Bad input")
            class BadInput {
                @Test
                @DisplayName("null")
                void badInputNull(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on null input",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(null, password)),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(null, password)));
                }

                @Test
                @DisplayName("empty")
                void badInputEmpty(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on empty input",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(new byte[]{}, password)),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(new byte[]{}, password)));
                }
            }
        }

        @Nested
        @DisplayName("CTR")
        class Ctr {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCtrNoPadding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesCtrNoPadding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesCtrNoPadding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesCtrPKCS5Padding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesCtrPKCS5Padding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesCtrPKCS5Padding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }
        }

        @Nested
        @DisplayName("CBC")
        class Cbc {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCbcNoPadding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesCbcNoPadding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesCbcNoPadding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesCbcPKCS5Padding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesCbcPKCS5Padding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesCbcPKCS5Padding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }
        }

        @Nested
        @DisplayName("GCM")
        class Gcm {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCbcNoPadding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesGcmNoPadding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesGcmNoPadding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesGcmPKCS5Padding128(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("192")
                void aesGcmPKCS5Padding192(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }

                @Test
                @DisplayName("256")
                void aesGcmPKCS5Padding256(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                    assertEquals(message.utf8(), decryptedMessage.utf8());
                }
            }
        }
    }

    @Nested
    @DisplayName("Key derivation")
    class Pbkdf {
        @Test
        @DisplayName("None")
        void none(TestInfo testInfo) {
            Alice alice = new Alice(new AliceContextBuilder()
                    .setPbkdf(AliceContext.Pbkdf.NONE)
                    .build());

            ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

            assertEquals(message.utf8(), decryptedMessage.utf8());
        }

        @Nested
        @DisplayName("SHA")
        class Sha {
            @Test
            @DisplayName("SHA 1")
            void sha1(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.SHA_1)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("SHA 224")
            void sha224(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.SHA_224)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("SHA 256")
            void sha256(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.SHA_256)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("SHA 384")
            void sha384(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.SHA_384)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("SHA 512")
            void sha512(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.SHA_512)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }
        }

        @Nested
        @DisplayName("PBKDF2")
        class Pbkdf2 {
            @Test
            @DisplayName("PBKDF2WithHmacSHA1")
            void pbkdf2sha1(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_1)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("PBKDF2WithHmacSHA256")
            void pbkdf2sha256(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_256)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("PBKDF2WithHmacSHA384")
            void pbkdf2sha384(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_384)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("PBKDF2WithHmacSHA512")
            void pbkdf2sha512(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setPbkdf(AliceContext.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }
        }
    }

    @Nested
    @DisplayName("AES file")
    class AesFile {
        @Nested
        @DisplayName("Bad arguments")
        class BadArguments {
            @Test
            @DisplayName("Bad iterations (0)")
            void badIterations(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setIterations(0)
                        .build());

                assertAll("Encryption and decryption should throw on null password",
                        () -> assertThrows(RuntimeException.class, () -> alice.encrypt(originalFile, encryptedFile, password)),
                        () -> assertThrows(RuntimeException.class, () -> alice.decrypt(encryptedFile, decryptedFile, password)));
            }

            @Nested
            @DisplayName("Bad password")
            class BadPassword {
                @Test
                @DisplayName("null")
                void badPasswordNull(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on null password",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(originalFile, encryptedFile, null)),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(encryptedFile, decryptedFile, null)));
                }

                @Test
                @DisplayName("empty")
                void badPasswordEmpty(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on empty password",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(originalFile, encryptedFile, new char[]{})),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(encryptedFile, decryptedFile, new char[]{})));
                }
            }

            @Nested
            @DisplayName("Bad input")
            class BadInput {
                @Test
                @DisplayName("null")
                void badInputNull(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on null input",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(null, null, password)),
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(originalFile, null, password)),
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(null, encryptedFile, password)));
                }

                @Test
                @DisplayName("empty")
                void badInputEmpty(TestInfo testInfo) {
                    Alice alice = new Alice(new AliceContextBuilder().build());

                    assertAll("Encryption and decryption should throw on empty input",
                            () -> assertThrows(RuntimeException.class, () -> alice.encrypt(emptyFile, encryptedFile, password)),
                            () -> assertThrows(RuntimeException.class, () -> alice.decrypt(emptyFile, decryptedFile, password)));
                }
            }
        }

        @Nested
        @DisplayName("CTR")
        class Ctr {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCtrNoPadding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesCtrNoPadding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesCtrNoPadding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesCtrPKCS5Padding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesCtrPKCS5Padding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesCtrPKCS5Padding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CTR)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }
        }

        @Nested
        @DisplayName("CBC")
        class Cbc {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCbcNoPadding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesCbcNoPadding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesCbcNoPadding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesCbcPKCS5Padding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesCbcPKCS5Padding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesCbcPKCS5Padding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.CBC)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }
        }

        @Nested
        @DisplayName("GCM")
        class Gcm {
            @Nested
            @DisplayName("NoPadding")
            class NoPadding {
                @Test
                @DisplayName("128")
                void aesCbcNoPadding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesGcmNoPadding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesGcmNoPadding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.NO_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }

            @Nested
            @DisplayName("PKCS5Padding")
            class Pkcs5Padding {
                @Test
                @DisplayName("128")
                void aesGcmPKCS5Padding128(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_128)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("192")
                void aesGcmPKCS5Padding192(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_192)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }

                @Test
                @DisplayName("256")
                void aesGcmPKCS5Padding256(TestInfo testInfo) throws IOException {
                    Alice alice = new Alice(new AliceContextBuilder()
                            .setAlgorithm(AliceContext.Algorithm.AES)
                            .setMode(AliceContext.Mode.GCM)
                            .setPadding(AliceContext.Padding.PKCS5_PADDING)
                            .setKeyLength(AliceContext.KeyLength.BITS_256)
                            .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                            .build());

                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, password);

                    assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                            FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
                }
            }
        }
    }

    @Nested
    @DisplayName("Message authentication")
    class MessageAuthentication {
        @Test
        @DisplayName("Null MAC algorithm and/or password")
        void nullMacAndPassword(TestInfo testInfo) {
            assertAll("getMac should throw on null algorithm and/or password",
                    () -> assertThrows(RuntimeException.class, () -> Alice.getMac(null, password)),
                    () -> assertThrows(RuntimeException.class, () -> Alice.getMac(AliceContext.MacAlgorithm.HMAC_SHA_1, null)),
                    () -> assertThrows(RuntimeException.class, () -> Alice.getMac(null, null)));
        }

        @Nested
        @DisplayName("Bytes")
        class Bytes {
            @Test
            @DisplayName("None")
            void none(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("HmacSHA1")
            void hmacSha1(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_1)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("HmacSHA256")
            void hmacSha256(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_256)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("HmacSHA384")
            void hmacSha384(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_384)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("HmacSHA512")
            void hmacSha512(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_512)
                        .build());

                ByteString decryptedMessage = ByteString.of(alice.decrypt(alice.encrypt(message.toByteArray(), password), password));

                assertEquals(message.utf8(), decryptedMessage.utf8());
            }

            @Test
            @DisplayName("Bad message authentication")
            void badMac(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_512)
                        .build());

                assertThrows(RuntimeException.class, () -> alice.decrypt(alice.encrypt(message.toByteArray(), password), badPassword));
            }
        }

        @Nested
        @DisplayName("File")
        class Files {
            @Test
            @DisplayName("None")
            void none(TestInfo testInfo) throws IOException {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.NONE)
                        .build());

                alice.encrypt(originalFile, encryptedFile, password);
                alice.decrypt(encryptedFile, decryptedFile, password);

                assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                        FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
            }

            @Test
            @DisplayName("HmacSHA1")
            void hmacSha1(TestInfo testInfo) throws IOException {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_1)
                        .build());

                alice.encrypt(originalFile, encryptedFile, password);
                alice.decrypt(encryptedFile, decryptedFile, password);

                assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                        FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
            }

            @Test
            @DisplayName("HmacSHA256")
            void hmacSha256(TestInfo testInfo) throws IOException {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_256)
                        .build());

                alice.encrypt(originalFile, encryptedFile, password);
                alice.decrypt(encryptedFile, decryptedFile, password);

                assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                        FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
            }

            @Test
            @DisplayName("HmacSHA384")
            void hmacSha384(TestInfo testInfo) throws IOException {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_384)
                        .build());

                alice.encrypt(originalFile, encryptedFile, password);
                alice.decrypt(encryptedFile, decryptedFile, password);

                assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                        FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
            }

            @Test
            @DisplayName("HmacSHA512")
            void hmacSha512(TestInfo testInfo) throws IOException {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_512)
                        .build());

                alice.encrypt(originalFile, encryptedFile, password);
                alice.decrypt(encryptedFile, decryptedFile, password);

                assertEquals(FileUtils.readFileToString(originalFile, StandardCharsets.UTF_8),
                        FileUtils.readFileToString(decryptedFile, StandardCharsets.UTF_8));
            }

            @Test
            @DisplayName("Bad message authentication")
            void badMac(TestInfo testInfo) {
                Alice alice = new Alice(new AliceContextBuilder()
                        .setMacAlgorithm(AliceContext.MacAlgorithm.HMAC_SHA_512)
                        .build());

                assertThrows(RuntimeException.class, () -> {
                    alice.encrypt(originalFile, encryptedFile, password);
                    alice.decrypt(encryptedFile, decryptedFile, badPassword);
                });
            }
        }
    }

    @Nested
    @DisplayName("AES Key generator")
    class KeyGenerator {
        @Test
        @DisplayName("128")
        void generateKey128(TestInfo testInfo) {
            byte[] key = Alice.generateKey(AliceContext.KeyLength.BITS_128);

            assertEquals(key.length, AliceContext.KeyLength.BITS_128.bytes());
        }

        @Test
        @DisplayName("192")
        void generateKey192(TestInfo testInfo) {
            byte[] key = Alice.generateKey(AliceContext.KeyLength.BITS_192);

            assertEquals(key.length, AliceContext.KeyLength.BITS_192.bytes());
        }

        @Test
        @DisplayName("256")
        void generateKey256(TestInfo testInfo) {
            byte[] key = Alice.generateKey(AliceContext.KeyLength.BITS_256);

            assertEquals(key.length, AliceContext.KeyLength.BITS_256.bytes());
        }

        @Test
        @DisplayName("Null key")
        void nullKey(TestInfo testInfo) {
            assertThrows(RuntimeException.class, () -> Alice.generateKey(null));
        }
    }
}
