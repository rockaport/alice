[![Circle
CI](https://circleci.com/gh/rockaport/alice.svg?style=shield)](https://circleci.com/gh/rockaport/alice)
[![Build Status](https://travis-ci.org/rockaport/alice.svg?branch=master)](https://travis-ci.org/rockaport/alice)
[![Release](https://jitpack.io/v/rockaport/alice.svg)](https://jitpack.io/#rockaport/alice)
[![codecov](https://codecov.io/gh/rockaport/alice/branch/master/graph/badge.svg)](https://codecov.io/gh/rockaport/alice)

# alice
Alice is a Java AES encryption library for working with byte arrays, files, and streams. Various key lengths, block modes, padding schemes, key deriviation functions, and Message Authentication Codes (MAC) are available. See the [javadoc](https://rockaport.github.io/alice) for more information.

Alice provides an easy wrapper around the javax.crypto cipher suite for symmetric key encryption. if a MAC algorithm is selected, additional [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) is performed using an [encrypt-then-mac](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_.28EtM.29) scheme.

![Data Structure](https://cloud.githubusercontent.com/assets/5369654/23003382/82fa26d0-f3be-11e6-8128-ce2ef6f71957.png)

Algorithms
- AES
- DES
- DESede (3DES)

Modes
- CBC (AES & DES & DESede)
- CTR (AES & DES & DESede)
- GCM (AES)

Padding
- NoPadding
- PKCS5Padding

Key Lengths (in bits)
- 64 (DES)
- 128 (AES)
- 192 (AES & DESede)
- 256 (AES)

Password Based Key Derivation Functions (PBKDF)
- None (use password as is, zero padded if necessary)
- SHA-{1, 224, 256, 384, 512} (hashes the password before use)
- PBKDF2WithHmacSHA{1, 256, 384, 512} (derives the key using a password-based key-derivation algorithm)

MAC Algorithm (Authenticated Encryption)
- None
- HmacSHA{1, 256, 384, 512}

IV Length
- 8 (DES & DESede)
- 16 (AES-CBC/CTR mode)
- Varies (GCM)

GCM Tag Length (in bits)
- 96
- 104
- 112
- 120
- 128

Iterations (used when the PBKDF = PBKDF2WithHmacSHA{Length})
- Varies

# Download
The easist way is to use [jitpack](https://jitpack.io/#rockaport/alice)

# Usage
## Initialization
```java
// Initialize an Alice instance with defaults:
// Cipher = AES/256/CTR/NoPadding
// Key Derivation = PBKDF2WithHmacSHA512/Iterations(10000)
// MAC = HmacSHA512
Alice alice = new Alice(new AliceContextBuilder().build());
```

### AES-CBC or CTR context initialization
```java
AliceContext aliceContext = new AliceContextBuilder()
        .setAlgorithm(AliceContext.Algorithm.AES)
        .setMode(AliceContext.Mode.CBC) // or AliceContext.Mode.CTR
        .setIvLength(16)
        .build()
```

### AES-GCM Context Initialization
```java
AliceContext aliceContext = new AliceContextBuilder()
        .setAlgorithm(AliceContext.Algorithm.AES)
        .setMode(AliceContext.Mode.GCM)
        .setIvLength(ivLength) // e.g. 12
        .setGcmTagLength(AliceContext.GcmTagLength.BITS_128)
        .build()
```

### DES-CBC or CTR Context Initialization
```java
AliceContext aliceContext = new AliceContextBuilder()
        .setAlgorithm(AliceContext.Algorithm.DES)
        .setMode(AliceContext.Mode.CBC) // or AliceContext.Mode.CTR
        .setIvLength(8)
        .build()
```

### 3DES-CBC or CTR Context Initialization
```java
AliceContext aliceContext = new AliceContextBuilder()
        .setAlgorithm(AliceContext.Algorithm.DESede)
        .setMode(AliceContext.Mode.CBC) // or AliceContext.Mode.CTR
        .setIvLength(8)
        .build()
```

## Encryption
After you've created an Alice instance with the desired context you can encrypt/decrypt byte arrays and files as shown. See the unit tests for more detailed usage and options.

### Working with byte arrays
```java
byte[] encryptedBytes = alice.encrypt(input, password);

byte[] decryptedBytes = alice.decrypt(encryptedBytes, password);
```

### Working with files
```java
alice.encrypt(inputFile, encryptedFile, password);

alice.decrypt(encryptedFile, decryptedFile, password);
```

### Working with streams
Note: Streaming encryption does not support authenticated encryption. You must set the mac algorithm to AliceContext.MacAlgorithm.NONE
```java
alice.encrypt(inputStream, encryptedStream, password);

alice.decrypt(encryptedStream, decryptedStream, password);
```
