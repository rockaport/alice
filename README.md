[![Circle
CI](https://circleci.com/gh/rockaport/alice.svg?style=shield)](https://circleci.com/gh/rockaport/alice)

# alice
Java AES encryption library for working with byte arrays and files. Various key lengths, block modes, padding schemes, key deriviation functions, and Message Authentication Codes (MAC) are available. See the [javadoc](https://rockaport.github.io/alice) for more information.

# Download
The easist way is to use [jitpack](https://jitpack.io/#rockaport/alice/0.2.0)

## Initialization
```java
// Initialize an Alice instance with defaults:
// Cipher = AES/256/CTR/NoPadding
// Key Derivation = PBKDF2WithHmacSHA512/Iterations(10000)
// MAC = HmacSHA512
Alice alice = new Alice(new AliceContextBuilder().build());
```

## Working with byte arrays
```java
byte[] encryptedBytes = alice.encrypt(input, password);

byte[] decryptedBytes = alice.decrypt(encryptedBytes, password);
```

## Working with files
```java
alice.encrypt(inputFile, encryptedFile, password);

alice.decrypt(encryptedFile, decryptedFile, password);
```
