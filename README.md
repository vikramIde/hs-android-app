# HypersignWalletCoreKotlin

This repository will dictate the best practises in terms of security for implementing Hypersign Mobile Wallet

## Using android Keystore


### Importing keystore

```Kotlin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

```

### Create Instance of keystore


```Kotlin
val KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore")

val KeyGenParameterSpec = KeyGenParameterSpec.Builder("HypersignKeyAllias",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()

KeyGenerator.init(KeyGenParameterSpec)
KeyGenerator.generateKey()


```

### GetKey string using keystore instance


```Kotlin
fun getKey(): SecretKey {
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)

        val secretKeyEntry = keystore.getEntry("HypersignKeyAllias", null) as KeyStore.SecretKeyEntry
        return secretKeyEntry.secretKey
}

```

### Encrypt string using keystore instance


```java
fun encryptData(data: String): Pair<ByteArray, ByteArray> {
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")

    var temp = data
    while (temp.toByteArray().size % 16 != 0)
        temp += "\u0020"

    cipher.init(Cipher.ENCRYPT_MODE, getKey())

    val ivBytes = cipher.iv
    val encryptedBytes = cipher.doFinal(temp.toByteArray(Charsets.UTF_8))

    return Pair(ivBytes, encryptedBytes)
}
```



### DeCrypt string using keystore instance


```Kotlin
fun decryptData(ivBytes: ByteArray, data: ByteArray): String{
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        val spec = IvParameterSpec(ivBytes)

        cipher.init(Cipher.DECRYPT_MODE, getKey(), spec)
        return cipher.doFinal(data).toString(Charsets.UTF_8).trim()
    }
```

### Reference

- https://medium.com/@josiassena/using-the-android-keystore-system-to-store-sensitive-information-3a56175a454b
- https://gist.github.com/JosiasSena/3bf4ca59777f7dedcaf41a495d96d984
- https://github.com/android/security-samples/tree/master/BiometricAuthentication/#readme
- https://developer.android.com/training/articles/keystore#kotlin
- https://github.com/tlarsin/AndroidKeyStoreEncryption
