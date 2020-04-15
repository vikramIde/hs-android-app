package com.example.android.biometricauth

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.BLOCK_MODE_CBC
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_PKCS7
import android.security.keystore.KeyProperties.KEY_ALGORITHM_AES
import android.util.Base64
import android.util.Log
import android.widget.Toast
import java.io.IOException
import java.security.*

import java.security.cert.CertificateException
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec


class CryptoUtils(val android_key: String): ICryptoUtils {

    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator

    fun setupKeyStoreAndKeyGenerator() {
        try {
            keyStore = KeyStore.getInstance(android_key)
            Log.e(android_key, "Android keystore name")

        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore", e)
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM_AES, android_key)
            Log.e("KeyGenLog", "perfectly initialized")

        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchProviderException ->
                    throw RuntimeException("Failed to get an instance of KeyGenerator", e)
                else -> throw e
            }
        }
    }

    fun setupCiphers(): Pair<Cipher, Cipher> {
        val defaultCipher: Cipher
        val cipherNotInvalidated: Cipher
        try {
            val cipherString = "$KEY_ALGORITHM_AES/$BLOCK_MODE_CBC/$ENCRYPTION_PADDING_PKCS7"
            defaultCipher = Cipher.getInstance(cipherString)
            cipherNotInvalidated = Cipher.getInstance(cipherString)
            Log.e("defaultCipher", cipherNotInvalidated.toString())

        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchPaddingException ->
                    throw RuntimeException("Failed to get an instance of Cipher", e)
                else -> throw e
            }
        }
        return Pair(defaultCipher, cipherNotInvalidated)
    }

    fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of enrolled
        // fingerprints has changed.
        try {
            keyStore.load(null)

            val keyProperties = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            val builder = KeyGenParameterSpec.Builder(keyName, keyProperties)
                    .setBlockModes(BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(false)
                    .setEncryptionPaddings(ENCRYPTION_PADDING_PKCS7)
                    .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)

            keyGenerator.run {
                init(builder.build())
                generateKey()
            }
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is InvalidAlgorithmParameterException,
                is CertificateException,
                is IOException -> throw RuntimeException(e)
                else -> throw e
            }
        }
    }
    
    private fun initCipher(cipher: Cipher, keyName: String, cipherMode: Int, password: CharArray): Boolean {
        try {
            keyStore.load(null)
            if(cipherMode === 0){
                cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(keyName, password) as SecretKey)
            }else{
                val spec = IvParameterSpec(cipher.iv)
                cipher.init(Cipher.DECRYPT_MODE, keyStore.getKey(DEFAULT_KEY_NAME, null) as SecretKey, spec)
            }

            return true
        } catch (e: Exception) {
            when (e) {
                is KeyPermanentlyInvalidatedException -> return false
                is KeyStoreException,
                is CertificateException,
                is UnrecoverableKeyException,
                is IOException,
                is NoSuchAlgorithmException,
                is InvalidKeyException -> throw RuntimeException("Failed to init Cipher", e)
                else -> throw e
            }
        }
    }

    override fun init() : Pair<Cipher, Cipher>{
        this.setupKeyStoreAndKeyGenerator()
        this.setupCiphers()
        val (defaultCipher: Cipher, cipherNotInvalidated: Cipher) = this.setupCiphers()
        this.createKey(DEFAULT_KEY_NAME, false)
        return Pair(defaultCipher, cipherNotInvalidated)
    }

    override fun tryEncrypt(message: String, cipher: Cipher, password: CharArray) : Pair<ByteArray, ByteArray> {


//        try {
//            initCipher(cipher, DEFAULT_KEY_NAME, Cipher.ENCRYPT_MODE)
//            text = Base64.encodeToString(cipher.doFinal(message.toByteArray()), 0 /* flags */)
//            ivBytes = cipher.iv
//
//        } catch (e: Exception) {
//            when (e) {
//                is BadPaddingException,
//                is IllegalBlockSizeException -> {
//                    Log.e("TAG", "Failed to encrypt the data with the generated key. ${e.message}")
//                }
//                else -> throw e
//            }
//        }

        initCipher(cipher, DEFAULT_KEY_NAME, 0, password)
        var temp = message
        while (temp.toByteArray().size % 16 != 0)
            temp += "\u0020"


        var text = cipher.doFinal(temp.toByteArray(Charsets.UTF_8))
        var ivBytes = cipher.iv
        return Pair(text, ivBytes)
    }

    override fun tryDecrypt(data: ByteArray, cipher: Cipher, password: CharArray): String {
         var text = ""
         try {
             initCipher(cipher, DEFAULT_KEY_NAME, 1, password)
             text = cipher.doFinal(data).toString(Charsets.UTF_8).trim()
         } catch (e: Exception) {
             when (e) {
                 is BadPaddingException,
                 is IllegalBlockSizeException -> {
                     Log.e("TAG", "Failed to decrypt the data with the generated key. ${e.message}")
                 }
                 else -> throw e
             }
         }
         return text
     }
}


interface ICryptoUtils {
    fun init() : Pair<Cipher, Cipher>
    fun tryEncrypt(message: String, cipher: Cipher, password: CharArray = "secret".toCharArray()) : Pair<ByteArray, ByteArray>
    fun tryDecrypt(data: ByteArray, cipher: Cipher,  password: CharArray = "secret".toCharArray()): String
}
    
