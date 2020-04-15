package com.example.android.biometricauth

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import javax.crypto.Cipher

class TestActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.toolbar))

        val cryptoUtilsObj: CryptoUtils = CryptoUtils(ANDROID_KEY_STORE)
        /*

        Log.i("MAIN", "After creating cryptoutil obj")
        cryptoUtilsObj.setupKeyStoreAndKeyGenerator()
        Log.i("MAIN", "After calling setupKeyStoreAndKeyGenerator()")
        val (defaultCipher: Cipher, cipherNotInvalidated: Cipher) = cryptoUtilsObj.setupCiphers()
        Log.i("MAIN", "After calling setupCiphers()")
        cryptoUtilsObj.createKey(DEFAULT_KEY_NAME, false)
        Log.i("MAIN", "After calling createKey()")
        */

        val (defaultCipher: Cipher, cipherNotInvalidated: Cipher) = cryptoUtilsObj.init()

        val message_to_entrypt = "Hello World"
        Log.i("Actual message", message_to_entrypt)
        val (encrypted_message_byte : ByteArray, ivBytes: ByteArray) = cryptoUtilsObj.tryEncrypt(message_to_entrypt, defaultCipher);
        val encrypted_message  = Base64.encodeToString(encrypted_message_byte, 0)
        Log.i("Encrypted Message", encrypted_message)
        val decryptedBack = cryptoUtilsObj.tryDecrypt(encrypted_message_byte, defaultCipher);
        Log.i("Decrypted Message", decryptedBack)

    }


    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DIALOG_FRAGMENT_TAG = "myFragment"
        private const val KEY_NAME_NOT_INVALIDATED = "key_not_invalidated"
        private const val SECRET_MESSAGE = "Very secret message"
        private const val TAG = "MainActivity"
    }
}