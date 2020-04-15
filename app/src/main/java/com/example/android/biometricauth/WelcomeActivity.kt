
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
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.io.IOException
import java.nio.charset.Charset
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.util.concurrent.Executor
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey


class WelcomeActivity : AppCompatActivity() {
     private val cryptoUtilsObj: CryptoUtils = CryptoUtils(ANDROID_KEY_STORE)
     override fun onCreate(savedInstanceState: Bundle?) {

         super.onCreate(savedInstanceState)
         val myPreference = HsPreference(this)

         val Message = myPreference.getEncrypted()
         val Decrypted = myPreference.getDecrypted()

         setContentView(R.layout.activity_welcome)
         findViewById<TextView>(R.id.encrypted_message).run {
             text = Message
         }
//         findViewById<TextView>(R.id.decrypted_message).run {
//             text = Decrypted
//         }

         cryptoUtilsObj.setupKeyStoreAndKeyGenerator()
         val (defaultCipher: Cipher, cipherNotInvalidated: Cipher) = cryptoUtilsObj.setupCiphers()
         
         initializeViews(cipherNotInvalidated, defaultCipher)
     }
    private fun initializeViews(cipherNotInvalidated: Cipher, defaultCipher: Cipher) {
        val button = findViewById<Button>(R.id.decrypt_button)
        cryptoUtilsObj.createKey(DEFAULT_KEY_NAME, false)
        button.setOnClickListener {
            showBiometricPrompt(defaultCipher,DEFAULT_KEY_NAME,"decrypt")
        }
    }


    private fun showBiometricPrompt(
        cipher: Cipher,
        keyName: String,
        buttonType: String
    ) {
        val myPreference = HsPreference(this)

        //if (cryptoUtilsObj.initCipher(cipher, keyName)){
            val biometricPromptUtils = BiometricPromptUtils(this, object : BiometricPromptUtils.BiometricListener {
                override fun onAuthenticationLockoutError() {
                    // implement your lockout error UI prompt
                }
    
                override fun onAuthenticationPermanentLockoutError() {
                    // implement your permanent lockout error UI prompt
                }
    
                override fun onAuthenticationSuccess() {
                    // implement your authentication success UI prompt
                    var message_to_entrypt = "Hello World"
                    if(buttonType==="encrypt")
                    {
                        val editText = findViewById<EditText>(R.id.user_text_input)
                        message_to_entrypt = editText.text.toString()
                        val (encrypted_message, ivBytes) = cryptoUtilsObj.tryEncrypt(message_to_entrypt, cipher)
                        myPreference.setEncrypted(encrypted_message.toString())

                        findViewById<TextView>(R.id.encrypted_message).run {
                            text = encrypted_message.toString()
                        }

                    } else if(buttonType==="decrypt") {
                        val Message =  Base64.decode(myPreference.getEncrypted().toByteArray(),1)

                        val decryptedMessage = cryptoUtilsObj.tryDecrypt(Message, cipher);

                        findViewById<TextView>(R.id.encrypted_message).run {
                            text = decryptedMessage.toString()
                        }
                    }
                }
    
                override fun onAuthenticationFailed() {
                    // implement your authentication failed UI prompt
                }
    
                override fun onAuthenticationError() {
                    // implement your authentication error UI prompt
                }
    
            })
            biometricPromptUtils.showBiometricPrompt(
                    resources.getString(R.string.confirmDescription),
                    resources.getString(R.string.cancelKey),
                    confirmationRequired = true
            )
       //}

        
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DIALOG_FRAGMENT_TAG = "myFragment"
        private const val KEY_NAME_NOT_INVALIDATED = "key_not_invalidated"
        private const val SECRET_MESSAGE = "Very secret message"
        private const val TAG = "MainActivity"
    }
}