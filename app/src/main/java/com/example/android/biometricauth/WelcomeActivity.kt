
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
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.io.IOException
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

     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         val myPreference = HsPreference(this)

         val Message = myPreference.getEncrypted()
         val Decrypted = myPreference.getDecrypted()

         setContentView(R.layout.activity_welcome)
         findViewById<TextView>(R.id.encrypted_message).run {
             text = Message
         }
         findViewById<TextView>(R.id.decrypted_message).run {
             text = Decrypted
         }
     }

    /**
     *
     * Read From SHaredPrefrence on an Ecrypted file
     */

    private fun readPrefrence (key : String): String? {

        val defaultValue = ""
        val sharedPref = this.getPreferences(Context.MODE_PRIVATE)
        val value = sharedPref.getString(key, defaultValue)
        return  value

    }
}