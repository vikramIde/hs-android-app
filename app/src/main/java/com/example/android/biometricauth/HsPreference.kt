package com.example.android.biometricauth

import android.content.Context

class HsPreference (context: Context) {
    val PREFERENCE_NAME = "HS_PREFERENCE"
    val PREFERENCE_ENCRYPTED = "HS_ENCRYPTED"
    val PREFERENCE_DECRYPTED = "HS_DECRYPTED"

    val preference = context.getSharedPreferences(PREFERENCE_NAME, Context.MODE_PRIVATE)

    fun getEncrypted() : String {
        return preference.getString(PREFERENCE_ENCRYPTED,"").toString()

    }

    fun setEncrypted(text: String) {
        val editor = preference.edit()
        editor.putString(PREFERENCE_ENCRYPTED,text)
        editor.apply()
    }

    fun getDecrypted() : String? {
        return preference.getString(PREFERENCE_DECRYPTED,"")

    }

    fun setDecrypted(text: String) {
        val editor = preference.edit()
        editor.putString(PREFERENCE_DECRYPTED,text)
        editor.apply()
    }

}