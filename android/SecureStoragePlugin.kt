package dev.wefter.bridge

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

class SecureStoragePlugin(context: Context, dispatcher: BridgeDispatcher) : WefterPlugin(context, dispatcher) {

    @WefterMethod
    fun set(payload: JSONObject, callback: (Result<Any>) -> Unit) {
        val key = validateKey(payload, callback) ?: return

        if (!payload.has("value") || payload.isNull("value")) {
            reject(callback, "VALUE_REQUIRED", "A string value is required.")
            return
        }
        val value = payload.optString("value", "")

        if (value.toByteArray(Charsets.UTF_8).size > MAX_VALUE_LENGTH) {
            reject(callback, "VALUE_TOO_LARGE", "Value must not exceed $MAX_VALUE_LENGTH bytes.")
            return
        }

        try {
            val committed = prefs().edit().putString(storageKey(key), encrypt(value)).commit()
            if (committed) {
                resolve(callback, JSONObject().put("success", true))
            } else {
                reject(callback, "WRITE_FAILED", "Could not write to secure storage.")
            }
        } catch (e: GeneralSecurityException) {
            reject(callback, "WRITE_FAILED", e.message ?: "Could not access the secure keystore.")
        } catch (e: Exception) {
            reject(callback, "WRITE_FAILED", e.message ?: "Could not write to secure storage.")
        }
    }

    @WefterMethod
    fun get(payload: JSONObject, callback: (Result<Any>) -> Unit) {
        val key = validateKey(payload, callback) ?: return

        try {
            val stored = prefs().getString(storageKey(key), null)
            val result = JSONObject()
            if (stored == null) {
                result.put("value", JSONObject.NULL)
            } else {
                result.put("value", decrypt(stored))
            }
            resolve(callback, result)
        } catch (e: GeneralSecurityException) {
            reject(callback, "READ_FAILED", e.message ?: "Could not access the secure keystore.")
        } catch (e: Exception) {
            reject(callback, "READ_FAILED", e.message ?: "Could not read from secure storage.")
        }
    }

    @WefterMethod
    fun remove(payload: JSONObject, callback: (Result<Any>) -> Unit) {
        val key = validateKey(payload, callback) ?: return

        try {
            if (prefs().edit().remove(storageKey(key)).commit()) {
                resolve(callback, JSONObject().put("success", true))
            } else {
                reject(callback, "REMOVE_FAILED", "Could not remove from secure storage.")
            }
        } catch (e: Exception) {
            reject(callback, "REMOVE_FAILED", e.message ?: "Could not remove from secure storage.")
        }
    }

    private fun validateKey(payload: JSONObject, callback: (Result<Any>) -> Unit): String? {
        val key = payload.optString("key", "").trim()

        if (key.isEmpty()) {
            reject(callback, "KEY_REQUIRED", "A non-empty key is required.")
            return null
        }
        if (key.length > MAX_KEY_LENGTH) {
            reject(callback, "KEY_TOO_LONG", "Key must not exceed $MAX_KEY_LENGTH characters.")
            return null
        }
        return key
    }

    private fun prefs(): SharedPreferences =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let {
            return it
        }

        val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
                KeyGenParameterSpec.Builder(
                                KEY_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
        )
        return keyGenerator.generateKey()
    }

    private fun storageKey(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.NO_WRAP or Base64.URL_SAFE)
    }

    private fun encrypt(plainText: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + cipherText, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH_BYTES)
        val cipherText = combined.copyOfRange(GCM_IV_LENGTH_BYTES, combined.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return String(cipher.doFinal(cipherText), Charsets.UTF_8)
    }

    companion object {
        private const val PREFS_NAME = "wefter_secure_storage_prefs"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "wefter_secure_storage_master_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val GCM_IV_LENGTH_BYTES = 12
        private const val MAX_KEY_LENGTH = 255
        private const val MAX_VALUE_LENGTH = 8192
    }
}
