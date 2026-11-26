package com.wci.core.crypto.tink

import android.content.Context
import android.os.Build
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * TinkVaultManager (S-13)
 * Manages Google Tink AEAD and Streaming AEAD vaults for student KYC documents,
 * admission scans, and sensitive PDF assets backed by Android Keystore master keys.
 */
class TinkVaultManager(private val context: Context) {

    companion object {
        private const val MASTER_KEY_URI = "android-keystore://wci_tink_master_key"
        private const val PREF_FILE_NAME = "wci_tink_keyset_prefs"
        private const val AEAD_KEYSET_NAME = "wci_aead_keyset"
        private const val STREAMING_KEYSET_NAME = "wci_streaming_keyset"

        private fun isTestHarness(): Boolean {
            val fp = runCatching { Build.FINGERPRINT }.getOrNull().orEmpty()
            return fp.equals("robolectric", ignoreCase = true) || fp.isBlank()
        }
    }

    private var aead: Aead? = null
    private var streamingAead: StreamingAead? = null

    init {
        AeadConfig.register()
        StreamingAeadConfig.register()

        if (!isTestHarness()) {
            val aeadKeysetHandle = AndroidKeysetManager.Builder()
                .withSharedPref(context, AEAD_KEYSET_NAME, PREF_FILE_NAME)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .keysetHandle
            aead = aeadKeysetHandle.getPrimitive(Aead::class.java)

            val streamingKeysetHandle = AndroidKeysetManager.Builder()
                .withSharedPref(context, STREAMING_KEYSET_NAME, PREF_FILE_NAME)
                .withKeyTemplate(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB)
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .keysetHandle
            streamingAead = streamingKeysetHandle.getPrimitive(StreamingAead::class.java)
        } else {
            // Headless JVM / Robolectric tests lack AndroidKeyStore; use real ephemeral AES-256-GCM Tink keysets
            aead = runCatching {
                KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM")).getPrimitive(Aead::class.java)
            }.getOrNull()
            streamingAead = runCatching {
                KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB)
                    .getPrimitive(StreamingAead::class.java)
            }.getOrNull()
        }
    }

    /**
     * Encrypts small byte array payloads (e.g. Aadhaar numbers, guardian phone) with AES-256-GCM.
     */
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray = "WCI_UNNAO".toByteArray(StandardCharsets.UTF_8)): ByteArray {
        val primitive = aead
            ?: throw SecurityException("AEAD vault unavailable: hardware Keystore initialization required.")
        return primitive.encrypt(plaintext, associatedData)
    }

    /**
     * Decrypts byte array payload.
     */
    fun decrypt(ciphertext: ByteArray, associatedData: ByteArray = "WCI_UNNAO".toByteArray(StandardCharsets.UTF_8)): ByteArray {
        val primitive = aead
            ?: throw SecurityException("AEAD vault unavailable: hardware Keystore initialization required.")
        return primitive.decrypt(ciphertext, associatedData)
    }

    /**
     * Creates an encrypting output stream for streaming document encryption in 4KB chunks.
     */
    fun newEncryptingStream(outputStream: OutputStream, associatedData: ByteArray): OutputStream {
        val primitive = streamingAead
            ?: throw IllegalStateException("Streaming AEAD primitive uninitialized")
        return primitive.newEncryptingStream(outputStream, associatedData)
    }

    /**
     * Creates a decrypting input stream for streaming document decryption.
     */
    fun newDecryptingStream(inputStream: InputStream, associatedData: ByteArray): InputStream {
        val primitive = streamingAead
            ?: throw IllegalStateException("Streaming AEAD primitive uninitialized")
        return primitive.newDecryptingStream(inputStream, associatedData)
    }
}
