package com.wci.core.crypto.pqc

import com.wci.nativecxx.WciNativeSentinel
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class HybridPqcKeyPackage(
    val publicKeyBase64: String,
    val privateKeyBase64: String
)

data class HybridCiphertextPackage(
    val ciphertextBase64: String,
    val sharedSecretBase64: String
)

/**
 * HybridPqcKem (S-02, S-12)
 * Real NIST FIPS 203 ML-KEM-768 + X25519 + HKDF-SHA256 Hybrid Post-Quantum KEM bridge
 * ensuring long-term resilience against "Harvest Now, Decrypt Later" adversaries.
 */
object HybridPqcKem {

    private const val DOMAIN_INFO = "WCI_UNNAO_HYBRID_KEM_V2"
    private const val X25519_LEN = 32
    private const val MLKEM768_PUB_LEN = 1184
    private const val MLKEM768_CT_LEN = 1088
    private val secureRandom = SecureRandom()

    /**
     * Generates a genuine hybrid ML-KEM-768 + X25519 keypair.
     * Layout: [4-byte BE X25519 len][X25519 bytes][4-byte BE ML-KEM len][ML-KEM bytes]
     */
    fun generateKeyPair(): HybridPqcKeyPackage {
        val mlkemGen = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768))
        }
        val mlkemKp = mlkemGen.generateKeyPair()
        val mlkemPub = (mlkemKp.public as MLKEMPublicKeyParameters).encoded
        val mlkemPriv = (mlkemKp.private as MLKEMPrivateKeyParameters).encoded

        val x25519Priv = X25519PrivateKeyParameters(secureRandom)
        val x25519Pub = x25519Priv.generatePublicKey().encoded

        val packedPub = packPair(x25519Pub, mlkemPub)
        val packedPriv = packPair(x25519Priv.encoded, mlkemPriv)

        return HybridPqcKeyPackage(
            publicKeyBase64 = Base64.getEncoder().encodeToString(packedPub),
            privateKeyBase64 = Base64.getEncoder().encodeToString(packedPriv)
        )
    }

    /**
     * Encapsulates a shared secret using recipient's hybrid ML-KEM-768 + X25519 public key.
     */
    fun encapsulate(recipientPublicKeyBase64: String): HybridCiphertextPackage {
        val rawPub = Base64.getDecoder().decode(recipientPublicKeyBase64)
        val (x25519PubBytes, mlkemPubBytes) = unpackPair(rawPub)
        require(x25519PubBytes.size == X25519_LEN && mlkemPubBytes.size == MLKEM768_PUB_LEN) {
            "Invalid hybrid recipient public key lengths."
        }

        val mlkemEnc = MLKEMGenerator(secureRandom).generateEncapsulated(
            MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, mlkemPubBytes)
        )
        val ephXPriv = X25519PrivateKeyParameters(secureRandom)
        val ephXPub = ephXPriv.generatePublicKey().encoded
        val ssX = ByteArray(X25519_LEN)
        X25519Agreement().apply { init(ephXPriv) }
            .calculateAgreement(X25519PublicKeyParameters(x25519PubBytes, 0), ssX, 0)

        val packedCt = packPair(ephXPub, mlkemEnc.encapsulation)
        val derived = deriveHybridKey(mlkemEnc.secret, ssX, packedCt)
        WciNativeSentinel.scrubMemory(ssX)

        return HybridCiphertextPackage(
            ciphertextBase64 = Base64.getEncoder().encodeToString(packedCt),
            sharedSecretBase64 = Base64.getEncoder().encodeToString(derived)
        )
    }

    /**
     * Decapsulates the shared secret using ML-KEM-768 + X25519 private keys and ciphertext.
     */
    fun decapsulate(ciphertextBase64: String, privateKeyBase64: String): ByteArray {
        val rawCt = Base64.getDecoder().decode(ciphertextBase64)
        val rawPriv = Base64.getDecoder().decode(privateKeyBase64)
        val (ephXPubBytes, mlkemCtBytes) = unpackPair(rawCt)
        val (x25519PrivBytes, mlkemPrivBytes) = unpackPair(rawPriv)

        require(ephXPubBytes.size == X25519_LEN && mlkemCtBytes.size == MLKEM768_CT_LEN) {
            "Invalid hybrid ciphertext dimensions."
        }
        require(x25519PrivBytes.size == X25519_LEN && mlkemPrivBytes.isNotEmpty()) {
            "Invalid hybrid private key dimensions."
        }

        val ssKem = MLKEMExtractor(MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlkemPrivBytes))
            .extractSecret(mlkemCtBytes)
        val ssX = ByteArray(X25519_LEN)
        try {
            X25519Agreement().apply { init(X25519PrivateKeyParameters(x25519PrivBytes, 0)) }
                .calculateAgreement(X25519PublicKeyParameters(ephXPubBytes, 0), ssX, 0)
            return deriveHybridKey(ssKem, ssX, rawCt)
        } finally {
            WciNativeSentinel.scrubMemory(ssKem)
            WciNativeSentinel.scrubMemory(ssX)
        }
    }

    private fun deriveHybridKey(ssKem: ByteArray, ssX: ByteArray, transcript: ByteArray): ByteArray {
        val salt = MessageDigest.getInstance("SHA-256").digest(transcript)
        val ikm = ByteArray(ssKem.size + ssX.size)
        System.arraycopy(ssKem, 0, ikm, 0, ssKem.size)
        System.arraycopy(ssX, 0, ikm, ssKem.size, ssX.size)
        val hkdf = HKDFBytesGenerator(SHA256Digest()).apply {
            init(HKDFParameters(ikm, salt, DOMAIN_INFO.toByteArray(StandardCharsets.UTF_8)))
        }
        return ByteArray(32).also {
            hkdf.generateBytes(it, 0, 32)
            WciNativeSentinel.scrubMemory(ikm)
        }
    }

    private fun packPair(first: ByteArray, second: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(8 + first.size + second.size)
        buf.putInt(first.size)
        buf.put(first)
        buf.putInt(second.size)
        buf.put(second)
        return buf.array()
    }

    private fun unpackPair(packed: ByteArray): Pair<ByteArray, ByteArray> {
        require(packed.size >= 8) { "Truncated hybrid container" }
        val buf = ByteBuffer.wrap(packed)
        val len1 = buf.int
        require(len1 in 1..buf.remaining() - 4) { "Invalid first block length: $len1" }
        val first = ByteArray(len1)
        buf.get(first)
        val len2 = buf.int
        require(len2 in 1..buf.remaining()) { "Invalid second block length: $len2" }
        val second = ByteArray(len2)
        buf.get(second)
        return first to second
    }

    /**
     * Encrypts data envelope with derived PQC master key and bound AAD.
     */
    fun sealEnvelope(plaintext: ByteArray, sharedSecret: ByteArray): ByteArray {
        require(sharedSecret.size == 32) { "Shared secret must be 256 bits" }
        val iv = ByteArray(12).apply { secureRandom.nextBytes(this) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(sharedSecret, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(DOMAIN_INFO.toByteArray(StandardCharsets.UTF_8))
        val encrypted = cipher.doFinal(plaintext)

        val out = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(encrypted, 0, out, iv.size, encrypted.size)
        return out
    }

    fun openEnvelope(envelope: ByteArray, sharedSecret: ByteArray): ByteArray {
        require(sharedSecret.size == 32 && envelope.size > 12) { "Invalid sealed envelope" }
        val iv = envelope.copyOfRange(0, 12)
        val ciphertext = envelope.copyOfRange(12, envelope.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sharedSecret, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(DOMAIN_INFO.toByteArray(StandardCharsets.UTF_8))
        return cipher.doFinal(ciphertext)
    }
}
