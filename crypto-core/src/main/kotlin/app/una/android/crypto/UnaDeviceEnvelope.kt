package app.una.android.crypto

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Byte-for-byte implementation of the device recovery envelope currently emitted by Una. */
object UnaDeviceEnvelope {
    private val magic = byteArrayOf('U'.code.toByte(), 'D'.code.toByte(), 'W'.code.toByte(), '1'.code.toByte())
    private val hkdfSalt = "UnaDeviceWrap.v1".encodeToByteArray()
    private const val PUBLIC_KEY_SIZE = 65
    private const val NONCE_SIZE = 12
    private const val TAG_SIZE = 16

    data class Parsed(
        val ephemeralPublicKeyX963: ByteArray,
        val nonce: ByteArray,
        val ciphertextAndTag: ByteArray,
    )

    fun parse(envelope: ByteArray): Parsed {
        val minimumSize = magic.size + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE
        require(envelope.size >= minimumSize) { "UDW1 envelope is truncated" }
        require(envelope.copyOfRange(0, magic.size).contentEquals(magic)) {
            "Unsupported Una device envelope version"
        }

        var offset = magic.size
        val publicKey = envelope.copyOfRange(offset, offset + PUBLIC_KEY_SIZE)
        require(publicKey.first() == 0x04.toByte()) { "Expected an uncompressed P-256 public key" }
        offset += PUBLIC_KEY_SIZE
        val nonce = envelope.copyOfRange(offset, offset + NONCE_SIZE)
        offset += NONCE_SIZE
        val ciphertext = envelope.copyOfRange(offset, envelope.size)
        return Parsed(publicKey, nonce, ciphertext)
    }

    fun unwrap(envelope: ByteArray, recipientPrivateScalar: ByteArray): ByteArray {
        require(recipientPrivateScalar.size == 32) { "P-256 private scalar must be 32 bytes" }
        return unwrap(envelope, privateKeyFromScalar(recipientPrivateScalar))
    }

    fun unwrap(
        envelope: ByteArray,
        recipientPrivateKey: PrivateKey,
        keyAgreementProvider: String? = null,
    ): ByteArray {
        val parsed = parse(envelope)
        val sharedSecret = ecdh(
            recipientPrivateKey,
            publicKeyFromX963(parsed.ephemeralPublicKeyX963),
            keyAgreementProvider,
        )
        val wrappingKey = hkdfSha256(sharedSecret, hkdfSalt, ByteArray(0), 32)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(wrappingKey, "AES"),
            GCMParameterSpec(TAG_SIZE * 8, parsed.nonce),
        )
        return cipher.doFinal(parsed.ciphertextAndTag)
    }

    fun wrap(
        plaintext: ByteArray,
        recipientPublicKeyX963: ByteArray,
        secureRandom: SecureRandom = SecureRandom(),
    ): ByteArray {
        val ephemeral = createEphemeralKeyPair()
        val sharedSecret = ecdh(
            ephemeral.private,
            publicKeyFromX963(recipientPublicKeyX963),
            null,
        )
        val wrappingKey = hkdfSha256(sharedSecret, hkdfSalt, ByteArray(0), 32)
        val nonce = ByteArray(NONCE_SIZE).also(secureRandom::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(wrappingKey, "AES"),
            GCMParameterSpec(TAG_SIZE * 8, nonce),
        )
        val ciphertextAndTag = cipher.doFinal(plaintext)
        return magic + publicKeyToX963(ephemeral.public) + nonce + ciphertextAndTag
    }

    fun createEphemeralKeyPair() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun ecdh(
        privateKey: PrivateKey,
        publicKey: PublicKey,
        provider: String?,
    ): ByteArray {
        val agreement = if (provider == null) {
            KeyAgreement.getInstance("ECDH")
        } else {
            KeyAgreement.getInstance("ECDH", provider)
        }
        return agreement.run {
            init(privateKey)
            doPhase(publicKey, true)
            generateSecret()
        }
    }

    private fun privateKeyFromScalar(scalar: ByteArray): PrivateKey {
        val spec = ECPrivateKeySpec(BigInteger(1, scalar), p256Parameters())
        return KeyFactory.getInstance("EC").generatePrivate(spec)
    }

    private fun publicKeyFromX963(bytes: ByteArray): PublicKey {
        require(bytes.size == PUBLIC_KEY_SIZE && bytes[0] == 0x04.toByte()) {
            "Expected a 65-byte uncompressed P-256 public key"
        }
        val point = ECPoint(
            BigInteger(1, bytes.copyOfRange(1, 33)),
            BigInteger(1, bytes.copyOfRange(33, 65)),
        )
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256Parameters()))
    }

    fun publicKeyToX963(key: PublicKey): ByteArray {
        val point = (key as ECPublicKey).w
        return byteArrayOf(0x04) +
            point.affineX.toUnsignedFixedWidth(32) +
            point.affineY.toUnsignedFixedWidth(32)
    }

    private fun BigInteger.toUnsignedFixedWidth(width: Int): ByteArray {
        val signed = toByteArray()
        val unsigned = if (signed.size == width + 1 && signed[0] == 0.toByte()) {
            signed.copyOfRange(1, signed.size)
        } else {
            signed
        }
        require(unsigned.size <= width) { "P-256 coordinate does not fit" }
        return ByteArray(width - unsigned.size) + unsigned
    }

    private fun p256Parameters(): ECParameterSpec {
        return AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    private fun hkdfSha256(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputSize: Int,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = mac.doFinal(inputKeyMaterial)
        val output = ByteBuffer.allocate(outputSize)
        var previous = ByteArray(0)
        var counter = 1

        while (output.hasRemaining()) {
            mac.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            output.put(previous, 0, minOf(previous.size, output.remaining()))
            counter += 1
            require(counter <= 256) { "HKDF output is too large" }
        }
        return output.array()
    }
}
