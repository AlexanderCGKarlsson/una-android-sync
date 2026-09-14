package app.una.android.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.AEADBadTagException
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceEnvelopeFailureModesTest {
    @Test
    fun anotherDevicePrivateKeyCannotUnwrapEnvelope() {
        val recipient = p256KeyPair()
        val otherDevice = p256KeyPair()
        val envelope = UnaDeviceEnvelope.wrap(
            plaintext = "household keyring".encodeToByteArray(),
            recipientPublicKeyX963 = UnaDeviceEnvelope.publicKeyToX963(recipient.public),
        )

        assertThrows(AEADBadTagException::class.java) {
            UnaDeviceEnvelope.unwrap(envelope, otherDevice.private)
        }
    }

    @Test
    fun tamperedEnvelopeIsRejected() {
        val recipient = p256KeyPair()
        val envelope = UnaDeviceEnvelope.wrap(
            plaintext = "household keyring".encodeToByteArray(),
            recipientPublicKeyX963 = UnaDeviceEnvelope.publicKeyToX963(recipient.public),
        )
        val tampered = envelope.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }

        assertThrows(AEADBadTagException::class.java) {
            UnaDeviceEnvelope.unwrap(tampered, recipient.private)
        }
    }

    @Test
    fun truncatedAndUnknownEnvelopeVersionsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            UnaDeviceEnvelope.parse(byteArrayOf('U'.code.toByte(), 'D'.code.toByte()))
        }

        val unknown = ByteArray(4 + 65 + 12 + 16).also {
            "UDW2".encodeToByteArray().copyInto(it)
        }
        assertThrows(IllegalArgumentException::class.java) {
            UnaDeviceEnvelope.parse(unknown)
        }
    }

    private fun p256KeyPair() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
}
