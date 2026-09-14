package app.una.android.crypto

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class UnaDeviceEnvelopeTest {
    private val decoder = Base64.getDecoder()

    @Test
    fun unwrapsCrossPlatformFixture() {
        val plaintext = UnaDeviceEnvelope.unwrap(
            envelope = decoder.decode(ENVELOPE),
            recipientPrivateScalar = decoder.decode(RECIPIENT_PRIVATE_KEY),
        )

        assertEquals(
            "{\"1\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"}",
            plaintext.decodeToString(),
        )
    }

    @Test
    fun createsEnvelopeThatRecipientCanUnwrap() {
        val plaintext = "synthetic keyring".encodeToByteArray()
        val envelope = UnaDeviceEnvelope.wrap(
            plaintext = plaintext,
            recipientPublicKeyX963 = decoder.decode(RECIPIENT_PUBLIC_KEY),
        )

        val unwrapped = UnaDeviceEnvelope.unwrap(
            envelope = envelope,
            recipientPrivateScalar = decoder.decode(RECIPIENT_PRIVATE_KEY),
        )

        assertArrayEquals(plaintext, unwrapped)
    }

    @Test
    fun exposesEnvelopeBoundaries() {
        val parsed = UnaDeviceEnvelope.parse(decoder.decode(ENVELOPE))

        assertEquals(65, parsed.ephemeralPublicKeyX963.size)
        assertEquals(12, parsed.nonce.size)
        assertArrayEquals(
            decoder.decode(EPHEMERAL_PUBLIC_KEY),
            parsed.ephemeralPublicKeyX963,
        )
    }

    private companion object {
        const val RECIPIENT_PRIVATE_KEY = "UZtCPXFfi11Un4v60lFCrXsWpbtYbfqHsR1sZqB6CjU="
        const val RECIPIENT_PUBLIC_KEY = "BGo5U94FsqcuQMJQpti4PBLNuErRvsNZWP25dbYI007r0oezSZoeCBBg8UdRpOvWTgQNZaE6CL4LXgjLUbiPq94="
        const val EPHEMERAL_PUBLIC_KEY = "BPOsgGG1FHlbiEPj1mKVJ+0q/WsfalVaesq7Xm95yMKsx7ubUUuW5k65zIDWJmLS40xxDSR3o0A0qNVVzpllyK4="
        const val ENVELOPE = "VURXMQTzrIBhtRR5W4hD49ZilSftKv1rH2pVWnrKu15vecjCrMe7m1FLluZOucyA1iZi0uNMcQ0kd6NANKjVVc6ZZciuISIjJCUmJygpKiss0/kjnlnOo29v6ncXIKWNS7a2fUkfkkAVYQovN3404hX3zIn8RnPMitgI5jLKHaEbnFZWo9bnkqi6P/j3xdUP1yGleo0="
    }
}
