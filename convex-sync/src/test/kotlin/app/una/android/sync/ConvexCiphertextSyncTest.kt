package app.una.android.sync

import app.una.android.crypto.VersionedEncryptedPayload
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class ConvexCiphertextSyncTest {
    @Test
    fun wireArgumentsContainCiphertextNonceAndKeyVersion() {
        val ciphertext = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(12) { (it + 41).toByte() }
        val payload = EncryptedArgument(ciphertext, nonce, keyVersion = 3)

        val arguments = ConvexCiphertextSync.buildArguments(
            payload = payload,
            payloadArgumentName = "payload",
            indexedArguments = mapOf("sortOrder" to 2.0),
        )

        @Suppress("UNCHECKED_CAST")
        val wirePayload = arguments.getValue("payload") as Map<String, Any>
        assertArrayEquals(ciphertext, wirePayload.getValue("ciphertext") as ByteArray)
        assertArrayEquals(nonce, wirePayload.getValue("nonce") as ByteArray)
        assertEquals(3.0, wirePayload.getValue("keyVersion"))
        assertEquals(2.0, arguments.getValue("sortOrder"))
    }

    @Test
    fun publicPayloadTypeHasNoPlaintextOrKeyField() {
        val fieldNames = EncryptedArgument::class.java.declaredFields.map { it.name.lowercase() }

        assertFalse(fieldNames.any { "plaintext" in it })
        assertFalse(fieldNames.any { it == "key" || it.endsWith("keybytes") })
    }

    @Test
    fun conversionFromCryptoCorePreservesOnlyEncryptedMaterial() {
        val payload = VersionedEncryptedPayload(
            ciphertext = ByteArray(24) { 8 },
            nonce = ByteArray(12) { 4 },
            keyVersion = 2,
        )

        val argument = EncryptedArgument.from(payload)

        assertArrayEquals(payload.ciphertext, argument.ciphertext)
        assertArrayEquals(payload.nonce, argument.nonce)
        assertEquals(payload.keyVersion, argument.keyVersion)
    }

    @Test
    fun indexedArgumentsCannotReplaceEncryptedPayload() {
        val payload = EncryptedArgument(ByteArray(16), ByteArray(12), 1)

        assertThrows(IllegalArgumentException::class.java) {
            ConvexCiphertextSync.buildArguments(
                payload = payload,
                payloadArgumentName = "payload",
                indexedArguments = mapOf("payload" to "plaintext"),
            )
        }
    }

    @Test
    fun callerCannotMutatePayloadAfterConstruction() {
        val ciphertext = ByteArray(16) { 1 }
        val nonce = ByteArray(12) { 2 }
        val argument = EncryptedArgument(ciphertext, nonce, 1)

        ciphertext.fill(9)
        nonce.fill(9)

        assertArrayEquals(ByteArray(16) { 1 }, argument.ciphertext)
        assertArrayEquals(ByteArray(12) { 2 }, argument.nonce)
    }
}
