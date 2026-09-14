package app.una.android.crypto

import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AgentReadableKeyringTest {
    @Test
    fun keyIsStableAndIsolatedFromOtherHouseholds() {
        val manager = AgentReadableKeyringManager(MemoryVault(), DeterministicSecureRandom())

        val first = manager.ensureKey("household-one")
        val retry = manager.ensureKey("household-one")
        val second = manager.ensureKey("household-two")

        assertArrayEquals(first.key(1), retry.key(1))
        assertFalse(first.key(1)!!.contentEquals(second.key(1)!!))
    }

    @Test
    fun importedVersionBecomesAvailableForReadsAndWrites() {
        val manager = AgentReadableKeyringManager(MemoryVault())
        val imported = manager.importKey("household", 3, ByteArray(32) { 9 })

        assertEquals(3, imported.currentWriteVersion)
        assertArrayEquals(ByteArray(32) { 9 }, manager.load("household")!!.key(3))
    }

    private class MemoryVault : KeyringVault {
        private var value: ByteArray? = null
        override fun store(keyring: ByteArray) { value = keyring.copyOf() }
        override fun load(): ByteArray? = value?.copyOf()
        override fun clear() { value = null }
    }

    private class DeterministicSecureRandom : SecureRandom() {
        private var next = 31
        override fun nextBytes(bytes: ByteArray) {
            bytes.fill(next.toByte())
            next += 1
        }
    }
}
