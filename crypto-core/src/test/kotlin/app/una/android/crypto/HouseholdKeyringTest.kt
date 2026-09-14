package app.una.android.crypto

import java.security.SecureRandom
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HouseholdKeyringTest {
    @Test
    fun storedHouseholdHintOnlyAppearsAfterAKeyringExists() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())

        assertFalse(manager.hasStoredHouseholdKeyHint())

        manager.create("household", ByteArray(32) { 1 })

        assertTrue(manager.hasStoredHouseholdKeyHint())
    }

    @Test
    fun bootstrapKeySurvivesRetryAndIsBoundOnlyAfterCompletion() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())

        val firstAttempt = manager.prepareBootstrapKey("google:one")
        val retry = manager.prepareBootstrapKey("google:one")

        assertArrayEquals(firstAttempt, retry)
        manager.completeBootstrap("household", firstAttempt, "google:one")
        assertArrayEquals(firstAttempt, manager.load("household")!!.key(1))
        assertEquals(null, manager.pendingBootstrapKey("google:one"))
    }

    @Test
    fun bootstrapKeysAreIsolatedBetweenGoogleIdentities() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())

        val firstIdentity = manager.prepareBootstrapKey("google:one")
        val secondIdentity = manager.prepareBootstrapKey("google:two")

        assertFalse(firstIdentity.contentEquals(secondIdentity))
        assertArrayEquals(firstIdentity, manager.pendingBootstrapKey("google:one"))
        assertArrayEquals(secondIdentity, manager.pendingBootstrapKey("google:two"))

        manager.completeBootstrap("second-household", secondIdentity, "google:two")
        assertArrayEquals(firstIdentity, manager.pendingBootstrapKey("google:one"))
        assertEquals(null, manager.pendingBootstrapKey("google:two"))
    }

    @Test
    fun keyringsForDifferentHouseholdsDoNotOverwriteEachOther() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        manager.create("one", ByteArray(32) { 1 })
        manager.create("two", ByteArray(32) { 2 })

        assertArrayEquals(ByteArray(32) { 1 }, manager.load("one")!!.key(1))
        assertArrayEquals(ByteArray(32) { 2 }, manager.load("two")!!.key(1))
    }

    @Test
    fun preparedRotationRetainsHistoryWithoutChangingWrites() {
        val vault = MemoryVault()
        val manager = HouseholdKeyringManager(vault, DeterministicSecureRandom())
        val firstKey = ByteArray(32) { 7 }
        manager.create("household", firstKey)

        val prepared = manager.prepareRotation("household", currentVersion = 1)

        assertEquals(1, prepared.currentWriteVersion)
        assertArrayEquals(firstKey, prepared.key(1))
        assertNotNull(prepared.key(2))
        assertFalse(prepared.key(1)!!.contentEquals(prepared.key(2)!!))

        val persisted = manager.load("household")!!
        assertEquals(1, persisted.currentWriteVersion)
        assertTrue(persisted.keys.keys.containsAll(listOf(1, 2)))
    }

    @Test
    fun commitChangesWritesOnlyAfterPreparedKeyExists() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        manager.create("household", ByteArray(32) { 1 })
        manager.prepareRotation("household", currentVersion = 1)

        val committed = manager.commitRotation("household", targetVersion = 2)

        assertEquals(2, committed.currentWriteVersion)
        assertNotNull(committed.key(1))
        assertNotNull(committed.key(2))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotAlignToServerVersionWithoutItsKey() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        manager.create("household", ByteArray(32) { 1 })

        manager.alignWriteVersion("household", serverVersion = 2)
    }

    @Test
    fun importedHistoricalKeyDoesNotReplaceCurrentWriteVersion() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        manager.create("household", ByteArray(32) { 1 })
        manager.prepareRotation("household", currentVersion = 1)
        manager.commitRotation("household", targetVersion = 2)

        val imported = manager.importKey("household", 3, ByteArray(32) { 3 })

        assertEquals(2, imported.currentWriteVersion)
        assertNotNull(imported.key(1))
        assertNotNull(imported.key(2))
        assertNotNull(imported.key(3))
    }

    @Test
    fun inviteKeyringRoundTripsEveryVersionUsingTheIosFormat() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        val firstKey = ByteArray(32) { 1 }
        manager.create("source", firstKey)
        val prepared = manager.prepareRotation("source", currentVersion = 1)
        manager.commitRotation("source", targetVersion = 2)

        val encoded = manager.exportInviteKeyring("source")
        val imported = manager.importInviteKeyring("target", encoded)

        assertEquals(2, imported.currentWriteVersion)
        assertArrayEquals(firstKey, imported.key(1))
        assertArrayEquals(prepared.key(2), imported.key(2))
    }

    @Test
    fun importsTheLiteralJsonShapeWrittenByIos() {
        val encodedKey = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 7 })
        val json = """{"formatVersion":1,"currentWriteVersion":2,"keys":{"1":"$encodedKey","2":"$encodedKey"}}"""
        val encodedKeyring = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(json.encodeToByteArray())
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())

        val imported = manager.importInviteKeyring("ios-household", encodedKeyring)

        assertEquals(2, imported.currentWriteVersion)
        assertArrayEquals(ByteArray(32) { 7 }, imported.key(1))
        assertArrayEquals(ByteArray(32) { 7 }, imported.key(2))
    }

    @Test
    fun removingOldHouseholdPreservesInvitedHousehold() {
        val manager = HouseholdKeyringManager(MemoryVault(), DeterministicSecureRandom())
        manager.create("old", ByteArray(32) { 1 })
        manager.create("invited", ByteArray(32) { 2 })

        manager.removeHousehold("old")

        assertEquals(null, manager.load("old"))
        assertArrayEquals(ByteArray(32) { 2 }, manager.load("invited")!!.key(1))
    }

    private class MemoryVault : KeyringVault {
        private var bytes: ByteArray? = null

        override fun store(keyring: ByteArray) {
            bytes = keyring.copyOf()
        }

        override fun load(): ByteArray? = bytes?.copyOf()

        override fun clear() {
            bytes = null
        }
    }

    private class DeterministicSecureRandom : SecureRandom() {
        private var next = 20

        override fun nextBytes(bytes: ByteArray) {
            bytes.fill(next.toByte())
            next += 1
        }
    }
}
