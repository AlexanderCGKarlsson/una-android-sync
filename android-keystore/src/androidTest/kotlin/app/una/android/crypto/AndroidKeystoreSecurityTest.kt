package app.una.android.crypto

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidKeystoreSecurityTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        clearAllTestState()
    }

    @After
    fun tearDown() {
        clearAllTestState()
    }

    @Test
    fun householdKeyringIsEncryptedAtRestAndCanBeRecovered() {
        val vault = AndroidKeyringVault(context)
        val plaintext = "UNA-TEST-HOUSEHOLD-KEYRING-DO-NOT-STORE".encodeToByteArray()

        vault.store(plaintext)

        assertArrayEquals(plaintext, vault.load())
        val stored = noBackupFile(HOUSEHOLD_FILE).readBytes()
        assertFalse(stored.contentEquals(plaintext))
        assertFalse(stored.containsSubsequence(plaintext))
        assertTrue(androidKeyStore().containsAlias(HOUSEHOLD_ALIAS))
    }

    @Test
    fun humanAndAssistantKeyringsUseSeparateKeysAndFiles() {
        val humanVault = AndroidKeyringVault(context)
        val assistantVault = AndroidAgentReadableKeyringVault(context)
        val humanPlaintext = "UNA-TEST-HUMAN-KEYRING".encodeToByteArray()
        val assistantPlaintext = "UNA-TEST-ASSISTANT-KEYRING".encodeToByteArray()

        humanVault.store(humanPlaintext)
        assistantVault.store(assistantPlaintext)

        assertArrayEquals(humanPlaintext, humanVault.load())
        assertArrayEquals(assistantPlaintext, assistantVault.load())
        assertFalse(noBackupFile(HOUSEHOLD_FILE).readBytes().containsSubsequence(humanPlaintext))
        assertFalse(noBackupFile(ASSISTANT_FILE).readBytes().containsSubsequence(assistantPlaintext))
        assertNotEquals(
            noBackupFile(HOUSEHOLD_FILE).readBytes().toList(),
            noBackupFile(ASSISTANT_FILE).readBytes().toList(),
        )
        val keyStore = androidKeyStore()
        assertTrue(keyStore.containsAlias(HOUSEHOLD_ALIAS))
        assertTrue(keyStore.containsAlias(ASSISTANT_ALIAS))
        assertNotEquals(HOUSEHOLD_ALIAS, ASSISTANT_ALIAS)
    }

    @Test
    fun tamperedKeyringFailsClosed() {
        val vault = AndroidKeyringVault(context)
        vault.store("UNA-TEST-KEYRING".encodeToByteArray())
        val file = noBackupFile(HOUSEHOLD_FILE)
        val tampered = file.readBytes()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
        file.writeBytes(tampered)

        assertThrows(GeneralSecurityException::class.java) {
            vault.load()
        }
    }

    @Test
    fun deviceKeyIsStableNonExportableAndUnwrapsItsEnvelope() {
        val firstManager = AndroidDeviceKeyManager(context)
        val firstPublicKey = firstManager.publicKeyX963()
        val firstIdentifier = firstManager.deviceIdentifier()
        val secondManager = AndroidDeviceKeyManager(context)
        val plaintext = "UNA-TEST-DEVICE-RECOVERY-KEY".encodeToByteArray()
        val envelope = UnaDeviceEnvelope.wrap(plaintext, firstPublicKey)

        assertArrayEquals(firstPublicKey, secondManager.publicKeyX963())
        assertTrue(firstIdentifier.startsWith("android:"))
        assertTrue(firstIdentifier == secondManager.deviceIdentifier())
        assertArrayEquals(plaintext, secondManager.unwrap(envelope))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val keyStore = androidKeyStore()
            val privateKey = keyStore.getKey(DEVICE_KEY_ALIAS, null)
            assertTrue(keyStore.containsAlias(DEVICE_KEY_ALIAS))
            assertNull(privateKey.encoded)
        }
    }

    @Test
    fun tamperedDeviceEnvelopeFailsClosed() {
        val manager = AndroidDeviceKeyManager(context)
        val envelope = UnaDeviceEnvelope.wrap(
            "UNA-TEST-DEVICE-RECOVERY-KEY".encodeToByteArray(),
            manager.publicKeyX963(),
        )
        envelope[envelope.lastIndex] = (envelope.last().toInt() xor 0x01).toByte()

        assertThrows(GeneralSecurityException::class.java) {
            manager.unwrap(envelope)
        }
    }

    private fun clearAllTestState() {
        noBackupFile(HOUSEHOLD_FILE).delete()
        noBackupFile("$HOUSEHOLD_FILE.bak").delete()
        noBackupFile(ASSISTANT_FILE).delete()
        noBackupFile("$ASSISTANT_FILE.bak").delete()
        noBackupFile(LEGACY_DEVICE_FILE).delete()
        noBackupFile("$LEGACY_DEVICE_FILE.bak").delete()

        val keyStore = androidKeyStore()
        listOf(HOUSEHOLD_ALIAS, ASSISTANT_ALIAS, DEVICE_KEY_ALIAS, LEGACY_DEVICE_ALIAS)
            .filter(keyStore::containsAlias)
            .forEach(keyStore::deleteEntry)
    }

    private fun noBackupFile(name: String): File = context.noBackupFilesDir.resolve(name)

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        return (0..size - candidate.size).any { offset ->
            candidate.indices.all { index -> this[offset + index] == candidate[index] }
        }
    }

    private companion object {
        const val HOUSEHOLD_ALIAS = "app.una.android.household-keyring-kek.v1"
        const val ASSISTANT_ALIAS = "app.una.android.agent-readable-keyring-kek.v1"
        const val DEVICE_KEY_ALIAS = "app.una.android.device-recovery-ecdh.v1"
        const val LEGACY_DEVICE_ALIAS = "app.una.android.device-recovery-kek.v1"
        const val HOUSEHOLD_FILE = "household-keyring.v1"
        const val ASSISTANT_FILE = "agent-readable-keyring.v1"
        const val LEGACY_DEVICE_FILE = "device-recovery-key.v1"
    }
}
