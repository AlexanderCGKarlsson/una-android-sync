package app.una.android.crypto

import java.security.SecureRandom
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * A household-scoped keyring used only for content explicitly shared with assistants.
 *
 * This key must never be substituted for the human household key. Keeping it separate lets an
 * adult revoke assistant access without disclosing the key that protects private household data.
 */
data class AgentReadableKeyring(
    val householdId: String,
    val keys: Map<Int, ByteArray>,
    val currentWriteVersion: Int,
) {
    fun key(version: Int): ByteArray? = keys[version]?.copyOf()
}

class AgentReadableKeyringManager(
    private val vault: KeyringVault,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    fun load(householdId: String): AgentReadableKeyring? {
        val stored = loadCollection().households[householdId] ?: return null
        return AgentReadableKeyring(
            householdId = stored.householdId,
            keys = stored.keys.mapKeys { (version, _) ->
                version.toIntOrNull()?.takeIf { it > 0 } ?: error("Invalid assistant key version")
            }.mapValues { (_, value) ->
                Base64.getUrlDecoder().decode(value).also(::requireKey)
            },
            currentWriteVersion = stored.currentWriteVersion,
        ).validated()
    }

    fun ensureKey(householdId: String): AgentReadableKeyring {
        load(householdId)?.let { return it }
        val key = ByteArray(KEY_SIZE_BYTES).also(secureRandom::nextBytes)
        return AgentReadableKeyring(householdId, mapOf(1 to key), 1).also(::store)
    }

    fun importKey(householdId: String, keyVersion: Int, rawKey: ByteArray): AgentReadableKeyring {
        requireKey(rawKey)
        require(keyVersion > 0) { "Assistant key version must be positive" }
        val existing = load(householdId)
        val writeVersion = maxOf(existing?.currentWriteVersion ?: keyVersion, keyVersion)
        return AgentReadableKeyring(
            householdId = householdId,
            keys = existing?.keys.orEmpty() + (keyVersion to rawKey.copyOf()),
            currentWriteVersion = writeVersion,
        ).also(::store)
    }

    fun removeHousehold(householdId: String) {
        require(householdId.isNotBlank()) { "Household ID is required" }
        val collection = loadCollection()
        if (collection.households.containsKey(householdId)) {
            storeCollection(collection.copy(households = collection.households - householdId))
        }
    }

    fun encryptString(keyring: AgentReadableKeyring, value: String): VersionedEncryptedPayload {
        val version = keyring.currentWriteVersion
        val key = requireNotNull(keyring.key(version)) { "Current assistant-readable key is missing" }
        val encrypted = UnaPayloadCrypto.encrypt(value.encodeToByteArray(), key, secureRandom)
        return VersionedEncryptedPayload(encrypted.ciphertext, encrypted.nonce, version)
    }

    fun clear() = vault.clear()

    private fun store(keyring: AgentReadableKeyring) {
        val value = keyring.validated()
        val collection = loadCollection()
        val stored = StoredKeyring(
            householdId = value.householdId,
            currentWriteVersion = value.currentWriteVersion,
            keys = value.keys.mapKeys { it.key.toString() }.mapValues { (_, key) ->
                Base64.getUrlEncoder().withoutPadding().encodeToString(key)
            },
        )
        storeCollection(collection.copy(households = collection.households + (value.householdId to stored)))
    }

    private fun loadCollection(): StoredKeyringCollection = vault.load()?.let { record ->
        Json.decodeFromString<StoredKeyringCollection>(record.decodeToString()).also {
            require(it.formatVersion == FORMAT_VERSION) { "Unsupported assistant keyring format" }
        }
    } ?: StoredKeyringCollection(FORMAT_VERSION, emptyMap())

    private fun storeCollection(collection: StoredKeyringCollection) {
        vault.store(Json.encodeToString(collection).encodeToByteArray())
    }

    private fun AgentReadableKeyring.validated(): AgentReadableKeyring {
        require(householdId.isNotBlank()) { "Household ID is required" }
        require(currentWriteVersion > 0) { "Assistant write version must be positive" }
        keys.forEach { (version, key) ->
            require(version > 0) { "Assistant key versions must be positive" }
            requireKey(key)
        }
        require(keys[currentWriteVersion] != null) { "Current assistant-readable key is missing" }
        return this
    }

    private fun requireKey(key: ByteArray) {
        require(key.size == KEY_SIZE_BYTES) { "Una assistant-readable keys must be 32 bytes" }
    }

    @Serializable
    private data class StoredKeyringCollection(
        val formatVersion: Int,
        val households: Map<String, StoredKeyring>,
    )

    @Serializable
    private data class StoredKeyring(
        val householdId: String,
        val currentWriteVersion: Int,
        val keys: Map<String, String>,
    )

    private companion object {
        const val FORMAT_VERSION = 1
        const val KEY_SIZE_BYTES = 32
    }
}
