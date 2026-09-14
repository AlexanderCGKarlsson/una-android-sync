package app.una.android.crypto

import java.security.SecureRandom
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

data class HouseholdKeyring(
    val householdId: String,
    val keys: Map<Int, ByteArray>,
    val currentWriteVersion: Int,
) {
    fun key(version: Int): ByteArray? = keys[version]?.copyOf()
}

data class InviteHouseholdKeyring(
    val keys: Map<Int, ByteArray>,
    val currentWriteVersion: Int,
) {
    fun currentKey(): ByteArray = requireNotNull(keys[currentWriteVersion]) {
        "Invite household keyring is missing its current key"
    }.copyOf()
}

data class VersionedEncryptedPayload(
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val keyVersion: Int,
)

interface KeyringVault {
    fun store(keyring: ByteArray)
    fun load(): ByteArray?
    fun clear()
}

/**
 * Owns Android's local household keyring contract.
 *
 * Historical key versions are retained for reads. Preparing a rotation persists the next key but
 * leaves currentWriteVersion unchanged; commitRotation is called only after Convex confirms the
 * wrapped-key transaction.
 */
class HouseholdKeyringManager(
    private val vault: KeyringVault,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    fun generateHouseholdKey(): ByteArray = ByteArray(KEY_SIZE_BYTES).also(secureRandom::nextBytes)

    fun prepareBootstrapKey(identityScope: String): ByteArray {
        require(identityScope.isNotBlank()) { "Bootstrap identity scope is required" }
        val collection = loadCollection()
        collection.pendingBootstrapKeys[identityScope]?.let { encoded ->
            return Base64.getUrlDecoder().decode(encoded).also(::requireKey)
        }
        val key = generateHouseholdKey()
        storeCollection(
            collection.copy(
                pendingBootstrapKey = null,
                pendingBootstrapKeys = collection.pendingBootstrapKeys + (
                    identityScope to Base64.getUrlEncoder().withoutPadding().encodeToString(key)
                ),
            ),
        )
        return key
    }

    fun pendingBootstrapKey(identityScope: String): ByteArray? {
        require(identityScope.isNotBlank()) { "Bootstrap identity scope is required" }
        return loadCollection().pendingBootstrapKeys[identityScope]?.let { encoded ->
            Base64.getUrlDecoder().decode(encoded).also(::requireKey)
        }
    }

    fun discardPendingBootstrapKey(identityScope: String) {
        require(identityScope.isNotBlank()) { "Bootstrap identity scope is required" }
        val collection = loadCollection()
        if (collection.pendingBootstrapKeys.containsKey(identityScope)) {
            storeCollection(
                collection.copy(
                    pendingBootstrapKey = null,
                    pendingBootstrapKeys = collection.pendingBootstrapKeys - identityScope,
                ),
            )
        }
    }

    fun create(householdId: String, firstKey: ByteArray): HouseholdKeyring {
        require(householdId.isNotBlank()) { "Household ID is required" }
        requireKey(firstKey)
        return HouseholdKeyring(
            householdId = householdId,
            keys = mapOf(1 to firstKey.copyOf()),
            currentWriteVersion = 1,
        ).also(::store)
    }

    fun completeBootstrap(
        householdId: String,
        firstKey: ByteArray,
        identityScope: String,
    ): HouseholdKeyring {
        requireKey(firstKey)
        require(identityScope.isNotBlank()) { "Bootstrap identity scope is required" }
        val collection = loadCollection()
        val pending = collection.pendingBootstrapKeys[identityScope]
            ?.let(Base64.getUrlDecoder()::decode)
        if (pending != null) {
            require(pending.contentEquals(firstKey)) { "Bootstrap key does not match the pending key" }
        }
        val keyring = HouseholdKeyring(
            householdId = householdId,
            keys = mapOf(1 to firstKey.copyOf()),
            currentWriteVersion = 1,
        ).validated()
        val stored = keyring.toStoredKeyring()
        storeCollection(
            collection.copy(
                households = collection.households + (householdId to stored),
                pendingBootstrapKey = null,
                pendingBootstrapKeys = collection.pendingBootstrapKeys - identityScope,
            ),
        )
        return keyring
    }

    fun load(householdId: String): HouseholdKeyring? {
        val collection = loadCollection()
        val stored = collection.households[householdId] ?: return null
        val keys = stored.keys.mapKeys { (version, _) ->
            version.toIntOrNull()?.takeIf { it > 0 } ?: error("Invalid household key version")
        }.mapValues { (_, encoded) ->
            Base64.getUrlDecoder().decode(encoded).also(::requireKey)
        }
        return HouseholdKeyring(
            householdId = stored.householdId,
            keys = keys,
            currentWriteVersion = stored.currentWriteVersion,
        ).validated()
    }

    fun hasStoredHouseholdKeyHint(): Boolean = loadCollection().households.isNotEmpty()

    fun encryptString(keyring: HouseholdKeyring, value: String): VersionedEncryptedPayload {
        val version = keyring.currentWriteVersion
        val key = keyring.key(version) ?: error("Current household write key is missing")
        return encryptString(value, key, version)
    }

    fun encryptString(value: String, key: ByteArray, keyVersion: Int): VersionedEncryptedPayload {
        requireKey(key)
        require(keyVersion > 0) { "Household key version must be positive" }
        val encrypted = UnaPayloadCrypto.encrypt(value.encodeToByteArray(), key, secureRandom)
        return VersionedEncryptedPayload(
            ciphertext = encrypted.ciphertext,
            nonce = encrypted.nonce,
            keyVersion = keyVersion,
        )
    }

    fun importKey(
        householdId: String,
        keyVersion: Int,
        rawKey: ByteArray,
    ): HouseholdKeyring {
        requireKey(rawKey)
        require(keyVersion > 0) { "Household key version must be positive" }
        val existing = load(householdId) ?: HouseholdKeyring(householdId, emptyMap(), keyVersion)
        return existing.copy(
            keys = existing.keys + (keyVersion to rawKey.copyOf()),
        ).validated().also(::store)
    }

    fun exportInviteKeyring(householdId: String): String {
        val keyring = requireNotNull(load(householdId)) { "Household keyring is missing" }
        val invite = StoredInviteKeyring(
            formatVersion = INVITE_FORMAT_VERSION,
            currentWriteVersion = keyring.currentWriteVersion,
            keys = keyring.keys.mapKeys { it.key.toString() }.mapValues { (_, key) ->
                Base64.getUrlEncoder().withoutPadding().encodeToString(key)
            },
        )
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(Json.encodeToString(invite).encodeToByteArray())
    }

    fun decodeInviteKeyring(encoded: String): InviteHouseholdKeyring {
        val decoded = Base64.getUrlDecoder().decode(encoded)
        val invite = Json.decodeFromString<StoredInviteKeyring>(decoded.decodeToString())
        require(invite.formatVersion == INVITE_FORMAT_VERSION) { "Unsupported invite keyring format" }
        require(invite.currentWriteVersion > 0) { "Invite write version must be positive" }
        val keys = invite.keys.mapKeys { (version, _) ->
            version.toIntOrNull()?.takeIf { it > 0 } ?: error("Invalid invite key version")
        }.mapValues { (_, key) ->
            Base64.getUrlDecoder().decode(key).also(::requireKey)
        }
        require(keys[invite.currentWriteVersion] != null) { "Invite keyring is missing its current key" }
        return InviteHouseholdKeyring(keys, invite.currentWriteVersion)
    }

    fun importInviteKeyring(
        householdId: String,
        encoded: String,
    ): HouseholdKeyring {
        val invite = decodeInviteKeyring(encoded)
        return HouseholdKeyring(
            householdId = householdId,
            keys = invite.keys.mapValues { it.value.copyOf() },
            currentWriteVersion = invite.currentWriteVersion,
        ).validated().also(::store)
    }

    fun removeHousehold(householdId: String) {
        require(householdId.isNotBlank()) { "Household ID is required" }
        val collection = loadCollection()
        if (collection.households.containsKey(householdId)) {
            storeCollection(collection.copy(households = collection.households - householdId))
        }
    }

    fun prepareRotation(householdId: String, currentVersion: Int): HouseholdKeyring {
        val existing = requireNotNull(load(householdId)) { "Household keyring is missing" }
        require(existing.currentWriteVersion == currentVersion) {
            "Local write version does not match the server rotation base"
        }
        require(existing.keys[currentVersion] != null) { "Current household key is missing" }
        val nextVersion = currentVersion + 1
        val nextKey = existing.keys[nextVersion] ?: generateHouseholdKey()
        return existing.copy(
            keys = existing.keys + (nextVersion to nextKey),
        ).also(::store)
    }

    fun commitRotation(householdId: String, targetVersion: Int): HouseholdKeyring {
        val existing = requireNotNull(load(householdId)) { "Household keyring is missing" }
        require(targetVersion == existing.currentWriteVersion + 1) {
            "Household rotations must advance exactly one version"
        }
        require(existing.keys[targetVersion] != null) { "Rotated household key is missing" }
        return existing.copy(currentWriteVersion = targetVersion).also(::store)
    }

    fun alignWriteVersion(householdId: String, serverVersion: Int): HouseholdKeyring {
        val existing = requireNotNull(load(householdId)) { "Household keyring is missing" }
        require(existing.keys[serverVersion] != null) { "Server household key is not available locally" }
        return existing.copy(currentWriteVersion = serverVersion).also(::store)
    }

    fun clear() = vault.clear()

    private fun store(keyring: HouseholdKeyring) {
        val validated = keyring.validated()
        val existing = loadCollection()
        val stored = validated.toStoredKeyring()
        storeCollection(existing.copy(households = existing.households + (validated.householdId to stored)))
    }

    private fun HouseholdKeyring.toStoredKeyring(): StoredKeyring =
        StoredKeyring(
            householdId = householdId,
            currentWriteVersion = currentWriteVersion,
            keys = keys.mapKeys { it.key.toString() }.mapValues { (_, key) ->
                Base64.getUrlEncoder().withoutPadding().encodeToString(key)
            },
        )

    private fun loadCollection(): StoredKeyringCollection = vault.load()?.let { record ->
        Json.decodeFromString<StoredKeyringCollection>(record.decodeToString()).also {
            require(it.formatVersion == FORMAT_VERSION) { "Unsupported keyring format" }
        }
    } ?: StoredKeyringCollection(FORMAT_VERSION, emptyMap(), null, emptyMap())

    private fun storeCollection(collection: StoredKeyringCollection) {
        vault.store(Json.encodeToString(collection).encodeToByteArray())
    }

    private fun HouseholdKeyring.validated(): HouseholdKeyring {
        require(householdId.isNotBlank()) { "Household ID is required" }
        require(currentWriteVersion > 0) { "Current write version must be positive" }
        keys.forEach { (version, key) ->
            require(version > 0) { "Household key versions must be positive" }
            requireKey(key)
        }
        require(keys[currentWriteVersion] != null) { "Current household write key is missing" }
        return this
    }

    private fun requireKey(key: ByteArray) {
        require(key.size == KEY_SIZE_BYTES) { "Una household keys must be 32 bytes" }
    }

    @Serializable
    private data class StoredKeyringCollection(
        val formatVersion: Int,
        val households: Map<String, StoredKeyring>,
        // Decode-only compatibility for an earlier unscoped Android development record.
        val pendingBootstrapKey: String? = null,
        val pendingBootstrapKeys: Map<String, String> = emptyMap(),
    )

    @Serializable
    private data class StoredKeyring(
        val householdId: String,
        val currentWriteVersion: Int,
        val keys: Map<String, String>,
    )

    @Serializable
    private data class StoredInviteKeyring(
        val formatVersion: Int,
        val currentWriteVersion: Int,
        val keys: Map<String, String>,
    )

    private companion object {
        const val FORMAT_VERSION = 1
        const val INVITE_FORMAT_VERSION = 1
        const val KEY_SIZE_BYTES = 32
    }
}
