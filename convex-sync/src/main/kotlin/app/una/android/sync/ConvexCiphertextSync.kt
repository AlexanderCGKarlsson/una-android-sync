package app.una.android.sync

import app.una.android.crypto.VersionedEncryptedPayload
import dev.convex.android.ConvexClientWithAuth
import kotlinx.coroutines.flow.Flow

// @notice This transport type deliberately cannot represent plaintext or raw key material.
// @dev Encrypt with crypto-core before constructing it do not add convenience plaintext fields.
class EncryptedArgument(
    ciphertext: ByteArray,
    nonce: ByteArray,
    val keyVersion: Int,
) {
    private val ciphertextBytes = ciphertext.copyOf()
    private val nonceBytes = nonce.copyOf()

    init {
        require(ciphertextBytes.size >= AUTHENTICATION_TAG_SIZE_BYTES) {
            "Encrypted payload must include its authentication tag"
        }
        require(nonceBytes.size == NONCE_SIZE_BYTES) { "Encrypted payload nonces must be 12 bytes" }
        require(keyVersion > 0) { "Encrypted payload key versions must be positive" }
    }

    val ciphertext: ByteArray
        get() = ciphertextBytes.copyOf()

    val nonce: ByteArray
        get() = nonceBytes.copyOf()

    internal fun toConvexMap(): Map<String, Any> = mapOf(
        "ciphertext" to ciphertextBytes.copyOf(),
        "nonce" to nonceBytes.copyOf(),
        "keyVersion" to keyVersion.toDouble(),
    )

    companion object {
        private const val NONCE_SIZE_BYTES = 12
        private const val AUTHENTICATION_TAG_SIZE_BYTES = 16

        fun from(payload: VersionedEncryptedPayload): EncryptedArgument = EncryptedArgument(
            ciphertext = payload.ciphertext,
            nonce = payload.nonce,
            keyVersion = payload.keyVersion,
        )
    }
}

// @notice indexedArguments are visible to the service and must contain operational metadata only.
// @dev Keep this adapter narrow so user-entered content cannot bypass the on device encryption.
class ConvexCiphertextSync(
    @PublishedApi internal val client: ConvexClientWithAuth<*>,
) {
    suspend inline fun <reified T> mutate(
        functionName: String,
        payload: EncryptedArgument,
        payloadArgumentName: String = "payload",
        indexedArguments: Map<String, Any> = emptyMap(),
    ): T = client.mutation<T>(
        functionName,
        buildArguments(payload, payloadArgumentName, indexedArguments),
    )

    inline fun <reified T> subscribe(
        functionName: String,
        indexedArguments: Map<String, Any> = emptyMap(),
    ): Flow<Result<T>> = client.subscribe<T>(functionName, indexedArguments)

    companion object {
        @PublishedApi
        internal fun buildArguments(
            payload: EncryptedArgument,
            payloadArgumentName: String,
            indexedArguments: Map<String, Any>,
        ): Map<String, Any> {
            require(functionNameSafe(payloadArgumentName)) { "Payload argument name is invalid" }
            require(payloadArgumentName !in indexedArguments) {
                "Indexed arguments must not replace the encrypted payload"
            }
            return indexedArguments + (payloadArgumentName to payload.toConvexMap())
        }

        private fun functionNameSafe(value: String): Boolean =
            value.isNotBlank() && value.all { it.isLetterOrDigit() || it == '_' }
    }
}
