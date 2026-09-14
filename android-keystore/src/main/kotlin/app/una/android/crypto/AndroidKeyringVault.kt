package app.una.android.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Local-at-rest protection for an exportable Una household keyring.
 *
 * The KEK never leaves Android Keystore. The encrypted keyring is deliberately written to
 * noBackupFilesDir so a restore cannot separate the ciphertext from the device-bound KEK.
 */
class AndroidKeyringVault(context: Context) : KeyringVault {
    private val file = AtomicFile(context.noBackupFilesDir.resolve(FILE_NAME))

    override fun store(keyring: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(keyring)
        val record = byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + encrypted

        val stream = file.startWrite()
        try {
            stream.write(record)
            file.finishWrite(stream)
        } catch (error: Throwable) {
            file.failWrite(stream)
            throw error
        }
    }

    override fun load(): ByteArray? {
        if (!file.baseFile.exists()) return null
        val record = file.readFully()
        require(record.isNotEmpty()) { "Keyring vault is empty" }
        val nonceSize = record[0].toInt() and 0xff
        require(nonceSize == 12 && record.size > 1 + nonceSize + 16) { "Keyring vault is invalid" }
        val nonce = record.copyOfRange(1, 1 + nonceSize)
        val ciphertext = record.copyOfRange(1 + nonceSize, record.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext)
    }

    override fun clear() {
        file.delete()
        val keyStore = keyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = keyStore()
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "app.una.android.household-keyring-kek.v1"
        const val FILE_NAME = "household-keyring.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
