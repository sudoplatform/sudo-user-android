/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.util.Base64
import org.json.JSONObject

/**
 * Encapsulates a public key used for asymmetric cryptographic operations.
 *
 * @param keyId unique ID of the key.
 * @param publicKey public key bytes.
 * @param algorithm asymmetric cryptography algorithm associated with the key
 * @param symmetricAlgorithm symmetric cryptography algorithm associated with symmetric key sealed by this public key.
 */
data class PublicKey(
    val keyId: String,
    val publicKey: ByteArray,
    val algorithm: String = RSA,
    val symmetricAlgorithm: String = AES_256
) {

    companion object {
        private const val ALGORITHM = "algorithm"
        private const val SYMMETRIC_ALGORITHM = "symmetricAlgorithm"
        private const val PUBLIC_KEY = "publicKey"
        private const val KEY_ID = "keyId"

        private const val RSA = "RSA"
        private const val AES_256 = "AES/256"
    }

    /**
     * Encode the key as [String].
     *
     * @return encoded key.
     */
    fun encode(): String {
        val json = JSONObject(
            mapOf(
                ALGORITHM to this.algorithm,
                SYMMETRIC_ALGORITHM to this.symmetricAlgorithm,
                KEY_ID to this.keyId,
                PUBLIC_KEY to Base64.encodeToString(this.publicKey, Base64.NO_WRAP)
            )
        )

        return json.toString()
    }

    // generated due to ByteArray property in data class
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKey

        if (keyId != other.keyId) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (algorithm != other.algorithm) return false
        if (symmetricAlgorithm != other.symmetricAlgorithm) return false

        return true
    }

    // generated due to ByteArray property in data class
    override fun hashCode(): Int {
        var result = keyId.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + symmetricAlgorithm.hashCode()
        return result
    }

}