/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.util.Base64
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import org.json.JSONObject
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Encapsulates a JSON Web Token.
 *
 * @param issuer URL to token issuer.
 * @param audience Intended audience of the token.
 * @param subject Identity associated with the token.
 * @param id unique ID of the token.
 * @param algorithm signature algorithm used to sign the token.
 * @param expiry date/time at which token will expire.
 * @param issuedAt date/time at which the token was issued.
 * @param notValidBefore token is not valid before this time.
 */
data class JWT(
    val issuer: String,
    val audience: String,
    val subject: String,
    val id: String? = null,
    val algorithm: String = DEFAULT_ALGORITHM,
    val keyId: String? = null,
    val expiry: Date = Date(Date().time + (DEFAULT_LIFETIME * 1000)),
    val issuedAt: Date = Date(),
    val notValidBefore: Date? = null,
    val payload: JSONObject = JSONObject(),
) {
    companion object {
        private const val DEFAULT_ALGORITHM = "RS256"
        private const val DEFAULT_LIFETIME = 3600
        private const val ALG = "alg"
        private const val KID = "kid"
        private const val ISS = "iss"
        private const val AUD = "aud"
        private const val IAT = "iat"
        private const val NBF = "nbf"
        private const val EXP = "exp"
        private const val SUB = "sub"
        private const val JTI = "jti"

        /**
         * Validates and decodes JWT.
         *
         * @param encoded JWT.
         * @param keyManager [KeyManagerInterface] to use for validating the signature (optional).
         * @return decoded JWT.
         */
        fun decode(encoded: String, keyManager: KeyManagerInterface? = null): JWT? {
            var jwt: JWT? = null

            val array = encoded.split(".")
            if (array.count() == 3) {
                val headerBytes =
                    Base64.decode(array[0], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                val payloadBytes =
                    Base64.decode(array[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                val signatureBytes =
                    Base64.decode(array[2], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

                if (headerBytes != null && payloadBytes != null && signatureBytes != null) {
                    val headers = JSONObject(String(headerBytes, Charsets.UTF_8))
                    val alg = headers[ALG] as String?
                    val kid = headers[KID] as String?
                    if (alg != null && kid != null) {
                        if (keyManager != null) {
                            // Validate the signature.
                            if (!keyManager.verifySignatureWithPublicKey(
                                    kid,
                                    "${array[0]}.${array[1]}".toByteArray(),
                                    signatureBytes,
                                )
                            ) {
                                return null
                            }
                        }

                        val payload = JSONObject(String(payloadBytes, Charsets.UTF_8))
                        val id = payload.opt(JTI) as String?
                        val issuer = payload.opt(ISS) as String?
                        val audience = payload.opt(AUD) as String?
                        val subject = payload.opt(SUB) as String?
                        val issuedAt = payload.opt(IAT) as Int?
                        val expiry = payload.opt(EXP) as Int?
                        val notValidBefore = payload.opt(NBF) as Int?

                        if (issuer != null &&
                            audience != null &&
                            subject != null &&
                            issuedAt != null &&
                            expiry != null
                        ) {
                            jwt = JWT(
                                issuer,
                                audience,
                                subject,
                                id,
                                alg,
                                kid,
                                Date(TimeUnit.SECONDS.toMillis(expiry.toLong())),
                                Date(TimeUnit.SECONDS.toMillis(issuedAt.toLong())),
                                if (notValidBefore != null) Date(TimeUnit.SECONDS.toMillis(notValidBefore.toLong())) else null,
                                payload,
                            )
                        }
                    }
                }
            }

            return jwt
        }
    }

    /**
     * Sign and encode the token. Mainly used for testing.
     *
     * @param keyManager [KeyManagerInterface] instance used to generate a digital signature.
     * @param keyId identifier of the key to use for generate the signature.
     * @return signed and encoded JWT.
     */
    fun signAndEncode(keyManager: KeyManagerInterface, keyId: String): String {
        val headers = JSONObject(
            mapOf(
                ALG to this.algorithm,
                KID to keyId,
            ),
        )

        val id = this.id ?: UUID.randomUUID().toString()
        val payload: MutableMap<String, Any> = mutableMapOf<String, Any>(
            JTI to id,
            ISS to this.issuer,
            AUD to this.audience,
            SUB to this.subject,
            IAT to TimeUnit.MILLISECONDS.toSeconds(this.issuedAt.time),
            EXP to TimeUnit.MILLISECONDS.toSeconds(this.expiry.time),
        )

        if (this.notValidBefore != null) {
            payload[NBF] = TimeUnit.MILLISECONDS.toSeconds(this.notValidBefore.time)
        }

        this.payload.keys().forEach { payload[it] = this.payload[it] }

        val encodedHeader = Base64.encodeToString(
            headers.toString().toByteArray(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )

        val encodedPayload = Base64.encodeToString(
            JSONObject(payload as Map<*, *>).toString().toByteArray(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )

        val encoded = "$encodedHeader.$encodedPayload"

        val signature = keyManager.generateSignatureWithPrivateKey(keyId, encoded.toByteArray())

        return "$encoded.${Base64.encodeToString(
            signature,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )}"
    }
}
