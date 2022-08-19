/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.util.Base64
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import org.json.JSONObject
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.UUID

/**
 * Authentication info consisting of a JWT signed using the locally stored private key.
 */
class LocalAuthenticationInfo(private val jwt: String, private val username: String) : AuthenticationInfo {

    override val type: String = "FSSO"

    override fun encode(): String {
        return this.jwt
    }

    override fun isValid(): Boolean {
        return true
    }

    override fun getUsername(): String {
        return this.username
    }

}

/**
 * Authentication provider for generating authentication info using a locally stored private key.
 *
 * @param name provider name. This name will be prepend to the generated UUID in JWT sub.
 * @param privateKey PEM encoded RSA private key.
 * @param publicKey PEM encoded RSA public key. This is optional. If not provided then will be
 * derived from the private key.
 * @param keyManager [KeyManagerInterface] instance to use for signing authentication info.
 * @param keyId key ID of the private key used to sign the authentication info.
 * @param username username be associated with the issued authentication info.
 * @param customAttributes custom attributes to add to the issued authentication info.
 */
class LocalAuthenticationProvider(
    private val name: String,
    privateKey: String,
    publicKey: String?,
    private val keyManager: KeyManagerInterface,
    private val keyId: String,
    private val username: String,
    private val customAttributes: Map<String, Any>? = null
) :
    AuthenticationProvider {

    companion object {
        private const val AUDIENCE = "identity-service"
    }

    init {
        val privateKeyData = Base64.decode(
            privateKey.replace("\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", ""), Base64.DEFAULT
        )

        val publicKeyData: ByteArray
        if(publicKey != null) {
            publicKeyData = Base64.decode(
                publicKey.replace("\n", "")
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", ""), Base64.DEFAULT
            )
        } else {
            // Generated the public key from the private key bits.
            val keySpec = PKCS8EncodedKeySpec(privateKeyData)
            val factory = KeyFactory.getInstance("RSA")

            val key: RSAPrivateCrtKey = factory.generatePrivate(keySpec) as RSAPrivateCrtKey

            val publicKeySpec =
                RSAPublicKeySpec(key.modulus, key.publicExponent)

            val publicKeyInfo =
                SubjectPublicKeyInfo.getInstance(factory.generatePublic(
                    publicKeySpec
                ).encoded)
            val publicKeyPKCS1ASN1 = publicKeyInfo.parsePublicKey()
            publicKeyData = publicKeyPKCS1ASN1.encoded
        }

        this.keyManager.deleteKeyPair(this.keyId)
        this.keyManager.addKeyPair(privateKeyData, publicKeyData, this.keyId)
    }

    override suspend fun getAuthenticationInfo(): AuthenticationInfo {
        val jwt = JWT(this.name, AUDIENCE, this.username, UUID.randomUUID().toString(), payload = if (this.customAttributes != null) JSONObject(this.customAttributes) else JSONObject())
        return LocalAuthenticationInfo(jwt.signAndEncode(this.keyManager, this.keyId), this.username)
    }

    override fun reset() {}
}
