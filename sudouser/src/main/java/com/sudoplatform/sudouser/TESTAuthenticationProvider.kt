/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.util.Base64
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import java.util.*

/**
 * Authentication info consisting of a JWT signed using the TEST registration key.
 */
class TESTAuthenticationInfo(private val jwt: String) : AuthenticationInfo {

    override val type: String = "TEST"

    override fun encode(): String {
        return this.jwt
    }

    override fun isValid(): Boolean {
        return true
    }

}

/**
 * Authentication provider for generating authentication info using a TEST registration key.
 *
 * @param name provider name. This name will be prepend to the generated UUID in JWT sub.
 * @param privateKey PEM encoded RSA private key.
 * @param publicKey PEM encoded RSA public key.
 * @param keyManager [KeyManagerInterface] instance to use for signing authentication info.
 */
class TESTAuthenticationProvider(
    private val name: String,
    privateKey: String,
    publicKey: String,
    private val keyManager: KeyManagerInterface
) :
    AuthenticationProvider {

    companion object {
        private const val REGISTER_KEY_NAME = "register_key"
        private const val TEST_REGISTRATION_ISSUER = "testRegisterIssuer"
        private const val TEST_REGISTRATION_AUDIENCE = "testRegisterAudience"
    }

    init {
        val privateKeyData = Base64.decode(
            privateKey.replace("\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", ""), Base64.DEFAULT
        )

        val publicKeyData = Base64.decode(
            publicKey.replace("\n", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", ""), Base64.DEFAULT
        )

        this.keyManager.deleteKeyPair(REGISTER_KEY_NAME)
        this.keyManager.addKeyPair(privateKeyData, publicKeyData, REGISTER_KEY_NAME)
    }

    override fun getAuthenticationInfo(): AuthenticationInfo {
        val jwt = JWT(TEST_REGISTRATION_ISSUER, TEST_REGISTRATION_AUDIENCE, "${this.name}-${UUID.randomUUID().toString()}", UUID.randomUUID().toString())
        return TESTAuthenticationInfo(jwt.signAndEncode(this.keyManager, REGISTER_KEY_NAME))
    }

    override fun reset() {}

}
