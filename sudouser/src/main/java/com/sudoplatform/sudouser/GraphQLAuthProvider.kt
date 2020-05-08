/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import com.amazonaws.mobileconnectors.appsync.sigv4.CognitoUserPoolsAuthProvider
import kotlinx.coroutines.runBlocking
import java.util.*
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * [SudoUserClient] based authentication provider implementation to be used by AWS AppSync client.
 */
class GraphQLAuthProvider(private val client: SudoUserClient) : CognitoUserPoolsAuthProvider {

    override fun getLatestAuthToken(): String {
        val idToken = this@GraphQLAuthProvider.client.getIdToken()
        val refreshToken = this@GraphQLAuthProvider.client.getRefreshToken()
        val expiry = this@GraphQLAuthProvider.client.getTokenExpiry()

        if (idToken != null && refreshToken != null && expiry != null) {
            if (expiry.time > Date().time + 600 * 1000) {
                return idToken
            } else {
                // Refresh the token if it has expired or will expire in 10 mins.
                val result = runBlocking {
                    this@GraphQLAuthProvider.refreshTokens(refreshToken)
                }

                when(result) {
                    is SignInResult.Success -> {
                        return result.idToken
                    }
                    is SignInResult.Failure -> {
                        throw result.error
                    }
                }
            }
        } else {
            // If tokens are missing then it's likely due to the client not being signed in.
            throw ApiException(
                ApiErrorCode.NOT_SIGNED_IN,
                "Client is not signed in."
            )
        }
    }

    private suspend fun refreshTokens(refreshToken: String): SignInResult = suspendCoroutine { cont ->
        this.client.refreshTokens(refreshToken) { cont.resume(it) }
    }

}