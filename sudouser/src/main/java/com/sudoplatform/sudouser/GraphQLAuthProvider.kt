/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import com.amazonaws.mobileconnectors.appsync.sigv4.CognitoUserPoolsAuthProvider
import com.sudoplatform.sudouser.exceptions.AuthenticationException
import kotlinx.coroutines.runBlocking
import java.util.Date

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
                return try {
                    val result = runBlocking {
                        this@GraphQLAuthProvider.client.refreshTokens(refreshToken)
                    }
                    result.idToken
                } catch (e: AuthenticationException.NotAuthorizedException) {
                    // Catch any NotAuthorizedException and return an invalid ID
                    // token. This avoids AppSync going into a retry loop and
                    // correctly return not authorized error to the caller.
                    ""
                } catch (t: Throwable) {
                    throw t
                }
            }
        } else {
            // If tokens are missing then it's likely due to the client not being signed in.
            throw AuthenticationException.NotSignedInException("Client is not signed in.")
        }
    }
}