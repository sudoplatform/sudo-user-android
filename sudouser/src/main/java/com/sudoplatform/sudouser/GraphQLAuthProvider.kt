/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import com.amazonaws.AmazonClientException
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
                    // There's a bug in AWSAppSync SDK's subscription code path
                    // where throwing any exception other than AmazonClientException
                    // will cause the app to crash. However, throwing AmazonClientException
                    // will always cause the subscription to be re-tried. Unfortunately,
                    // there's currently no way to throw an exception to indicate that
                    // there's a non-recoverable error. The best we can do is to return
                    // an empty string to cause an authorization error to abort the retry.
                    // This could be misleading in some cases because the consumer might
                    // attempt to sign in again. This is a temporary measure until the
                    // AWSAppSync SDK bug is fixed.
                    val cause = t.cause
                    if (cause != null && cause is AmazonClientException && cause.isRetryable) {
                        // Throwing AmazonClientException will cause the subscription to be
                        // retried so we use our best guess as to whether or not the underlying
                        // error is recoverable.
                        throw AmazonClientException("Failed to refresh tokens", t)
                    }
                    // We have not detected recoverable error so we return an empty string to cause
                    // an authorization error. We actually don't have any other option.
                    return ""
                }
            }
        } else {
            // If tokens are missing then it's likely due to the client not being signed in.
            // Return an empty string because of the subscription related AWSAppSync SDK bug
            // mentioned previously.
            return ""
        }
    }
}