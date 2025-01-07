/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.app.Activity
import android.content.Context
import android.net.Uri
import com.amazonaws.mobileconnectors.cognitoauth.Auth
import com.amazonaws.mobileconnectors.cognitoauth.AuthUserSession
import com.amazonaws.mobileconnectors.cognitoauth.handlers.AuthHandler
import com.sudoplatform.sudouser.exceptions.SudoUserException
import org.json.JSONObject
import java.util.Date

/**
 * Encapsulates a federated sign-in result.
 */
sealed class FederatedSignInResult {
    /**
     * Encapsulates a successful sign-in result.
     *
     * @param idToken ID token containing the user's identity attributes.
     * @param accessToken access token required for authorizing API access.
     * @param refreshToken refresh token used for refreshing ID and access tokens.
     * @param lifetime lifetime of ID and access tokens in seconds.
     */
    data class Success(
        val idToken: String,
        val accessToken: String,
        val refreshToken: String,
        val lifetime: Int,
        val username: String,
    ) :
        FederatedSignInResult()

    /**
     * Encapsulates a failed sign-in result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : FederatedSignInResult()
}

/**
 *  Responsible for managing the authentication flow for browser based federated sign in.
 */
interface AuthUI : AutoCloseable {

    /**
     * Presents the sign in UI for federated sign in using an external identity provider.
     *
     * @param activity activity to launch custom tabs from and to listen for the intent completions.
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     */
    fun presentFederatedSignInUI(activity: Activity, callback: (FederatedSignInResult) -> Unit)

    /**
     * Presents the sign out UI for federated sign in using an external identity provider.
     *
     * @param callback callback for returning successful sign out result or error.
     */
    fun presentFederatedSignOutUI(callback: (ApiResult) -> Unit)

    /**
     * Processes tokens from federated sign in via Android intent data pointed to by the specified URL. The tokens
     * are passed to the app via a redirect URL with custom scheme mapped to the app.
     *
     * @param data URL to intent data containing the tokens.
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     */
    fun processFederatedSignInTokens(data: Uri, callback: (FederatedSignInResult) -> Unit)

    /**
     * Resets any internal state.
     */
    fun reset()
}

/**
 *  AuthUI implementation that uses Cognito Auth UI.
 *
 * @param config configuration parameters.
 * @param context Android app context.
 */
class CognitoAuthUI(val config: JSONObject, val context: Context) :
    AuthUI {

    companion object {
        private const val CONFIG_APP_CLIENT_ID = "appClientId"
        private const val CONFIG_WEB_DOMAIN = "webDomain"
        private const val CONFIG_SIGN_IN_REDIRECT_URI = "signInRedirectUri"
        private const val CONFIG_SIGN_OUT_REDIRECT_URI = "signOutRedirectUri"
    }

    /**
     * Builder for AWS Cognito Auth API used for federated sign in.
     */
    private var authBuilder: Auth.Builder

    /** [Auth] instances that might be bound to a service and require releasing */
    private val boundAuthInstances = mutableListOf<Auth>()

    init {
        val appClientId = config[CONFIG_APP_CLIENT_ID] as String?
        val webDomain = config[CONFIG_WEB_DOMAIN] as String?
        val signInRedirectUri = config[CONFIG_SIGN_IN_REDIRECT_URI] as String?
        val signOutRedirectUri = config[CONFIG_SIGN_OUT_REDIRECT_URI] as String?

        if (appClientId == null ||
            webDomain == null ||
            signInRedirectUri == null ||
            signOutRedirectUri == null
        ) {
            throw IllegalArgumentException("appClientId, webDomain, signInRedirectUri or signOutRedirectUri was null.")
        }

        this.authBuilder = Auth.Builder().setApplicationContext(context)
            .setAppClientId(appClientId)
            .setScopes(arrayOf("openid").toSet())
            .setAppCognitoWebDomain(webDomain)
            .setSignInRedirect(signInRedirectUri)
            .setSignOutRedirect(signOutRedirectUri)
    }

    override fun presentFederatedSignInUI(activity: Activity, callback: (FederatedSignInResult) -> Unit) {
        val auth = authBuilder.setAuthHandler(object : AuthHandler {
            override fun onSuccess(session: AuthUserSession) {
                val idToken = session.idToken.jwtToken
                val username = session.username
                val accessToken = session.accessToken.jwtToken
                val refreshToken = session.refreshToken.token
                val expirationTime = session.idToken.expiration
                if (idToken != null &&
                    accessToken != null &&
                    refreshToken != null &&
                    expirationTime != null &&
                    username != null
                ) {
                    val lifetime = (expirationTime.time - Date().time) / 1000

                    callback(
                        FederatedSignInResult.Success(
                            idToken,
                            accessToken,
                            refreshToken,
                            lifetime.toInt(),
                            username,
                        ),
                    )
                } else {
                    callback(
                        FederatedSignInResult.Failure(
                            SudoUserException.FailedException(
                                "Authentication tokens missing.",
                            ),
                        ),
                    )
                }
            }

            override fun onSignout() {
                callback(
                    FederatedSignInResult.Failure(
                        IllegalStateException("Sign in caused sign out callback to be called."),
                    ),
                )
            }

            override fun onFailure(e: Exception) {
                callback(FederatedSignInResult.Failure(e))
            }
        }).build()

        auth.getSession(activity)
        boundAuthInstances.add(auth)
    }

    override fun presentFederatedSignOutUI(callback: (ApiResult) -> Unit) {
        val auth = this.authBuilder.setAuthHandler(object : AuthHandler {
            override fun onSuccess(session: AuthUserSession) {
                callback(
                    ApiResult.Failure(
                        IllegalStateException("Sign out caused sign in callback to be called."),
                    ),
                )
            }

            override fun onSignout() {
                callback(ApiResult.Success)
            }

            override fun onFailure(e: Exception) {
                callback(ApiResult.Failure(e))
            }
        }).build()

        auth.signOut()
        boundAuthInstances.add(auth)
    }

    override fun processFederatedSignInTokens(data: Uri, callback: (FederatedSignInResult) -> Unit) {
        val auth = this.authBuilder.setAuthHandler(object : AuthHandler {
            override fun onSuccess(session: AuthUserSession) {
                val idToken = session.idToken.jwtToken
                val username = session.username
                val accessToken = session.accessToken.jwtToken
                val refreshToken = session.refreshToken.token
                val expirationTime = session.idToken.expiration
                if (idToken != null &&
                    accessToken != null &&
                    refreshToken != null &&
                    expirationTime != null &&
                    username != null
                ) {
                    val lifetime = (expirationTime.time - Date().time) / 1000

                    callback(
                        FederatedSignInResult.Success(
                            idToken,
                            accessToken,
                            refreshToken,
                            lifetime.toInt(),
                            username,
                        ),
                    )
                } else {
                    callback(
                        FederatedSignInResult.Failure(
                            SudoUserException.FailedException(
                                "Authentication tokens missing.",
                            ),
                        ),
                    )
                }
            }

            override fun onSignout() {
                callback(
                    FederatedSignInResult.Failure(
                        IllegalStateException("Sign in caused sign out callback to be called."),
                    ),
                )
            }

            override fun onFailure(e: Exception) {
                callback(FederatedSignInResult.Failure(e))
            }
        }).build()

        auth.getTokens(data)
        boundAuthInstances.add(auth)
    }

    override fun reset() {
        val auth = this.authBuilder.setAuthHandler(object : AuthHandler {
            override fun onSuccess(session: AuthUserSession) {
            }

            override fun onSignout() {
            }

            override fun onFailure(e: Exception) {
            }
        }).build()

        auth.signOut(true)
        boundAuthInstances.add(auth)
    }

    override fun close() {
        boundAuthInstances.forEach { auth ->
            try {
                auth.release()
            } catch (e: Exception) {
                // Suppress
            }
        }
        boundAuthInstances.clear()
    }
}
