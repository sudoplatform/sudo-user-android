/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.content.Context
import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AnonymousAWSCredentials
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.regions.Region
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidentityprovider.AmazonCognitoIdentityProviderClient
import com.amazonaws.services.cognitoidentityprovider.model.DeleteUserRequest
import com.amazonaws.services.cognitoidentityprovider.model.GlobalSignOutRequest
import com.amazonaws.services.cognitoidentityprovider.model.InitiateAuthRequest
import com.amazonaws.services.cognitoidentityprovider.model.NotAuthorizedException
import com.amazonaws.services.cognitoidentityprovider.model.RespondToAuthChallengeRequest
import com.amazonaws.services.cognitoidentityprovider.model.RevokeTokenRequest
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.exceptions.AuthenticationException
import com.sudoplatform.sudouser.exceptions.DeregisterException
import com.sudoplatform.sudouser.exceptions.RegisterException
import com.sudoplatform.sudouser.exceptions.SignOutException
import com.sudoplatform.sudouser.extensions.signUp
import org.json.JSONObject
import java.util.Date

/**
 * Encapsulates a generic API result.
 */
sealed class ApiResult {
    /**
     * Encapsulates a successful API result.
     */
    object Success : ApiResult()

    /**
     * Encapsulates a failed API result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : ApiResult()
}

/**
 * Encapsulates a registration result.
 */
sealed class RegisterResult {
    /**
     * Encapsulates a successful registration result.
     *
     * @param uid user ID of the newly registered user.
     */
    data class Success(val uid: String) : RegisterResult()

    /**
     * Encapsulates a failed registration result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : RegisterResult()
}

/**
 * Encapsulates a sign-in result.
 */
sealed class SignInResult {
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
        val lifetime: Int
    ) :
        SignInResult()

    /**
     * Encapsulates a failed sign-in result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : SignInResult()
}

/**
 * Encapsulates the authentication tokens obtained from a successful authentication.
 *
 * @param idToken ID token containing the user's identity attributes.
 * @param accessToken access token required for authorizing API access.
 * @param refreshToken refresh token used for refreshing ID and access tokens.
 * @param lifetime lifetime of ID and access tokens in seconds.
 */
data class AuthenticationTokens(
    val idToken: String,
    val accessToken: String,
    val refreshToken: String,
    val lifetime: Int
)

/**
 * Encapsulates interface requirements for an external identity provider to register and authenticate an identity
 * within Sudo platform ecosystem.
 */
interface IdentityProvider {

    /**
     * Registers a new user against the identity provider.
     *
     * @param uid user ID.
     * @param parameters registration parameters.
     * @return user ID
     */
    @Throws(RegisterException::class)
    suspend fun register(
        uid: String,
        parameters: Map<String, String>
    ): String

    /**
     * De-registers a user.
     *
     * @param uid user ID.
     * @param accessToken access token to authenticate and authorize the request.
     */
    @Throws(RegisterException::class)
    suspend fun deregister(uid: String, accessToken: String)

    /**
     * Sign into the identity provider.
     *
     * @param uid user ID.
     * @param parameters sign-in parameters.
     * @returns Successful authentication result [AuthenticationTokens]
     */
    @Throws(AuthenticationException::class)
    suspend fun signIn(
        uid: String,
        parameters: Map<String, String>
    ): AuthenticationTokens

    /**
     * Refresh the access and ID tokens using the refresh token.
     *
     * @param refreshToken refresh token used to refresh the access and ID tokens.
     * @return Successful authentication result [AuthenticationTokens] containing refreshed tokens
     */
    @Throws(AuthenticationException::class)
    suspend fun refreshTokens(refreshToken: String): AuthenticationTokens

    /**
     * Signs out the user from this device only.
     *
     * @param refreshToken refresh token tied to this device.
     */
    @Throws(AuthenticationException::class)
    suspend fun signOut(refreshToken: String)

    /**
     * Signs out the user from all devices.
     *
     * @param accessToken access token used to authorize the request.
     */
    @Throws(SignOutException::class)
    suspend fun globalSignOut(accessToken: String)
}

/**
 * Identity provider implementation that uses AWS Cognito User Pool.
 */
internal class CognitoUserPoolIdentityProvider(
    config: JSONObject,
    context: Context,
    private val keyManager: KeyManagerInterface,
    private val passwordGenerator: PasswordGenerator,
    private val logger: Logger = DefaultLogger.instance
) : IdentityProvider {

    companion object {
        private const val CONFIG_REGION = "region"
        private const val CONFIG_POOL_ID = "poolId"
        private const val CONFIG_CLIENT_ID = "clientId"

        private const val AUTH_PARAM_NAME_USER_NAME = "USERNAME"
        private const val AUTH_PARAM_NAME_ANSWER = "ANSWER"
        private const val AUTH_PARAM_NAME_REFRESH = "REFRESH_TOKEN"

        private const val CHALLENGE_PARAM_NAME_AUDIENCE = "audience"
        private const val CHALLENGE_PARAM_NAME_NONCE = "nonce"

        const val REGISTRATION_PARAM_ANSWER = "answer"
        const val REGISTRATION_PARAM_ANSWER_PARTS = "parts"
        const val REGISTRATION_PARAM_ANSWER_METADATA = "answerMetadata"
        const val REGISTRATION_PARAM_DEVICE_ID = "deviceId"
        const val REGISTRATION_PARAM_PUBLIC_KEY = "publicKey"
        const val REGISTRATION_PARAM_CHALLENGE_TYPE = "challengeType"
        const val REGISTRATION_PARAM_REGISTRATION_ID = "registrationId"

        const val SIGN_IN_PARAM_NAME_USER_KEY_ID = "userKeyId"
        const val SIGN_IN_PARAM_NAME_CHALLENGE_TYPE = "challengeType"
        const val SIGN_IN_PARAM_NAME_ANSWER = "answer"

        const val SIGN_IN_JWT_LIFETIME = 300
        const val SIGN_IN_JWT_ALGORITHM = "RS256"

        const val SERVICE_ERROR_SERVICE_ERROR = "sudoplatform.ServiceError"
        const val SERVICE_ERROR_DECODING_ERROR = "sudoplatform.identity.DecodingError"
        const val SERVICE_ERROR_VALIDATION_FAILED = "sudoplatform.identity.UserValidationFailed"
        const val SERVICE_ERROR_MISSING_REQUIRED_INPUT =
            "sudoplatform.identity.MissingRequiredInputs"
        const val SERVICE_ERROR_SAFETY_NET_CHECK_FAILED =
            "sudoplatform.identity.SafetyNetCheckFailed"
        const val SERVICE_ERROR_TEST_REG_CHECK_FAILED = "sudoplatform.identity.TestRegCheckFailed"
        const val SERVICE_ERROR_CHALLENGE_TYPE_NOT_SUPPORTED =
            "sudoplatform.identity.ChallengeTypeNotSupported"
        const val SERVICE_ERROR_ALREADY_REGISTERED = "sudoplatform.identity.AlreadyRegistered"
    }

    /**
     * Cognito user pool used for authentication and registration.
     */
    private var userPool: CognitoUserPool

    /**
     * Cognito identity provider used for custom authentication flow.
     */
    private var idpClient: AmazonCognitoIdentityProviderClient

    init {
        val region = config[CONFIG_REGION] as String?
        val poolId = config[CONFIG_POOL_ID] as String?
        val clientId = config[CONFIG_CLIENT_ID] as String?

        if (region == null
            || poolId == null
            || clientId == null
        ) {
            throw IllegalArgumentException("region, poolId or clientId was null.")
        }

        this.userPool = CognitoUserPool(
            context,
            poolId,
            clientId,
            null,
            Regions.fromName(region)
        )

        this.idpClient =
            AmazonCognitoIdentityProviderClient(AnonymousAWSCredentials(), ClientConfiguration())
        this.idpClient.setRegion(Region.getRegion(region))
    }

    override suspend fun register(uid: String, parameters: Map<String, String>): String {
        this.logger.debug("uid: $uid, parameters: $parameters")

        // Generate a random password. Currently, Cognito requires a password although we won't
        // be using password based authentication.
        val password =
            this@CognitoUserPoolIdentityProvider.passwordGenerator.generatePassword(
                length = 50,
                upperCase = true,
                lowerCase = true,
                special = true,
                number = true
            )

        val cognitoAttributes = CognitoUserAttributes()

        return userPool.signUp(uid, password, cognitoAttributes, parameters)
    }

    override suspend fun signIn(uid: String, parameters: Map<String, String>): AuthenticationTokens {
        this.logger.debug("uid: $uid, parameters: $parameters")

        val initiateAuthRequest = InitiateAuthRequest()
        initiateAuthRequest.authFlow = "CUSTOM_AUTH"
        initiateAuthRequest.clientId = this.userPool.clientId
        initiateAuthRequest.authParameters = mapOf(AUTH_PARAM_NAME_USER_NAME to uid)

        try {
            val initiateAuthResult = this.idpClient.initiateAuth(initiateAuthRequest)
            val challengeName = initiateAuthResult.challengeName
            val session = initiateAuthResult.session
            val nonce = initiateAuthResult.challengeParameters[CHALLENGE_PARAM_NAME_NONCE]
            val audience =
                initiateAuthResult.challengeParameters[CHALLENGE_PARAM_NAME_AUDIENCE]

            if (challengeName != null && session != null && nonce != null && audience != null) {
                val respondToAuthChallengeRequest = RespondToAuthChallengeRequest()
                respondToAuthChallengeRequest.clientId = this.userPool.clientId
                respondToAuthChallengeRequest.challengeName = challengeName
                respondToAuthChallengeRequest.session = session

                var answer: String? = null
                val challengeType = parameters[SIGN_IN_PARAM_NAME_CHALLENGE_TYPE]
                if (challengeType == "FSSO") {
                    answer = parameters[SIGN_IN_PARAM_NAME_ANSWER]
                    respondToAuthChallengeRequest.clientMetadata =
                        mapOf(SIGN_IN_PARAM_NAME_CHALLENGE_TYPE to "FSSO")
                } else {
                    val userKeyId = parameters[SIGN_IN_PARAM_NAME_USER_KEY_ID]

                    if (userKeyId != null) {
                        val jwt = JWT(
                            uid,
                            audience,
                            uid,
                            nonce,
                            SIGN_IN_JWT_ALGORITHM,
                            null,
                            Date(Date().time + (SIGN_IN_JWT_LIFETIME * 1000))
                        )
                        answer = jwt.signAndEncode(
                            this@CognitoUserPoolIdentityProvider.keyManager,
                            userKeyId
                        )
                    }
                }

                if (answer != null) {
                    respondToAuthChallengeRequest.challengeResponses = mapOf(
                        AUTH_PARAM_NAME_USER_NAME to uid,
                        AUTH_PARAM_NAME_ANSWER to answer
                    )

                    val respondToAuthChallengeResult =
                        this.idpClient.respondToAuthChallenge(respondToAuthChallengeRequest)
                    val idToken = respondToAuthChallengeResult.authenticationResult.idToken
                    val accessToken =
                        respondToAuthChallengeResult.authenticationResult.accessToken
                    val refreshToken =
                        respondToAuthChallengeResult.authenticationResult.refreshToken
                    val lifetime = respondToAuthChallengeResult.authenticationResult.expiresIn

                    if (idToken != null && accessToken != null && refreshToken != null) {
                        return AuthenticationTokens(
                            idToken,
                            accessToken,
                            refreshToken,
                            lifetime
                        )
                    } else {
                        throw AuthenticationException.FailedException("Authentication tokens not found.")
                    }
                } else {
                    throw AuthenticationException.FailedException("Challenge answer not found.")
                }
            } else {
                throw AuthenticationException.FailedException("Invalid initiate auth result.")
            }
        } catch (t: Throwable) {
            when (t) {
                is AuthenticationException -> throw t
                is NotAuthorizedException -> throw AuthenticationException.NotAuthorizedException(
                    cause = t
                )
                else -> throw AuthenticationException.FailedException(cause = t)
            }
        }
    }

    override suspend fun deregister(uid: String, accessToken: String) {
        this.logger.debug("uid: $uid, accessToken: $accessToken")

        val deleteUserRequest = DeleteUserRequest()
        deleteUserRequest.accessToken = accessToken
        try {
            this.idpClient.deleteUser(deleteUserRequest)
        } catch (t: Throwable) {
            when (t) {
                is NotAuthorizedException -> throw DeregisterException.NotAuthorizedException(cause = t)
                else -> throw DeregisterException.FailedException(cause = t)
            }
        }
    }

    override suspend fun refreshTokens(refreshToken: String): AuthenticationTokens {
        this.logger.debug("refreshToken: $refreshToken")
        val initiateAuthRequest = InitiateAuthRequest()
        initiateAuthRequest.authFlow = "REFRESH_TOKEN_AUTH"
        initiateAuthRequest.clientId = this.userPool.clientId
        initiateAuthRequest.authParameters = mapOf(AUTH_PARAM_NAME_REFRESH to refreshToken)

        try {
            val initiateAuthResult= this.idpClient.initiateAuth(initiateAuthRequest)
            val idToken = initiateAuthResult.authenticationResult.idToken
            val accessToken = initiateAuthResult.authenticationResult.accessToken
            val lifetime = initiateAuthResult.authenticationResult.expiresIn

            if (idToken != null && accessToken != null) {
                return AuthenticationTokens(
                    idToken,
                    accessToken,
                    refreshToken,
                    lifetime
                )
            } else {
                throw AuthenticationException.FailedException(
                    "Authentication tokens not found."
                )
            }
        } catch (t: Throwable) {
            when (t) {
                is AuthenticationException -> throw t
                is NotAuthorizedException -> throw AuthenticationException.NotAuthorizedException(cause = t)
                else -> throw AuthenticationException.FailedException(cause = t)
            }
        }
    }

    override suspend fun signOut(refreshToken: String) {
        val request = RevokeTokenRequest()
        request.clientId = this.userPool.clientId
        request.token = refreshToken

        try {
            this.idpClient.revokeToken(request)
        } catch (t: Throwable) {
            when (t) {
                is NotAuthorizedException -> throw SignOutException.NotAuthorizedException(cause = t)
                else -> throw SignOutException.FailedException(cause = t)
            }
        }
    }

    override suspend fun globalSignOut(accessToken: String) {
        val request = GlobalSignOutRequest()
        request.accessToken = accessToken

        try {
            this.idpClient.globalSignOut(request)
        } catch (t: Throwable) {
            when (t) {
                is NotAuthorizedException -> throw SignOutException.NotAuthorizedException(cause = t)
                else -> throw SignOutException.FailedException(cause = t)
            }
        }
    }
}
