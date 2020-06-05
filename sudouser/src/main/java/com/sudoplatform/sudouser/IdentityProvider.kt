/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.content.Context
import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AnonymousAWSCredentials
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler
import com.amazonaws.regions.Region
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidentityprovider.AmazonCognitoIdentityProviderClient
import com.amazonaws.services.cognitoidentityprovider.model.*
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.sudoplatform.sudologging.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
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
 * Encapsulates interface requirements for an external identity provider to register and authenticate an identity
 * within Sudo platform ecosystem.
 */
interface IdentityProvider {

    /**
     * Registers a new user against the identity provider.
     *
     * @param uid user ID.
     * @param parameters registration parameters.
     * @param callback callback for returning registration result containing the newly created user's ID or error.
     * @Throws(ApiException::class)
     */
    fun register(
        uid: String,
        parameters: Map<String, String>,
        callback: (RegisterResult) -> Unit
    )

    /**
     * Deregisters a user.
     *
     * @param uid user ID.
     * @param accessToken access token to authenticate and authorize the request.
     * @param callback callback for returning success or error.
     */
    fun deregister(uid: String, accessToken: String, callback: (ApiResult) -> Unit)

    /**
     * Sign into the identity provider.
     *
     * @param uid user ID.
     * @param parameters sign-in parameters.
     * @param parameters callback for returning sign in result containing ID, access and refresh token or error.
     * @Throws(ApiException::class)
     */
    fun signIn(
        uid: String,
        parameters: Map<String, String>,
        callback: (SignInResult) -> Unit
    )

    /**
     * Refresh the access and ID tokens using the refresh token.
     *
     * @param callback callback for returning refresh token result containing ID, access and refresh token or error.
     */
    fun refreshTokens(refreshToken: String, callback: (SignInResult) -> Unit)

    /**
     * Signs out the user from all devices.
     *
     * @param accessToken access token used to authorize the request.
     * @param callback callback for returning successful result or error.
     */
    fun globalSignOut(accessToken: String, callback: (ApiResult) -> Unit)

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

    override fun register(
        uid: String,
        parameters: Map<String, String>,
        callback: (RegisterResult) -> Unit
    ) {
        this.logger.debug("uid: $uid, parameters: $parameters")

        GlobalScope.launch(Dispatchers.IO) {
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
            this@CognitoUserPoolIdentityProvider.userPool.signUp(
                uid,
                password,
                cognitoAttributes,
                parameters,
                object : SignUpHandler {
                    override fun onSuccess(
                        user: CognitoUser?,
                        signUpResult: SignUpResult
                    ) {
                        if (user?.userId != null) {
                            if (signUpResult.isUserConfirmed) {
                                callback(RegisterResult.Success(user.userId))
                            } else {
                                callback(
                                    RegisterResult.Failure(
                                        ApiException(
                                            ApiErrorCode.IDENTITY_NOT_CONFIRMED,
                                            "Identity was created but is not confirmed."
                                        )
                                    )
                                )
                            }
                        } else {
                            callback(
                                RegisterResult.Failure(
                                    IllegalStateException()
                                )
                            )
                        }
                    }

                    override fun onFailure(exception: Exception?) {
                        if (exception != null) {
                            val message = exception.message
                            if (message != null) {
                                if (message.contains(SERVICE_ERROR_SERVICE_ERROR)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.SERVER_ERROR,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(SERVICE_ERROR_MISSING_REQUIRED_INPUT)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.INVALID_INPUT,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(SERVICE_ERROR_DECODING_ERROR)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.INVALID_INPUT,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(SERVICE_ERROR_SAFETY_NET_CHECK_FAILED)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.NOT_AUTHORIZED,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(SERVICE_ERROR_VALIDATION_FAILED)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.NOT_AUTHORIZED,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(SERVICE_ERROR_TEST_REG_CHECK_FAILED)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.NOT_AUTHORIZED,
                                                message
                                            )
                                        )
                                    )
                                } else if (message.contains(
                                        SERVICE_ERROR_CHALLENGE_TYPE_NOT_SUPPORTED)) {
                                    callback(
                                        RegisterResult.Failure(
                                            ApiException(
                                                ApiErrorCode.NOT_AUTHORIZED,
                                                message
                                            )
                                        )
                                    )
                                } else {
                                    callback(RegisterResult.Failure(exception))
                                }
                            } else {
                                callback(RegisterResult.Failure(exception))
                            }
                        } else {
                            callback(
                                RegisterResult.Failure(
                                    ApiException(
                                        ApiErrorCode.FATAL_ERROR,
                                        "Expected failure detail not found."
                                    )
                                )
                            )
                        }
                    }
                })
        }
    }

    override fun signIn(
        uid: String,
        parameters: Map<String, String>,
        callback: (SignInResult) -> Unit
    ) {
        this.logger.debug("uid: $uid, parameters: $parameters")

        GlobalScope.launch(Dispatchers.IO) {
            val userKeyId = parameters[SIGN_IN_PARAM_NAME_USER_KEY_ID]

            if (userKeyId != null) {
                val initiateAuthRequest = InitiateAuthRequest()
                initiateAuthRequest.authFlow = "CUSTOM_AUTH"
                initiateAuthRequest.clientId =
                    this@CognitoUserPoolIdentityProvider.userPool.clientId
                initiateAuthRequest.authParameters = mapOf(AUTH_PARAM_NAME_USER_NAME to uid)

                try {
                    val initiateAuthResult =
                        this@CognitoUserPoolIdentityProvider.idpClient.initiateAuth(
                            initiateAuthRequest
                        )
                    val challengeName = initiateAuthResult.challengeName
                    val session = initiateAuthResult.session
                    val nonce = initiateAuthResult.challengeParameters[CHALLENGE_PARAM_NAME_NONCE]
                    val audience =
                        initiateAuthResult.challengeParameters[CHALLENGE_PARAM_NAME_AUDIENCE]

                    if (challengeName != null && session != null && nonce != null && audience != null) {
                        val respondToAuthChallengeRequest = RespondToAuthChallengeRequest()
                        respondToAuthChallengeRequest.clientId =
                            this@CognitoUserPoolIdentityProvider.userPool.clientId
                        respondToAuthChallengeRequest.challengeName = challengeName
                        respondToAuthChallengeRequest.session = session

                        val jwt = JWT(
                            uid,
                            audience,
                            uid,
                            nonce,
                            SIGN_IN_JWT_ALGORITHM,
                            null,
                            Date(Date().time + (SIGN_IN_JWT_LIFETIME * 1000))
                        )
                        val encodedJWT = jwt.signAndEncode(
                            this@CognitoUserPoolIdentityProvider.keyManager,
                            userKeyId
                        )
                        respondToAuthChallengeRequest.challengeResponses = mapOf(
                            AUTH_PARAM_NAME_USER_NAME to uid,
                            AUTH_PARAM_NAME_ANSWER to encodedJWT
                        )

                        val respondToAuthChallengeResult =
                            this@CognitoUserPoolIdentityProvider.idpClient.respondToAuthChallenge(
                                respondToAuthChallengeRequest
                            )
                        val idToken = respondToAuthChallengeResult.authenticationResult.idToken
                        val accessToken =
                            respondToAuthChallengeResult.authenticationResult.accessToken
                        val refreshToken =
                            respondToAuthChallengeResult.authenticationResult.refreshToken
                        val lifetime = respondToAuthChallengeResult.authenticationResult.expiresIn

                        if (idToken != null && accessToken != null && refreshToken != null) {
                            callback(
                                SignInResult.Success(
                                    idToken,
                                    accessToken,
                                    refreshToken,
                                    lifetime
                                )
                            )
                        } else {
                            callback(
                                SignInResult.Failure(
                                    ApiException(
                                        ApiErrorCode.FATAL_ERROR,
                                        "Authentication tokens not found."
                                    )
                                )
                            )
                        }
                    } else {
                        callback(
                            SignInResult.Failure(
                                ApiException(
                                    ApiErrorCode.FATAL_ERROR,
                                    "Invalid initiate auth result."
                                )
                            )
                        )
                    }
                } catch (e: NotAuthorizedException) {
                    callback(
                        SignInResult.Failure(
                            ApiException(
                                ApiErrorCode.NOT_AUTHORIZED,
                                "cause: $e"
                            )
                        )
                    )
                } catch (e: Exception) {
                    callback(
                        SignInResult.Failure(
                            ApiException(
                                ApiErrorCode.FATAL_ERROR,
                                "cause: $e"
                            )
                        )
                    )
                }
            } else {
                callback(
                    SignInResult.Failure(
                        ApiException(
                            ApiErrorCode.NOT_REGISTERED,
                            "Not registered."
                        )
                    )
                )
            }
        }
    }

    override fun deregister(uid: String, accessToken: String, callback: (ApiResult) -> Unit) {
        this.logger.debug("uid: $uid, accessToken: $accessToken")
        GlobalScope.launch(Dispatchers.IO) {
            val deleteUserRequest = DeleteUserRequest()
            deleteUserRequest.accessToken = accessToken
            try {
                this@CognitoUserPoolIdentityProvider.idpClient.deleteUser(deleteUserRequest)
                callback(ApiResult.Success)
            } catch (e: NotAuthorizedException) {
                callback(
                    ApiResult.Failure(
                        ApiException(
                            ApiErrorCode.NOT_AUTHORIZED,
                            "cause: $e"
                        )
                    )
                )
            } catch (e: Exception) {
                callback(ApiResult.Failure(e))
            }
        }
    }

    override fun refreshTokens(refreshToken: String, callback: (SignInResult) -> Unit) {
        this.logger.debug("refreshToken: $refreshToken")

        GlobalScope.launch(Dispatchers.IO) {
            val initiateAuthRequest = InitiateAuthRequest()
            initiateAuthRequest.authFlow = "REFRESH_TOKEN_AUTH"
            initiateAuthRequest.clientId = this@CognitoUserPoolIdentityProvider.userPool.clientId
            initiateAuthRequest.authParameters = mapOf(AUTH_PARAM_NAME_REFRESH to refreshToken)

            try {
                val initiateAuthResult =
                    this@CognitoUserPoolIdentityProvider.idpClient.initiateAuth(initiateAuthRequest)

                val idToken = initiateAuthResult.authenticationResult.idToken
                val accessToken = initiateAuthResult.authenticationResult.accessToken
                val lifetime = initiateAuthResult.authenticationResult.expiresIn

                if (idToken != null && accessToken != null) {
                    callback(
                        SignInResult.Success(
                            idToken,
                            accessToken,
                            refreshToken,
                            lifetime
                        )
                    )
                } else {
                    callback(
                        SignInResult.Failure(
                            ApiException(
                                ApiErrorCode.FATAL_ERROR,
                                "Authentication tokens not found."
                            )
                        )
                    )
                }
            } catch (e: NotAuthorizedException) {
                callback(
                    SignInResult.Failure(
                        ApiException(
                            ApiErrorCode.NOT_AUTHORIZED,
                            "cause: $e"
                        )
                    )
                )
            } catch (e: Exception) {
                callback(
                    SignInResult.Failure(
                        ApiException(
                            ApiErrorCode.FATAL_ERROR,
                            "cause: $e"
                        )
                    )
                )
            }
        }
    }

    override fun globalSignOut(accessToken: String, callback: (ApiResult) -> Unit) {
        GlobalScope.launch(Dispatchers.IO) {
            val request = GlobalSignOutRequest()
            request.accessToken = accessToken

            try {
                this@CognitoUserPoolIdentityProvider.idpClient.globalSignOut(request)
                callback(ApiResult.Success)
            } catch (e: NotAuthorizedException) {
                callback(
                    ApiResult.Failure(
                        ApiException(
                            ApiErrorCode.NOT_AUTHORIZED,
                            "cause: $e"
                        )
                    )
                )
            } catch (e: Exception) {
                callback(
                    ApiResult.Failure(
                        ApiException(
                            ApiErrorCode.FATAL_ERROR,
                            "cause: $e"
                        )
                    )
                )
            }
        }
    }

}