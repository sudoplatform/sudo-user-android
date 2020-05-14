/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.content.Context
import android.net.Uri
import com.amazonaws.auth.CognitoCachingCredentialsProvider
import com.amazonaws.auth.CognitoCredentialsProvider
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.regions.Regions
import com.anonyome.keymanager.KeyManagerFactory
import com.anonyome.keymanager.KeyManagerInterface
import com.apollographql.apollo.GraphQLCall
import com.apollographql.apollo.api.Error
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudouser.type.RegisterFederatedIdInput
import java.security.PrivateKey
import java.util.*
import org.json.JSONObject
import com.sudoplatform.sudologging.Logger

/**
 * Supported symmetric key algorithms.
 */
enum class SymmetricKeyEncryptionAlgorithm(private val stringValue: String) {
    AES_CBC_PKCS7PADDING("AES/CBC/PKCS7Padding");

    companion object {

        fun fromString(stringValue: String): SymmetricKeyEncryptionAlgorithm? {
            var value: SymmetricKeyEncryptionAlgorithm? = null
            if (stringValue == "AES/CBC/PKCS7Padding") {
                value =
                    AES_CBC_PKCS7PADDING
            }

            return value
        }

    }

    override fun toString(): String {
        when (this) {
            AES_CBC_PKCS7PADDING -> return this.stringValue
        }
    }

}

/**
 * Interface encapsulating a library of functions for calling Sudo Platform identity service, managing keys, performing
 * cryptographic operations.
 */
interface SudoUserClient {

    /**
     * Client version.
     */
    val version: String

    /**
     * Indicates whether or not this client is registered with Sudo Platform backend.
     *
     * @return *true* if the client is registered.
     */
    fun isRegistered(): Boolean

    /**
     * Indicates whether or not this client is signed in with Sudo Platform backend. The client is
     * considered signed in if it cached valid ID and access tokens.
     *
     * @return *true* if the client is signed in.
     */
    fun isSignedIn(): Boolean

    /**
     * Removes all keys associated with this client and invalidates any cached authentication credentials.
     */
    fun reset()

    /**
     * Registers this client against the backend with a SafetyNet attestation result.
     *
     * @param attestationResult SafetyNet attestation result.
     * @param nonce nonce used to generate SafetyNet attestation result. This should be unique for each device so
     *  use UUID or Android ID.
     * @param registrationId registration ID to uniquely identify this registration request.
     * @param callback callback for returning registration result containing the newly created user's ID or error.
     * @Throws(ApiException::class)
     */
    fun registerWithSafetyNetAttestation(
        attestationResult: String,
        nonce: String,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    )

    /**
     * Registers this client against the backend with an external authentication provider. Caller must
     * implement [AuthenticationProvider] protocol to return appropriate authentication token required
     * to authorize the registration request.
     *
     * @param authenticationProvider authentication provider that provides the authentication token.
     * @param registrationId registration ID to uniquely identify this registration request.
     * @param callback callback for returning registration result containing the newly created user's ID or error.
     */
    fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    )

    /**
     * De-registers a user.
     *
     * @param callback callback for returning success or error.
     */
    fun deregister(callback: (ApiResult) -> Unit)

    /**
     * Sign into the backend using a private key. The client must have created a private/public key pair via
     * one of the *register* methods.
     *
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     * @Throws(ApiException::class)
     */
    fun signInWithKey(callback: (SignInResult) -> Unit)

    /**
     * Presents the sign in UI for federated sign in using an external identity provider.
     *
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     */
    fun presentFederatedSignInUI(callback: (SignInResult) -> Unit)

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
     */
    fun processFederatedSignInTokens(data: Uri)

    /**
     * Refresh the access and ID tokens using the refresh token.
     *
     * @param callback callback for returning refresh token result containing ID, access and refresh token or error.
     */
    fun refreshTokens(refreshToken: String, callback: (SignInResult) -> Unit)

    /**
     * Returns the ID token cached from the last sign-in.
     *
     * @return ID token.
     */
    fun getIdToken(): String?

    /**
     * Returns the access token cached from the last sign-in.
     *
     * @return access token.
     */
    fun getAccessToken(): String?

    /**
     * Returns the refresh token cached from the last sign-in.
     *
     * @return refresh token.
     */
    fun getRefreshToken(): String?

    /**
     * Returns the ID and access token expiry cached from the last sign-in.
     *
     * @return token expiry.
     */
    fun getTokenExpiry(): Date?

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("getUserName()"),
        level = DeprecationLevel.WARNING
    )
    fun getUserId(): String?

    /**
     * Returns the user name associated with this client. The username maybe needed to contact
     * the support team when diagnosing an issue related to a specific user.
     *
     * @return user name.
     */
    fun getUserName(): String?

    /**
     * Returns the subject of the user associated with this client.
     * Note: This is an internal method used by other Sudo platform SDKs.
     *
     * @return user subject.
     */
    fun getSubject(): String?

    /**
     * Get the Symmetric Key ID associated with this client. The Symmetric Key ID is generated during a register
     * request and saved within the keychain for the current device.
     *
     * @return symmetric Key ID associated with the device.
     */
    fun getSymmetricKeyId(): String?

    /**
     * Encrypts the given data using the specified key and encryption algorithm.
     *
     * @param keyId ID of the encryption key to use.
     * @param algorithm encryption algorithm to use.
     * @param data data to encrypt.
     * @return encrypted data.
     */
    fun encrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray

    /**
     * Encrypts the given data using the specified key and encryption algorithm.
     *
     * @param keyId ID of the encryption key to use.
     * @param algorithm encryption algorithm to use.
     * @param data data to decrypt.
     * @return: decrypted data.
     */
    fun decrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray

    /**
     * Clears cached authentication tokens.
     */
    fun clearAuthTokens()

    /**
     * Signs out the user from all devices.
     *
     * @param callback callback for returning successful result or error.
     */
    fun globalSignOut(callback: (ApiResult) -> Unit)


    /**
     * Returns the logins to use for accessing other Sudo Platform services. You must be signed in to get
     * logins.
     *
     * Note: This is an internal API used by other platform service clients.
     *
     * @return: map of logins.
     */
    fun getLogins(): Map<String, String>

    /**
     * Returns a credentials provider that can be used for authenticating into various services provided
     * by Sudo Platform.
     *
     * Note: This is an internal API used by other platform service clients.
     *
     * @return: credentials provider.
     */
    fun getCredentialsProvider(): CognitoCredentialsProvider

    /**
     * Returns the specified claim associated with the user's identity.
     *
     * @param name claim name.
     * @return: the specified claim value. The value can be of any JSON supported types. Safe cast
     * it to the expected Kotlin type before using it, e.g. [String], [Number], [Boolean], [Map] or
     * []Array].
     */
    fun getUserClaim(name: String): Any?

}

/**
 * Default implementation of [SudoUserClient] interface.
 *
 * @param config configuration parameters.
 * @param context Android app context.
 * @param namespace namespace to use for internal data and cryptographic keys. This should be unique
 *  per client per app to avoid name conflicts between multiple clients.
 * @param logger logger to use for logging messages.
 * @param keyManager custom [KeyManagerInterface] implementation. Mainly used for unit testing (optional)
 * @param identityProvider custom identity provider. Mainly used for unit testing (optional).
 * @param apiClient custom API client. Mainly used for unit testing (optional).
 * @param credentialsProvider custom credentials provider. Mainly used for unit testing (optional).
 * @param authUI custom auth UI. Mainly used for unit testing (optional).
 * @param idGenerator custom ID generator. Mainly used for unit testing (optional).
 */
class DefaultSudoUserClient(
    private val context: Context,
    private val namespace: String = "ids",
    private val logger: Logger = DefaultLogger.instance,
    config: JSONObject? = null,
    keyManager: KeyManagerInterface? = null,
    identityProvider: IdentityProvider? = null,
    apiClient: AWSAppSyncClient? = null,
    credentialsProvider: CognitoCredentialsProvider? = null,
    authUI: AuthUI? = null,
    idGenerator: IdGenerator = IdGenerateImpl()
) : SudoUserClient {

    companion object {
        private const val KEY_NAME_SYMMETRIC_KEY_ID = "symmetricKeyId"
        private const val KEY_NAME_USER_ID = "userId"
        private const val KEY_NAME_USER_KEY_ID = "userKeyId"
        private const val KEY_NAME_ID_TOKEN = "idToken"
        private const val KEY_NAME_ACCESS_TOKEN = "accessToken"
        private const val KEY_NAME_REFRESH_TOKEN = "refreshToken"
        private const val KEY_NAME_TOKEN_EXPIRY = "tokenExpiry"

        private const val CONFIG_NAMESPACE_IDENTITY_SERVICE = "identityService"
        private const val CONFIG_NAMESPACE_FEDERATED_SIGN_IN = "federatedSignIn"

        private const val CONFIG_REGION = "region"
        private const val CONFIG_POOL_ID = "poolId"
        private const val CONFIG_IDENTITY_POOL_ID = "identityPoolId"
        private const val CONFIG_API_URL = "apiUrl"

        private const val SIGN_IN_PARAM_NAME_USER_KEY_ID = "userKeyId"

        private const val AES_BLOCK_SIZE = 16

        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_SERVER_ERROR = "sudoplatform.identity.ServerError"

        private const val MAX_VALIDATION_DATA_SIZE = 2048
    }

    override val version: String = "1.0"

    /**
     * [KeyManagerInterface] instance needed for cryptographic operations.
     */
    private val keyManager: KeyManagerInterface

    /**
     * Identity provider to use for registration and authentication.
     */
    private val identityProvider: IdentityProvider

    /**
     * UUID generator.
     */
    private val idGenerator: IdGenerator

    /**
     * Auth UI for federated sign in.
     */
    private var authUI: AuthUI? = null

    /**
     * AWS region hosting identity service.
     */
    private val region: String

    /**
     * Cognito user pool ID used by identity service.
     */
    private val poolId: String

    /**
     * Cognito identity pool ID used by identity service.
     */
    private val identityPoolId: String

    /**
     * Cognito credentials provider to use for authenticating to various AWS services.
     */
    private val credentialsProvider: CognitoCredentialsProvider

    /**
     * GraphQL client used for calling identity service API.
     */
    private val apiClient: AWSAppSyncClient

    init {
        val configManager = DefaultSudoConfigManager(context)

        @Suppress("UNCHECKED_CAST")
        val identityServiceConfig = config?.opt(CONFIG_NAMESPACE_IDENTITY_SERVICE) as JSONObject?
            ?: configManager.getConfigSet(CONFIG_NAMESPACE_IDENTITY_SERVICE)

        require(identityServiceConfig != null) { "Client configuration not found." }

        this.keyManager = keyManager ?: KeyManagerFactory(context).createAndroidKeyManager()
        this.identityProvider = identityProvider ?: CognitoUserPoolIdentityProvider(
            identityServiceConfig,
            context,
            this.keyManager,
            PasswordGeneratorImpl(),
            this.logger
        )

        val apiUrl = identityServiceConfig[CONFIG_API_URL] as String?
        val region = identityServiceConfig[CONFIG_REGION] as String?

        val authProvider = GraphQLAuthProvider(this)

        this.apiClient = apiClient ?: AWSAppSyncClient.builder()
            .serverUrl(apiUrl)
            .region(Regions.fromName(region))
            .cognitoUserPoolsAuthProvider(authProvider)
            .mutationQueueExecutionTimeout(30)
            .context(this.context)
            .build()

        this.idGenerator = idGenerator

        @Suppress("UNCHECKED_CAST")
        val federatedSignInConfig =
            config?.opt(CONFIG_NAMESPACE_FEDERATED_SIGN_IN) as JSONObject?
                ?: configManager.getConfigSet(CONFIG_NAMESPACE_FEDERATED_SIGN_IN)

        if (federatedSignInConfig != null) {
            this.authUI = authUI ?: CognitoAuthUI(
                federatedSignInConfig,
                context
            )
        }

        if (region != null) {
            this.region = region
        } else {
            throw java.lang.IllegalArgumentException("region was null.")
        }

        val poolId = identityServiceConfig[CONFIG_POOL_ID] as String?
        if (poolId != null) {
            this.poolId = poolId
        } else {
            throw java.lang.IllegalArgumentException("poolId was null.")
        }

        val identityPoolId = identityServiceConfig[CONFIG_IDENTITY_POOL_ID] as String?
        if (identityPoolId != null) {
            this.identityPoolId = identityPoolId
        } else {
            throw java.lang.IllegalArgumentException("identityPoolId was null.")
        }

        this.credentialsProvider = credentialsProvider ?: CognitoCachingCredentialsProvider(
            context,
            identityPoolId,
            Regions.fromName(region)
        )
    }

    override fun isRegistered(): Boolean {
        val uid = this.keyManager.getPassword(namespace(KEY_NAME_USER_ID))

        val userKeyId =
            this.keyManager.getPassword(namespace(KEY_NAME_USER_KEY_ID))?.toString(Charsets.UTF_8)
        var privateKey: PrivateKey? = null
        var publicKey: java.security.PublicKey? = null
        if (userKeyId != null) {
            privateKey = this.keyManager.getPrivateKey(userKeyId)
            publicKey = this.keyManager.getPublicKey(userKeyId)
        }

        val symmetricKeyId =
            this.keyManager.getPassword(namespace(KEY_NAME_SYMMETRIC_KEY_ID))
                ?.toString(Charsets.UTF_8)
        var symmetricKey: ByteArray? = null
        if (symmetricKeyId != null) {
            symmetricKey = this.keyManager.getSymmetricKeyData(symmetricKeyId)
        }

        return uid != null && privateKey != null && publicKey != null && symmetricKey != null
    }

    override fun isSignedIn(): Boolean {
        val idToken = this.getIdToken()
        val accessToken = this.getAccessToken()
        val expiry = this.getTokenExpiry()

        if (idToken != null && accessToken != null && expiry != null) {
            return expiry.time > Date().time
        } else {
            return false
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.keyManager.removeAllKeys()
        this.apiClient.clearCaches()
        this.credentialsProvider.clear()
        this.credentialsProvider.clearCredentials()
        this.clearAuthTokens()
    }

    override fun registerWithSafetyNetAttestation(
        attestationResult: String,
        nonce: String,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    ) {
        this.logger.info("Registering using registration challenge.")

        if (!this.isRegistered()) {
            // Clear out any partial registration data.
            this.reset()

            val (uid, publicKey) = this.generateRegistrationData()

            val parameters: MutableMap<String, String> = mutableMapOf(
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_CHALLENGE_TYPE to RegistrationChallengeType.SAFETY_NET.name,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER to "dummy_answer", // Mainly needed for backward compatibility.
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_DEVICE_ID to nonce,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_REGISTRATION_ID to (registrationId
                    ?: this.idGenerator.generateId()),
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_PUBLIC_KEY to publicKey.encode()
            )

            // Split the SafetyNet attestation result into chunks to avoid hitting the Cognito's
            // validation data limit.
            val answerParts = attestationResult.chunked(MAX_VALIDATION_DATA_SIZE)
            val answerPartNames: MutableList<String> = mutableListOf()
            for ((index, element) in answerParts.iterator().withIndex()) {
                val key = "${CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER}.${index}"
                parameters[key] = element
                answerPartNames.add(key)
            }

            val answerMetada =
                mapOf<String, Any>(CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER_PARTS to answerPartNames)
            parameters[CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER_METADATA] =
                JSONObject(answerMetada).toString()

            this.identityProvider.register(uid, parameters) { result ->
                when (result) {
                    is RegisterResult.Success -> {
                        this.setUserId(result.uid)
                        callback(result)
                    }
                    is RegisterResult.Failure -> {
                        callback(result)
                    }
                }
            }
        } else {
            val error =
                ApiException(
                    ApiErrorCode.ALREADY_REGISTERED,
                    "Client is already registered."
                )
            this.logger.error("$error")
            callback(RegisterResult.Failure(error))
        }
    }

    override fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    ) {
        this.logger.info("Registering using external authentication provider.")

        if (!this.isRegistered()) {
            val authInfo = authenticationProvider.getAuthenticationInfo()
            val token = authInfo.encode()
            val jwt = JWT.decode(token)

            // Clear out any partial registration data.
            this.reset()

            val (uid, publicKey) = this.generateRegistrationData()

            val parameters = mapOf(
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_CHALLENGE_TYPE to authInfo.type,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER to authInfo.encode(),
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_REGISTRATION_ID to (registrationId
                    ?: this.idGenerator.generateId()),
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_PUBLIC_KEY to publicKey.encode()
            )

            this.identityProvider.register(jwt?.subject ?: uid, parameters) { result ->
                when (result) {
                    is RegisterResult.Success -> {
                        this.setUserId(result.uid)
                        callback(result)
                    }
                    is RegisterResult.Failure -> {
                        callback(result)
                    }
                }
            }
        } else {
            val error =
                ApiException(
                    ApiErrorCode.ALREADY_REGISTERED,
                    "Client is already registered."
                )
            this.logger.error("$error")
            callback(RegisterResult.Failure(error))
        }
    }

    override fun deregister(callback: (ApiResult) -> Unit) {
        this.logger.info("De-registering user.")

        val accessToken = this.getAccessToken()

        if (accessToken != null) {
            this.apiClient.mutate(DeregisterMutation.builder().build())
                .enqueue(object : GraphQLCall.Callback<DeregisterMutation.Data>() {
                    override fun onResponse(response: Response<DeregisterMutation.Data>) {
                        this@DefaultSudoUserClient.reset()
                        callback(ApiResult.Success)
                    }

                    override fun onFailure(e: ApolloException) {
                        callback(ApiResult.Failure(e))
                    }
                })
        } else {
            val error = ApiException(
                ApiErrorCode.NOT_SIGNED_IN,
                "Not signed in."
            )
            this.logger.error("$error")
            callback(ApiResult.Failure(error))
        }
    }

    override fun signInWithKey(callback: (SignInResult) -> Unit) {
        this.logger.info("Signing in using private key.")

        val uid = this.getUserName()
        val userKeyId = this.keyManager.getPassword(namespace(KEY_NAME_USER_KEY_ID))
            ?.toString(Charsets.UTF_8)

        if (uid != null && userKeyId != null) {
            val parameters = mapOf(
                SIGN_IN_PARAM_NAME_USER_KEY_ID to userKeyId
            )

            this.identityProvider.signIn(uid, parameters) { result ->
                when (result) {
                    is SignInResult.Success -> {
                        this.storeTokens(
                            result.idToken,
                            result.accessToken,
                            result.refreshToken,
                            result.lifetime
                        )

                        this.credentialsProvider.logins = this.getLogins()
                        this.registerFederatedIdAndRefreshTokens(
                            result.idToken,
                            result.accessToken,
                            result.refreshToken,
                            result.lifetime,
                            callback
                        )
                    }
                    is SignInResult.Failure -> {
                        callback(result)
                    }
                }
            }
        } else {
            val error = ApiException(
                ApiErrorCode.NOT_REGISTERED,
                "Not registered."
            )
            this.logger.error("$error")
            callback(SignInResult.Failure(error))
        }
    }

    override fun presentFederatedSignInUI(callback: (SignInResult) -> Unit) {
        this.authUI?.presentFederatedSignInUI { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(
                        namespace(
                            KEY_NAME_USER_ID
                        )
                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        namespace(KEY_NAME_USER_ID)
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime
                    )

                    // Generate the symmetric key if it has not been generated before.
                    val symmetricKeyId = this@DefaultSudoUserClient.getSymmetricKeyId()
                    if (symmetricKeyId == null) {
                        this@DefaultSudoUserClient.generateSymmetricKey()
                    }

                    this.credentialsProvider.logins = this.getLogins()

                    this.registerFederatedIdAndRefreshTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime,
                        callback
                    )
                }
                is FederatedSignInResult.Failure -> {
                    callback(SignInResult.Failure(result.error))
                }
            }
        }
    }

    override fun presentFederatedSignOutUI(callback: (ApiResult) -> Unit) {
        this.authUI?.presentFederatedSignOutUI(callback)
    }

    override fun processFederatedSignInTokens(data: Uri) {
        this.authUI?.processFederatedSignInTokens(data) { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(
                        namespace(
                            KEY_NAME_USER_ID
                        )
                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        namespace(KEY_NAME_USER_ID)
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime
                    )

                    // Generate the symmetric key if it has not been generated before.
                    val symmetricKeyId = this@DefaultSudoUserClient.getSymmetricKeyId()
                    if (symmetricKeyId == null) {
                        this@DefaultSudoUserClient.generateSymmetricKey()
                    }
                }
                is FederatedSignInResult.Failure -> {
                    this.logger.error("Failed to process the federated sign in redirect: ${result.error}")
                }
            }
        }
    }

    override fun refreshTokens(refreshToken: String, callback: (SignInResult) -> Unit) {
        this.logger.info("Refreshing authentication tokens.")

        this.identityProvider.refreshTokens(refreshToken) { result ->
            when (result) {
                is SignInResult.Success -> {
                    this.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime
                    )
                }
            }
            callback(result)
        }
    }

    /**
     * Namespace the name (key name, parameter name etc).
     *
     * @param name name to convert.
     * @return name prefixed with namespace.
     */
    private fun namespace(name: String): String {
        return this.namespace + "." + name
    }

    /**
     * Generates cryptographic keys and user ID required for registration.
     *
     * @return user ID and public key.
     */
    private fun generateRegistrationData(): Pair<String, PublicKey> {
        this.reset()

        // Generate user ID.
        val uid = this.idGenerator.generateId().toUpperCase(Locale.US)

        // Generate and store user's key ID.
        val keyId = this.idGenerator.generateId().toUpperCase(Locale.US)
        this.keyManager.addPassword(keyId.toByteArray(), namespace(KEY_NAME_USER_KEY_ID))

        // Generate a new key pair for authentication and encryption.
        this.keyManager.generateKeyPair(keyId)

        // Retrieve the public key so it can be registered with the backend.
        val keyData = this.keyManager.getPublicKeyData(keyId)
        val publicKey = PublicKey(keyId, keyData)

        this.generateSymmetricKey()

        return uid to publicKey
    }

    private fun generateSymmetricKey() {
        // Delete existing key.
        val symmetricKeyId = this.getSymmetricKeyId()
        if (symmetricKeyId != null) {
            this.keyManager.deleteSymmetricKey(symmetricKeyId)
            this.keyManager.deletePassword(namespace(KEY_NAME_SYMMETRIC_KEY_ID))
        }

        // Generate and store symmetric key ID.
        val keyId = this.idGenerator.generateId().toUpperCase(Locale.US)
        this.keyManager.addPassword(keyId.toByteArray(), namespace(KEY_NAME_SYMMETRIC_KEY_ID))

        // Generate symmetric key for encrypting secrets.
        this.keyManager.generateSymmetricKey(keyId)
    }

    override fun getIdToken(): String? {
        return this.keyManager.getPassword(namespace(KEY_NAME_ID_TOKEN))?.toString(Charsets.UTF_8)
    }

    override fun getAccessToken(): String? {
        return this.keyManager.getPassword(namespace(KEY_NAME_ACCESS_TOKEN))
            ?.toString(Charsets.UTF_8)
    }

    override fun getRefreshToken(): String? {
        return this.keyManager.getPassword(namespace(KEY_NAME_REFRESH_TOKEN))
            ?.toString(Charsets.UTF_8)
    }

    override fun getTokenExpiry(): Date? {
        var expiry: Date? = null

        val timeSinceEpoch =
            this.keyManager.getPassword(namespace(KEY_NAME_TOKEN_EXPIRY))?.toString(Charsets.UTF_8)
                ?.toLong()
        if (timeSinceEpoch != null) {
            expiry = Date(timeSinceEpoch)
        }

        return expiry
    }

    override fun getUserId(): String? {
        return this.getUserName()
    }

    override fun getUserName(): String? {
        return this.keyManager.getPassword(namespace(KEY_NAME_USER_ID))?.toString(Charsets.UTF_8)
    }

    override fun getSubject(): String? {
        return this.getUserClaim("sub") as? String
    }

    override fun getSymmetricKeyId(): String? {
        return this.keyManager.getPassword(namespace(KEY_NAME_SYMMETRIC_KEY_ID))
            ?.toString(Charsets.UTF_8)
    }

    override fun encrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray {
        val iv = this.keyManager.createRandomData(AES_BLOCK_SIZE)
        val encryptedData = this.keyManager.encryptWithSymmetricKey(
            keyId,
            data,
            iv,
            KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )

        return encryptedData + iv
    }

    override fun decrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray {
        val encryptedData = data.copyOfRange(0, data.count() - AES_BLOCK_SIZE)
        val iv = data.copyOfRange(data.count() - AES_BLOCK_SIZE, data.count())

        return this.keyManager.decryptWithSymmetricKey(
            keyId,
            encryptedData,
            iv,
            KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )
    }

    override fun clearAuthTokens() {
        this.keyManager.deletePassword(namespace(KEY_NAME_ID_TOKEN))
        this.keyManager.deletePassword(namespace(KEY_NAME_ACCESS_TOKEN))
        this.keyManager.deletePassword(namespace(KEY_NAME_REFRESH_TOKEN))
        this.keyManager.deletePassword(namespace(KEY_NAME_TOKEN_EXPIRY))

        this.authUI?.reset()
    }

    override fun getLogins(): Map<String, String> {
        val idToken = this.getIdToken()
        return if (idToken != null) {
            mapOf("cognito-idp.${this.region}.amazonaws.com/${this.poolId}" to idToken)
        } else {
            mapOf()
        }
    }

    override fun globalSignOut(callback: (ApiResult) -> Unit) {
        val accessToken = this.getAccessToken()
        if (accessToken != null) {
            this.identityProvider.globalSignOut(accessToken, callback)
            this.clearAuthTokens()
        }
    }

    override fun getCredentialsProvider(): CognitoCredentialsProvider {
        return this.credentialsProvider
    }

    override fun getUserClaim(name: String): Any? {
        var value: Any? = null

        val idToken = this.getIdToken()
        if (idToken != null) {
            val jwt = JWT.decode(idToken)
            if (jwt != null) {
                value = jwt.payload.opt(name)
            }
        }

        return value
    }

    /**
     * Stores authentication tokens in the key store.
     *
     * @param idToken ID token.
     * @param accessToken access token.
     * @param refreshToken refresh token.
     * @param lifetime token lifetime in seconds.
     */
    private fun storeTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int
    ) {
        this.keyManager.deletePassword(namespace(KEY_NAME_ID_TOKEN))
        this.keyManager.addPassword(idToken.toByteArray(), namespace(KEY_NAME_ID_TOKEN))

        this.keyManager.deletePassword(namespace(KEY_NAME_ACCESS_TOKEN))
        this.keyManager.addPassword(accessToken.toByteArray(), namespace(KEY_NAME_ACCESS_TOKEN))

        this.keyManager.deletePassword(namespace(KEY_NAME_REFRESH_TOKEN))
        this.keyManager.addPassword(refreshToken.toByteArray(), namespace(KEY_NAME_REFRESH_TOKEN))

        this.keyManager.deletePassword(namespace(KEY_NAME_TOKEN_EXPIRY))
        this.keyManager.addPassword(
            "${lifetime * 1000 + Date().time}".toByteArray(),
            namespace(KEY_NAME_TOKEN_EXPIRY)
        )
    }

    private fun setUserId(id: String) {
        this.keyManager.deletePassword(namespace(KEY_NAME_USER_ID))
        this.keyManager.addPassword(id.toByteArray(), namespace(KEY_NAME_USER_ID))
    }

    private fun registerFederatedIdAndRefreshTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int,
        callback: (SignInResult) -> Unit
    ) {
        this.logger.info("Registering federated ID.")

        // If the identity ID is already in the ID token as a claim then no need to register
        // the federated identity again.
        val identityId = this.getUserClaim("custom:identityId")
        if (identityId != null) {
            callback(SignInResult.Success(idToken, accessToken, refreshToken, lifetime))
            return
        }

        val input = RegisterFederatedIdInput.builder().idToken(idToken).build()
        this.apiClient.mutate(RegisterFederatedIdMutation.builder().input(input).build())
            .enqueue(object : GraphQLCall.Callback<RegisterFederatedIdMutation.Data>() {
                override fun onResponse(response: Response<RegisterFederatedIdMutation.Data>) {
                    val error = response.errors().firstOrNull()
                    if (error != null) {
                        callback(
                            SignInResult.Failure(
                                this@DefaultSudoUserClient.graphQLErrorToApiException(error)
                            )
                        )
                    } else {
                        this@DefaultSudoUserClient.refreshTokens(refreshToken, callback)
                    }
                }

                override fun onFailure(e: ApolloException) {
                    callback(SignInResult.Failure(e))
                }
            })
    }

    private fun graphQLErrorToApiException(error: Error): ApiException {
        this.logger.error("GraphQL error received: $error")

        return when (error.customAttributes()[GRAPHQL_ERROR_TYPE]) {
            GRAPHQL_ERROR_SERVER_ERROR -> {
                ApiException(ApiErrorCode.SERVER_ERROR, "$error")
            }
            else -> {
                ApiException(ApiErrorCode.GRAPHQL_ERROR, "$error")
            }
        }
    }

}