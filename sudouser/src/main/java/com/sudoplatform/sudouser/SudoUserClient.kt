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
import com.sudoplatform.sudokeymanager.KeyManagerFactory
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.babylon.certificatetransparency.certificateTransparencyInterceptor
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.exceptions.*
import com.sudoplatform.sudouser.type.RegisterFederatedIdInput
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import java.security.PrivateKey
import java.util.*
import com.sudoplatform.sudouser.extensions.enqueue
import com.sudoplatform.sudouser.extensions.toDeregisterException
import com.sudoplatform.sudouser.extensions.toRegistrationException
import com.sudoplatform.sudouser.extensions.toApiException

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

    companion object {

        /**
         * Creates a [Builder] for [SudoUserClient].
         */
        fun builder(context: Context) =
            Builder(context)

    }

    /**
     * Builder used to construct [SudoUserClient].
     */
    class Builder(private val context: Context) {
        private var apiClient: AWSAppSyncClient? = null
        private var namespace :String? = "ids"
        private var logger: Logger? = null
        private var config: JSONObject? = null
        private var keyManager: KeyManagerInterface? = null
        private var identityProvider: IdentityProvider? = null
        private var credentialsProvider: CognitoCredentialsProvider? = null
        private var authUI: AuthUI? = null
        private var idGenerator: IdGenerator? = IdGenerateImpl()

        /**
         * Provide an [AWSAppSyncClient] for the [SudoUserClient]. If this is not supplied,
         * a default [AWSAppSyncClient] will be used. This is mainly used for unit testing.
         */
        fun setApiClient(apiClient: AWSAppSyncClient) = also {
            this.apiClient = apiClient
        }

        /**
         * Provide the namespace to use for internal data and cryptographic keys. This should be unique
         * per client per app to avoid name conflicts between multiple clients. If a value is not supplied
         * a default value will be used.
         */
        fun setNamespace(namespace: String) = also {
            this.namespace = namespace
        }

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) = also {
            this.logger = logger
        }

        /**
         * Provide the configuration parameters.
         */
        fun setConfig(config: JSONObject) = also {
            this.config = config
        }

        /**
         * Provide custom [KeyManagerInterface] implementation. This is mainly used for unit testing (optional).
         */
        fun setKeyManager(keyManager: KeyManagerInterface) = also {
            this.keyManager = keyManager
        }

        /**
         * Provide a custom identity provider. This is mainly used for unit testing (optional).
         */
        fun setIdentityProvider(identityProvider: IdentityProvider) = also {
            this.identityProvider = identityProvider
        }

        /**
         * Provide a custom credentials provider. This is mainly used for unit testing (optional).
         * If a value is not provided, a default implementation will be used.
         */
        fun setCredentialsProvider(credentialsProvider: CognitoCredentialsProvider) = also {
            this.credentialsProvider = credentialsProvider
        }

        /**
         * Provide a custom auth UI. This is mainly used for unit testing (optional).
         */
        fun setAuthUI(authUI: AuthUI) = also {
            this.authUI = authUI
        }

        /**
         * Provide a custom ID generator. This is mainly used for unit testing.
         * If a value is not provided, a default implementation will be used.
         */
        fun setIdGenerator(idGenerator: IdGenerator) = also {
            this.idGenerator = idGenerator
        }

        /**
         * Constructs and returns an [SudoUserClient].
         */
        fun build(): SudoUserClient {
            return DefaultSudoUserClient(
                this.context,
                this.namespace ?: "ids",
                this.logger ?: DefaultLogger.instance,
                this.config ?: null,
                this.keyManager ?: null,
                this.identityProvider ?: null,
                this.apiClient ?: null,
                this.credentialsProvider ?: null,
                this.authUI ?: null,
                this.idGenerator ?: IdGenerateImpl()
            )
        }
    }

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
     * @return user ID
     */
    @Throws(RegisterException::class)
    suspend fun registerWithSafetyNetAttestation(
        attestationResult: String,
        nonce: String,
        registrationId: String?
    ): String

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("registerWithSafetyNetAttestation(attestationResult, nonce, registrationId)"),
        level = DeprecationLevel.WARNING
    )
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
     * @return user ID of the newly created user
     */
    @Throws(RegisterException::class)
    suspend fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?
    ): String

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("registerWithAuthenticationProvider(authenticationProvider, registrationId)"),
        level = DeprecationLevel.WARNING
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
     */
    @Throws(DeregisterException::class)
    suspend fun deregister()

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("deregister()"),
        level = DeprecationLevel.WARNING
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
     * @return Successful authentication result [AuthenticationTokens]
     */
    @Throws(AuthenticationException::class)
    suspend fun signInWithKey(): AuthenticationTokens

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("signInWithKey()"),
        level = DeprecationLevel.WARNING
    )
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
     * Sign into the backend  with an external authentication provider. Caller must implement `AuthenticationProvider`
     * protocol to return the appropriate authentication token associated with the external identity registered with
     * [registerWithAuthenticationProvider].
     *
     * @param authenticationProvider authentication provider that provides the authentication token.
     * @return Successful authentication result [AuthenticationTokens]
     */
    suspend fun signInWithAuthenticationProvider(authenticationProvider: AuthenticationProvider): AuthenticationTokens

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
     * @return successful authentication result [AuthenticationTokens]
     */
    @Throws(AuthenticationException::class)
    suspend fun refreshTokens(refreshToken: String): AuthenticationTokens

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("refreshTokens(refreshToken)"),
        level = DeprecationLevel.WARNING
    )
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
        message = "This is deprecated and will be removed in the future.",
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
     */
    @Throws(SignOutException::class)
    suspend fun globalSignOut()

    @Deprecated(
        message ="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("globalSignOut()"),
        level = DeprecationLevel.WARNING
    )
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

    /**
     * Returns the list of supported registration challenge types supported by the configured backend.
     *
     * @return: list of supported registration challenge types.
     */
    fun getSupportedRegistrationChallengeType(): List<RegistrationChallengeType>

    /**
     * Registers an observer for sign in status changes.
     *
     * @param id unique ID to associate with the observer.
     * @param observer sign in status observer to register.
     */
    fun registerSignInStatusObserver(id: String, observer: SignInStatusObserver)

    /**
     * Deregisters an existing sign in status observer.
     *
     * @param id ID of the observer to deregister.
     */
    fun deregisterSignInStatusObserver(id: String)

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
        private const val CONFIG_REGISTRATION_METHODS = "registrationMethods"

        private const val SIGN_IN_PARAM_NAME_USER_KEY_ID = "userKeyId"
        private const val SIGN_IN_PARAM_NAME_CHALLENGE_TYPE = "challengeType"
        private const val SIGN_IN_PARAM_NAME_ANSWER = "answer"

        private const val AES_BLOCK_SIZE = 16

        private const val MAX_VALIDATION_DATA_SIZE = 2048
    }

    override val version: String = "8.0.4"

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

    /**
     * List of supported registration challenge types.
     */
    private val challengeTypes: List<RegistrationChallengeType>

    /**
     * List of sign in status observers.
     */
    private val signInStatusObservers: MutableMap<String, SignInStatusObserver> = mutableMapOf()

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

        @Suppress("UNCHECKED_CAST")
        val registrationMethods =
            identityServiceConfig.opt(CONFIG_REGISTRATION_METHODS) as JSONArray?
        if (registrationMethods != null) {
            this.challengeTypes = Array(registrationMethods.length()) {
                try {
                    RegistrationChallengeType.valueOf(registrationMethods.getString(it))
                } catch (e: Exception) {
                    // Ignore registration methods not relevant for Android SDK.
                }
            }.asList() as List<RegistrationChallengeType>
        } else {
            this.challengeTypes = listOf()
        }

        val authProvider = GraphQLAuthProvider(this)

        this.apiClient = apiClient ?: AWSAppSyncClient.builder()
            .serverUrl(apiUrl)
            .region(Regions.fromName(region))
            .cognitoUserPoolsAuthProvider(authProvider)
            .context(this.context)
            .okHttpClient(buildOkHttpClient())
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

        return if (idToken != null && accessToken != null && expiry != null) {
            expiry.time > Date().time
        } else {
            false
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

    override suspend fun registerWithSafetyNetAttestation(
        attestationResult: String,
        nonce: String,
        registrationId: String?
    ): String {
        this.logger.info("Registering using registration challenge.")

        if (!this.isRegistered()) {
            // Clear out any partial registration data.
            this.reset()

            // Generate user ID.
            val uid = this.idGenerator.generateId().toUpperCase(Locale.US)

            val publicKey = this.generateRegistrationData()

            // Generate the shared encryption key.
            this.generateSymmetricKey()

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

            val answerMetadata =
                mapOf<String, Any>(CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER_PARTS to answerPartNames)
            parameters[CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER_METADATA] =
                JSONObject(answerMetadata).toString()

            val userId = identityProvider.register(uid, parameters)
            setUserId(userId)
            return userId
        } else {
            throw RegisterException.AlreadyRegisteredException("Client is already registered.")
        }
    }

    override fun registerWithSafetyNetAttestation(
        attestationResult: String,
        nonce: String,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    ) {
        this.logger.info("Registering using registration challenge.")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val userId = registerWithSafetyNetAttestation(attestationResult, nonce, registrationId)
                callback(RegisterResult.Success(userId))
            } catch (e: RegisterException) {
                toApiException(e)?.let { callback(RegisterResult.Failure(it)) }?: callback(RegisterResult.Failure(e))
            }
        }
    }

    override suspend fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?
    ): String {
        this.logger.info("Registering using external authentication provider.")

        if (!this.isRegistered()) {
            val authInfo = authenticationProvider.getAuthenticationInfo()
            val token = authInfo.encode()
            val jwt = JWT.decode(token)

            val uid = jwt?.subject ?: this.idGenerator.generateId().toUpperCase(Locale.US)

            val parameters = mutableMapOf(
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_CHALLENGE_TYPE to authInfo.type,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER to token,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_REGISTRATION_ID to (registrationId
                    ?: this.idGenerator.generateId())
            )

            if (authInfo.type == "TEST") {
                // Generate a signing key for TEST registration.
                val publicKey = this.generateRegistrationData()
                parameters[CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_PUBLIC_KEY] =
                    publicKey.encode()
            }

            // Generate the shared encryption key.
            this.generateSymmetricKey()

            val userId = identityProvider.register(uid, parameters)
            setUserId(userId)
            return userId
        } else {
            throw RegisterException.AlreadyRegisteredException("Client is already registered.")
        }
    }

    override fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?,
        callback: (RegisterResult) -> Unit
    ) {
        this.logger.info("Registering using external authentication provider.")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val userId = registerWithAuthenticationProvider(authenticationProvider, registrationId)
                callback(RegisterResult.Success(userId))
            } catch (e: RegisterException) {
                toApiException(e)?.let { callback(RegisterResult.Failure(it)) }?: callback(RegisterResult.Failure(e))
            }
        }
    }

    override suspend fun deregister() {
        this.logger.info("De-registering user.")

        val accessToken = this.getAccessToken()

        if (accessToken != null) {
            try {
                val mutation = DeregisterMutation.builder().build()

                val response = this.apiClient.mutate(mutation).enqueue()

                if(response.hasErrors()) {
                    throw response.errors().first().toDeregisterException()
                }

                val result = response.data()?.deregister()
                if (result != null) {
                    this.reset()
                    return
                } else {
                    throw DeregisterException.FailedException("Mutation succeeded but output was null.")
                }
            } catch (t: Throwable) {
                when (t) {
                    is DeregisterException -> throw t
                    else -> throw DeregisterException.FailedException(cause = t)
                }
            }
        }
    }

    override fun deregister(callback: (ApiResult) -> Unit) {
        this.logger.info("De-registering user.")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                deregister()
                callback(ApiResult.Success)
            } catch (e: DeregisterException) {
                toApiException(e)?.let { callback(ApiResult.Failure(it)) }?: callback(ApiResult.Failure(e))
            }
        }
    }

    override suspend fun signInWithKey(): AuthenticationTokens {
        this.logger.info("Signing in using private key.")

        val uid = this.getUserName()
        val userKeyId = this.keyManager.getPassword(namespace(KEY_NAME_USER_KEY_ID))
            ?.toString(Charsets.UTF_8)

        if (uid != null && userKeyId != null) {
            val parameters = mapOf(
                SIGN_IN_PARAM_NAME_USER_KEY_ID to userKeyId
            )

            this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.SIGNING_IN) }

            try {
                val authenticationTokens = identityProvider.signIn(uid, parameters)

                storeTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime
                )

                credentialsProvider.logins = getLogins()

                return registerFederatedIdAndRefreshTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime
                )

            } catch (e: AuthenticationException) {
                signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.NOT_SIGNED_IN) }
                throw e
            }
        } else {
            this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.NOT_SIGNED_IN) }
            throw AuthenticationException.NotRegisteredException("Not registered.")
        }
    }

    override fun signInWithKey(callback: (SignInResult) -> Unit) {
        this.logger.info("Signing in using private key.")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val authenticationResult = signInWithKey()
                callback(toSuccessfulSignInResult(authenticationResult))
            } catch (e: AuthenticationException) {
                toApiException(e)?.let { callback(SignInResult.Failure(it)) }?: callback(SignInResult.Failure(e))
            }
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

    override suspend fun signInWithAuthenticationProvider(authenticationProvider: AuthenticationProvider): AuthenticationTokens {
        this.logger.info("Signing in with authentication provider.")

        val authInfo = authenticationProvider.getAuthenticationInfo()
        val uid = authInfo.getUsername()

        if (uid != null) {
            val parameters = mapOf(
                SIGN_IN_PARAM_NAME_CHALLENGE_TYPE to authInfo.type,
                SIGN_IN_PARAM_NAME_ANSWER to authInfo.encode()
            )

            this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.SIGNING_IN) }

            try {
                val authenticationTokens = this.identityProvider.signIn(uid, parameters)

                this.storeTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime
                )

                this.credentialsProvider.logins = this.getLogins()

                return this.registerFederatedIdAndRefreshTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime
                )
            } catch (e: AuthenticationException) {
                signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.NOT_SIGNED_IN) }
                throw e
            }
        } else {
            this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.NOT_SIGNED_IN) }
            throw AuthenticationException.NotRegisteredException("Not registered.")
        }
    }

    override suspend fun refreshTokens(refreshToken: String): AuthenticationTokens {
        this.logger.info("Refreshing authentication tokens.")

        this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.SIGNING_IN) }

        try {
            val refreshTokenResult = identityProvider.refreshTokens(refreshToken)
            storeTokens(
                refreshTokenResult.idToken,
                refreshTokenResult.accessToken,
                refreshTokenResult.refreshToken,
                refreshTokenResult.lifetime
            )

            this.credentialsProvider.logins = this.getLogins()

            this@DefaultSudoUserClient.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.SIGNED_IN) }
            return AuthenticationTokens(
                    refreshTokenResult.idToken,
                    refreshTokenResult.accessToken,
                    refreshTokenResult.refreshToken,
                    refreshTokenResult.lifetime
                )
        } catch (e: AuthenticationException) {
            this@DefaultSudoUserClient.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.NOT_SIGNED_IN) }
            throw e
        }
    }

    override fun refreshTokens(refreshToken: String, callback: (SignInResult) -> Unit) {
        this.logger.info("Refreshing authentication tokens.")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val refreshTokenResult = refreshTokens(refreshToken)
                callback(toSuccessfulSignInResult(refreshTokenResult))
            } catch (e: AuthenticationException) {
                toApiException(e)?.let { callback(SignInResult.Failure(it)) }?: callback(SignInResult.Failure(e))
            }
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
     * Generates cryptographic keys required for registration.
     *
     * @return public key.
     */
    private fun generateRegistrationData(): PublicKey {
        // Delete existing key.
        val userKeyId = this.keyManager.getPassword(namespace(KEY_NAME_USER_KEY_ID))?.toString(Charsets.UTF_8)
        if (userKeyId != null) {
            this.keyManager.deleteKeyPair(userKeyId)
            this.keyManager.deletePassword(namespace(KEY_NAME_USER_KEY_ID))
        }

        // Generate and store user's key ID.
        val keyId = this.idGenerator.generateId().toUpperCase(Locale.US)
        this.keyManager.addPassword(keyId.toByteArray(), namespace(KEY_NAME_USER_KEY_ID))

        // Generate a new key pair for authentication and encryption.
        this.keyManager.generateKeyPair(keyId)

        // Retrieve the public key so it can be registered with the backend.
        val keyData = this.keyManager.getPublicKeyData(keyId)

        return PublicKey(keyId, keyData)
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

    override suspend fun globalSignOut() {
        val accessToken = this.getAccessToken()
        if (accessToken != null) {
            this.identityProvider.globalSignOut(accessToken)
            this.clearAuthTokens()
        }
    }

    override fun globalSignOut(callback: (ApiResult) -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                globalSignOut()
                callback(ApiResult.Success)
            } catch (e: SignOutException) {
                toApiException(e)?.let { callback(ApiResult.Failure(it)) }?: callback(ApiResult.Failure(e))
            }
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

    override fun getSupportedRegistrationChallengeType(): List<RegistrationChallengeType> {
        return this.challengeTypes
    }

    override fun registerSignInStatusObserver(id: String, observer: SignInStatusObserver) {
        this.signInStatusObservers[id] = observer
    }

    override fun deregisterSignInStatusObserver(id: String) {
        this.signInStatusObservers.remove(id)
    }

    /**
     * Stores authentication tokens in the key store.fx
     *
     * @param idToken ID token.
     * @param accessToken access token.
     * @param refreshToken refresh token.
     * @param lifetime token lifetime in seconds.
     */
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

    private suspend fun registerFederatedIdAndRefreshTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int
    ): AuthenticationTokens {
        this.logger.info("Registering federated ID.")

        // If the identity ID is already in the ID token as a claim then no need to register
        // the federated identity again.
        val identityId = this.getUserClaim("custom:identityId")
        if (identityId != null) {
            this.signInStatusObservers.values.forEach { it.signInStatusChanged(SignInStatus.SIGNED_IN) }
            return AuthenticationTokens(idToken, accessToken, refreshToken, lifetime)
        }

        try {
            val input = RegisterFederatedIdInput.builder().idToken(idToken).build()

            val mutation = RegisterFederatedIdMutation.builder().input(input).build()

            val response = this.apiClient.mutate(mutation)
                .enqueue()

            if (response.hasErrors()) {
                throw response.errors().first().toRegistrationException()
            }

            val result = response.data()?.registerFederatedId()
            if (result != null) {
                return refreshTokens(refreshToken)
            } else {
                throw RegisterException.FailedException("Mutation succeeded but output was null.")
            }

        } catch (t: Throwable) {
            when (t) {
                is RegisterException -> throw t
                else -> throw RegisterException.FailedException(cause = t)
            }
        }
    }

    private fun registerFederatedIdAndRefreshTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int,
        callback: (SignInResult) -> Unit
    ) {
        this.logger.info("Registering federated ID.")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val authenticationResult = registerFederatedIdAndRefreshTokens(idToken, accessToken, refreshToken, lifetime)
                callback(toSuccessfulSignInResult(authenticationResult))
            } catch (e: Exception) {
                callback(SignInResult.Failure(e))
            }
        }
    }

    private fun toSuccessfulSignInResult(authenticationTokens: AuthenticationTokens): SignInResult.Success {
        return SignInResult.Success(
            authenticationTokens.idToken,
            authenticationTokens.accessToken,
            authenticationTokens.refreshToken,
            authenticationTokens.lifetime
        )
    }

    /**
     * Construct the [OkHttpClient] configured with the certificate transparency checking interceptor.
     */
    private fun buildOkHttpClient(): OkHttpClient {
        val interceptor = certificateTransparencyInterceptor {
            // Enable for AWS hosts. The document says I can use *.* for all hosts
            // but that enhancement hasn't been released yet (v0.2.0)
            +"*.amazonaws.com"
            +"*.amazon.com"

            // Enabled for testing
            +"*.badssl.com"
        }
        val okHttpClient = OkHttpClient.Builder().apply {
            // Convert exceptions from certificate transparency into http errors that stop the
            // exponential backoff retrying of [AWSAppSyncClient]
            addInterceptor(ConvertSslErrorsInterceptor())

            // Certificate transparency checking
            addNetworkInterceptor(interceptor)
        }
        return okHttpClient.build()
    }

}