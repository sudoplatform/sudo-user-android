/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.app.Activity
import android.content.Context
import android.net.Uri
import com.amazonaws.auth.CognitoCachingCredentialsProvider
import com.amazonaws.auth.CognitoCredentialsProvider
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.regions.Regions
import com.sudoplatform.sudokeymanager.KeyManagerFactory
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.appmattus.certificatetransparency.certificateTransparencyInterceptor
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.exceptions.AuthenticationException
import com.sudoplatform.sudouser.exceptions.DeregisterException
import com.sudoplatform.sudouser.exceptions.GlobalSignOutException
import com.sudoplatform.sudouser.exceptions.RegisterException
import com.sudoplatform.sudouser.exceptions.SignOutException
import com.sudoplatform.sudouser.type.RegisterFederatedIdInput
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import java.util.Date
import java.util.Locale
import com.sudoplatform.sudouser.extensions.enqueue
import com.sudoplatform.sudouser.extensions.toDeregisterException
import com.sudoplatform.sudouser.extensions.toGlobalSignOutException
import com.sudoplatform.sudouser.extensions.toRegistrationException

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
        private var namespace: String? = "ids"
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
                this.config,
                this.keyManager,
                this.identityProvider,
                this.apiClient,
                this.credentialsProvider,
                this.authUI,
                this.idGenerator ?: IdGenerateImpl()
            )
        }
    }

    /**
     * Checksum's for each file are generated and are used to create a checksum that is used when publishing to maven central.
     * In order to retry a failed publish without needing to change any functionality, we need a way to generate a different checksum
     * for the source code.  We can change the value of this property which will generate a different checksum for publishing
     * and allow us to retry.  The value of `version` doesn't need to be kept up-to-date with the version of the code.
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

    /**
     * De-registers a user.
     */
    @Throws(DeregisterException::class)
    suspend fun deregister()

    /**
     * Sign into the backend using a private key. The client must have created a private/public key pair via
     * one of the *register* methods.
     *
     * @return Successful authentication result [AuthenticationTokens]
     */
    @Throws(AuthenticationException::class)
    suspend fun signInWithKey(): AuthenticationTokens

    /**
     * Presents the sign in UI for federated sign in using an external identity provider.
     *
     * @param activity activity to launch custom tabs from and to listen for the intent completions.
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     */
    fun presentFederatedSignInUI(activity: Activity, callback: (SignInResult) -> Unit)

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
     * @param callback callback for returning sign in result containing ID, access and refresh token or error.
     */
    fun processFederatedSignInTokens(data: Uri, callback: (FederatedSignInResult) -> Unit)

    /**
     * Refresh the access and ID tokens using the refresh token.
     *
     * @return successful authentication result [AuthenticationTokens]
     */
    @Throws(AuthenticationException::class)
    suspend fun refreshTokens(refreshToken: String): AuthenticationTokens

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

    /**
     * Returns the refresh token expiry cached from the last sign-in.
     *
     * @return refresh token expiry.
     */
    fun getRefreshTokenExpiry(): Date?

    /**
     * Returns the user name associated with this client. The username maybe needed to contact
     * the support team when diagnosing an issue related to a specific user.
     *
     * @return user name.
     */
    fun getUserName(): String?

    /**
     * Sets the user name associated with this client.
     *
     * @param name user name to set.
     */
    fun setUserName(name: String)

    /**
     * Returns the subject of the user associated with this client.
     * Note: This is an internal method used by other Sudo platform SDKs.
     *
     * @return user subject.
     */
    fun getSubject(): String?

    /**
     * Clears cached authentication tokens.
     */
    fun clearAuthTokens()

    /**
     * Signs out the user from this device only.
     */
    @Throws(SignOutException::class)
    suspend fun signOut()

    /**
     * Signs out the user from all devices.
     */
    @Throws(SignOutException::class)
    suspend fun globalSignOut()

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
        private const val KEY_NAME_USER_ID = "userId"
        private const val KEY_NAME_USER_KEY_ID = "userKeyId"
        private const val KEY_NAME_ID_TOKEN = "idToken"
        private const val KEY_NAME_ACCESS_TOKEN = "accessToken"
        private const val KEY_NAME_REFRESH_TOKEN = "refreshToken"
        private const val KEY_NAME_TOKEN_EXPIRY = "tokenExpiry"
        private const val KEY_NAME_REFRESH_TOKEN_EXPIRY = "refreshTokenExpiry"

        private const val CONFIG_NAMESPACE_IDENTITY_SERVICE = "identityService"
        private const val CONFIG_NAMESPACE_FEDERATED_SIGN_IN = "federatedSignIn"

        private const val CONFIG_REGION = "region"
        private const val CONFIG_POOL_ID = "poolId"
        private const val CONFIG_IDENTITY_POOL_ID = "identityPoolId"
        private const val CONFIG_API_URL = "apiUrl"
        private const val CONFIG_REGISTRATION_METHODS = "registrationMethods"
        private const val CONFIG_REFRESH_TOKEN_LIFETIME = "refreshTokenLifetime"

        private const val SIGN_IN_PARAM_NAME_USER_KEY_ID = "userKeyId"
        private const val SIGN_IN_PARAM_NAME_CHALLENGE_TYPE = "challengeType"
        private const val SIGN_IN_PARAM_NAME_ANSWER = "answer"

        private const val AES_BLOCK_SIZE = 16

        private const val MAX_VALIDATION_DATA_SIZE = 2048
    }

    override val version: String = "11.0.0"

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
     * Refresh token lifetime in days.
     */
    private val refreshTokenLifetime: Int

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
        val identityServiceConfig: JSONObject?
        val federatedSignInConfig: JSONObject?
        if(config != null) {
            identityServiceConfig = config.opt(CONFIG_NAMESPACE_IDENTITY_SERVICE) as JSONObject?
            federatedSignInConfig = config.opt(CONFIG_NAMESPACE_FEDERATED_SIGN_IN) as JSONObject?
        } else {
            val configManager = DefaultSudoConfigManager(context)
            identityServiceConfig = configManager.getConfigSet(CONFIG_NAMESPACE_IDENTITY_SERVICE)
            federatedSignInConfig = configManager.getConfigSet(CONFIG_NAMESPACE_FEDERATED_SIGN_IN)
        }

        require(identityServiceConfig != null) { "Client configuration not found." }

        this.keyManager =
            keyManager ?: KeyManagerFactory(context).createAndroidKeyManager(this.namespace)
        this.identityProvider = identityProvider ?: CognitoUserPoolIdentityProvider(
            identityServiceConfig,
            context,
            this.keyManager,
            PasswordGeneratorImpl(),
            this.logger
        )

        val apiUrl = identityServiceConfig[CONFIG_API_URL] as String?
        val region = identityServiceConfig[CONFIG_REGION] as String?
        var refreshTokenLifetime = identityServiceConfig.optInt(CONFIG_REFRESH_TOKEN_LIFETIME, 60)

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

        if (federatedSignInConfig != null) {
            this.authUI = authUI ?: CognitoAuthUI(
                federatedSignInConfig,
                context
            )

            refreshTokenLifetime = federatedSignInConfig.optInt(CONFIG_REFRESH_TOKEN_LIFETIME, 60)
        }

        this.refreshTokenLifetime = refreshTokenLifetime

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
        val uid = this.keyManager.getPassword(KEY_NAME_USER_ID)
        return uid != null
    }

    override fun isSignedIn(): Boolean {
        val idToken = this.getIdToken()
        val accessToken = this.getAccessToken()
        val expiry = this.getRefreshTokenExpiry()

        return if (idToken != null && accessToken != null && expiry != null) {
            // Considered signed in up to 1 hour before the expiry of refresh token.
            expiry.time > (Date().time + 60 * 60 * 1000)
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
            val uid = this.idGenerator.generateId().uppercase(Locale.US)

            val publicKey = this.generateRegistrationData()

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
            this.setUserName(userId)
            return userId
        } else {
            throw RegisterException.AlreadyRegisteredException("Client is already registered.")
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

            val uid = jwt?.subject ?: this.idGenerator.generateId().uppercase(Locale.US)

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

            val userId = identityProvider.register(uid, parameters)
            this.setUserName(userId)
            return userId
        } else {
            throw RegisterException.AlreadyRegisteredException("Client is already registered.")
        }
    }

    override suspend fun deregister() {
        this.logger.info("De-registering user.")

        if (!this.isRegistered()) {
            throw AuthenticationException.NotRegisteredException()
        }

        val accessToken = this.getAccessToken()

        if (accessToken != null) {
            try {
                val mutation = DeregisterMutation.builder().build()

                val response = this.apiClient.mutate(mutation).enqueue()

                if (response.hasErrors()) {
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

    override suspend fun signInWithKey(): AuthenticationTokens {
        this.logger.info("Signing in using private key.")

        val uid = this.getUserName()
        val userKeyId = this.keyManager.getPassword(KEY_NAME_USER_KEY_ID)
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

                this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

                this.credentialsProvider.logins = getLogins()
                this.credentialsProvider.refresh()

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

    override fun presentFederatedSignInUI(activity: Activity, callback: (SignInResult) -> Unit) {
        this.authUI?.presentFederatedSignInUI(activity) { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(

                        KEY_NAME_USER_ID

                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        KEY_NAME_USER_ID
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime
                    )

                    this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

                    this.credentialsProvider.logins = this.getLogins()
                    CoroutineScope(Dispatchers.IO).launch {
                        this@DefaultSudoUserClient.credentialsProvider.refresh()

                        val authenticationTokens =
                            this@DefaultSudoUserClient.registerFederatedIdAndRefreshTokens(
                                result.idToken,
                                result.accessToken,
                                result.refreshToken,
                                result.lifetime,
                            )

                        callback(
                            SignInResult.Success(
                                authenticationTokens.idToken,
                                authenticationTokens.accessToken,
                                authenticationTokens.refreshToken,
                                authenticationTokens.lifetime,
                            )
                        )
                    }
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

    override fun processFederatedSignInTokens(
        data: Uri,
        callback: (FederatedSignInResult) -> Unit
    ) {
        this.authUI?.processFederatedSignInTokens(data) { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(

                        KEY_NAME_USER_ID

                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        KEY_NAME_USER_ID
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime
                    )

                    this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

                    this.credentialsProvider.logins = this.getLogins()

                    CoroutineScope(Dispatchers.IO).launch {
                        this@DefaultSudoUserClient.credentialsProvider.refresh()

                        callback(
                            FederatedSignInResult.Success(
                                result.idToken,
                                result.accessToken,
                                result.refreshToken,
                                result.lifetime,
                                result.username
                            )
                        )
                    }
                }
                is FederatedSignInResult.Failure -> {
                    this.logger.error("Failed to process the federated sign in redirect: ${result.error}")
                    callback(FederatedSignInResult.Failure(result.error))
                }
            }
        }
    }

    override suspend fun signInWithAuthenticationProvider(authenticationProvider: AuthenticationProvider): AuthenticationTokens {
        this.logger.info("Signing in with authentication provider.")

        val authInfo = authenticationProvider.getAuthenticationInfo()
        val uid = authInfo.getUsername()

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

            this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

            this.credentialsProvider.logins = this.getLogins()
            this.credentialsProvider.refresh()

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
            this.credentialsProvider.refresh()

            this@DefaultSudoUserClient.signInStatusObservers.values.forEach {
                it.signInStatusChanged(
                    SignInStatus.SIGNED_IN
                )
            }
            return AuthenticationTokens(
                refreshTokenResult.idToken,
                refreshTokenResult.accessToken,
                refreshTokenResult.refreshToken,
                refreshTokenResult.lifetime
            )
        } catch (e: AuthenticationException) {
            this@DefaultSudoUserClient.signInStatusObservers.values.forEach {
                it.signInStatusChanged(
                    SignInStatus.NOT_SIGNED_IN
                )
            }
            throw e
        }
    }

    /**
     * Generates cryptographic keys required for registration.
     *
     * @return public key.
     */
    private fun generateRegistrationData(): PublicKey {
        // Delete existing key.
        val userKeyId = this.keyManager.getPassword(KEY_NAME_USER_KEY_ID)?.toString(Charsets.UTF_8)
        if (userKeyId != null) {
            this.keyManager.deleteKeyPair(userKeyId)
            this.keyManager.deletePassword(KEY_NAME_USER_KEY_ID)
        }

        // Generate and store user's key ID.
        val keyId = this.idGenerator.generateId().uppercase(Locale.US)
        this.keyManager.addPassword(keyId.toByteArray(), KEY_NAME_USER_KEY_ID)

        // Generate a new key pair for authentication and encryption.
        this.keyManager.generateKeyPair(keyId)

        // Retrieve the public key so it can be registered with the backend.
        val keyData = this.keyManager.getPublicKeyData(keyId)

        return PublicKey(keyId, keyData)
    }

    override fun getIdToken(): String? {
        return this.keyManager.getPassword(KEY_NAME_ID_TOKEN)?.toString(Charsets.UTF_8)
    }

    override fun getAccessToken(): String? {
        return this.keyManager.getPassword(KEY_NAME_ACCESS_TOKEN)
            ?.toString(Charsets.UTF_8)
    }

    override fun getRefreshToken(): String? {
        return this.keyManager.getPassword(KEY_NAME_REFRESH_TOKEN)
            ?.toString(Charsets.UTF_8)
    }

    override fun getTokenExpiry(): Date? {
        var expiry: Date? = null

        val timeSinceEpoch =
            this.keyManager.getPassword(KEY_NAME_TOKEN_EXPIRY)?.toString(Charsets.UTF_8)
                ?.toLong()
        if (timeSinceEpoch != null) {
            expiry = Date(timeSinceEpoch)
        }

        return expiry
    }

    override fun getRefreshTokenExpiry(): Date? {
        var expiry: Date? = null

        val timeSinceEpoch =
            this.keyManager.getPassword(KEY_NAME_REFRESH_TOKEN_EXPIRY)?.toString(Charsets.UTF_8)
                ?.toLong()
        if (timeSinceEpoch != null) {
            expiry = Date(timeSinceEpoch)
        }

        return expiry
    }

    override fun getUserName(): String? {
        return this.keyManager.getPassword(KEY_NAME_USER_ID)?.toString(Charsets.UTF_8)
    }

    override fun setUserName(name: String) {
        this.keyManager.deletePassword(KEY_NAME_USER_ID)
        this.keyManager.addPassword(name.toByteArray(), KEY_NAME_USER_ID)
    }

    override fun getSubject(): String? {
        return this.getUserClaim("sub") as? String
    }

    @Synchronized override fun clearAuthTokens() {
        this.keyManager.deletePassword(KEY_NAME_ID_TOKEN)
        this.keyManager.deletePassword(KEY_NAME_ACCESS_TOKEN)
        this.keyManager.deletePassword(KEY_NAME_REFRESH_TOKEN)
        this.keyManager.deletePassword(KEY_NAME_TOKEN_EXPIRY)

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

    override suspend fun signOut() {
        this.logger.info("Signing out user from this device.")

        val refreshToken = this.getRefreshToken() ?: throw AuthenticationException.NotSignedInException()

        try {
            identityProvider.signOut(refreshToken)
            this.clearAuthTokens()
        } catch (t: Throwable) {
            when (t) {
                is SignOutException -> throw t
                else -> throw SignOutException.FailedException(cause = t)
            }
        }
    }

    override suspend fun globalSignOut() {
        this.logger.info("Globally signing out user.")

        if (!this.isSignedIn()) {
            throw AuthenticationException.NotSignedInException()
        }

        try {
            val mutation = GlobalSignOutMutation.builder().build()

            val response = this.apiClient.mutate(mutation).enqueue()

            if (response.hasErrors()) {
                throw response.errors().first().toGlobalSignOutException()
            }

            val result = response.data()?.globalSignOut()
            if (result != null) {
                this.clearAuthTokens()
                return
            } else {
                throw GlobalSignOutException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (t: Throwable) {
            when (t) {
                is GlobalSignOutException -> throw t
                else -> throw GlobalSignOutException.FailedException(cause = t)
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
     * Stores authentication tokens in the key store.
     *
     * @param idToken ID token.
     * @param accessToken access token.
     * @param refreshToken refresh token.
     * @param lifetime token lifetime in seconds.
     */
    @Synchronized private fun storeTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int
    ) {
        this.keyManager.deletePassword(KEY_NAME_ID_TOKEN)
        this.keyManager.addPassword(idToken.toByteArray(), KEY_NAME_ID_TOKEN)

        this.keyManager.deletePassword(KEY_NAME_ACCESS_TOKEN)
        this.keyManager.addPassword(accessToken.toByteArray(), KEY_NAME_ACCESS_TOKEN)

        this.keyManager.deletePassword(KEY_NAME_REFRESH_TOKEN)
        this.keyManager.addPassword(refreshToken.toByteArray(), KEY_NAME_REFRESH_TOKEN)

        this.keyManager.deletePassword(KEY_NAME_TOKEN_EXPIRY)
        this.keyManager.addPassword(
            "${lifetime * 1000 + Date().time}".toByteArray(),
            KEY_NAME_TOKEN_EXPIRY
        )
    }

    @Synchronized private fun storeRefreshTokenLifetime(refreshTokenLifetime: Int) {
        this.keyManager.deletePassword(KEY_NAME_REFRESH_TOKEN_EXPIRY)
        this.keyManager.addPassword(
            "${refreshTokenLifetime * 24L * 60L * 60L * 1000L + Date().time}".toByteArray(),
            KEY_NAME_REFRESH_TOKEN_EXPIRY
        )
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

    /**
     * Construct the [OkHttpClient] configured with the certificate transparency checking interceptor.
     */
    private fun buildOkHttpClient(): OkHttpClient {
        val interceptor = certificateTransparencyInterceptor {}
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