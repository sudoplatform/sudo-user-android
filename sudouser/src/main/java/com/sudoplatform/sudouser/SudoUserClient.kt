/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import android.app.Activity
import android.content.Context
import android.net.Uri
import com.amazonaws.auth.CognitoCachingCredentialsProvider
import com.amazonaws.auth.CognitoCredentialsProvider
import com.amazonaws.regions.Regions
import com.amplifyframework.api.ApiCategory
import com.amplifyframework.api.ApiCategoryConfiguration
import com.amplifyframework.api.ApiException
import com.amplifyframework.api.aws.AWSApiPlugin
import com.amplifyframework.api.aws.ApiAuthProviders
import com.apollographql.apollo3.api.Optional
import com.appmattus.certificatetransparency.cache.AndroidDiskCache
import com.appmattus.certificatetransparency.certificateTransparencyInterceptor
import com.appmattus.certificatetransparency.loglist.LogListDataSourceFactory
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudokeymanager.AndroidSQLiteStore
import com.sudoplatform.sudokeymanager.KeyManagerFactory
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.sudoplatform.sudokeymanager.KeyNotFoundException
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.amplify.GraphQLAuthProvider
import com.sudoplatform.sudouser.amplify.GraphQLClient
import com.sudoplatform.sudouser.exceptions.SudoUserException
import com.sudoplatform.sudouser.exceptions.SudoUserException.Companion.toSudoUserException
import com.sudoplatform.sudouser.graphql.DeregisterMutation
import com.sudoplatform.sudouser.graphql.GlobalSignOutMutation
import com.sudoplatform.sudouser.graphql.RegisterFederatedIdMutation
import com.sudoplatform.sudouser.graphql.ResetMutation
import com.sudoplatform.sudouser.graphql.type.RegisterFederatedIdInput
import com.sudoplatform.sudouser.http.ConvertClientErrorsInterceptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import org.json.JSONObject
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.Locale
import kotlin.coroutines.cancellation.CancellationException

/**
 * Interface encapsulating a library of functions for calling Sudo Platform identity service, managing keys, performing
 * cryptographic operations.
 */
interface SudoUserClient : AutoCloseable {

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
        private var apiClient: GraphQLClient? = null
        private var namespace: String? = "ids"
        private var logger: Logger? = null
        private var config: JSONObject? = null
        private var keyManager: KeyManagerInterface? = null
        private var identityProvider: IdentityProvider? = null
        private var credentialsProvider: CognitoCredentialsProvider? = null
        private var authUI: AuthUI? = null
        private var idGenerator: IdGenerator? = IdGenerateImpl()
        private var databaseName: String? = AndroidSQLiteStore.DEFAULT_DATABASE_NAME

        /**
         * Provide an [GraphQLClient] for the [SudoUserClient]. If this is not supplied,
         * a default [GraphQLClient] will be used. This is mainly used for unit testing.
         */
        fun setApiClient(apiClient: GraphQLClient) = also {
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
         * Provide the database name to use for exportable key store database.
         */
        fun setDatabaseName(databaseName: String) = also {
            this.databaseName = databaseName
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
                this.idGenerator ?: IdGenerateImpl(),
                this.databaseName ?: AndroidSQLiteStore.DEFAULT_DATABASE_NAME,
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
     * Registers this client against the backend with an external authentication provider. Caller must
     * implement [AuthenticationProvider] protocol to return appropriate authentication token required
     * to authorize the registration request.
     *
     * @param authenticationProvider authentication provider that provides the authentication token.
     * @param registrationId registration ID to uniquely identify this registration request.
     * @return user ID of the newly created user
     */
    @Throws(SudoUserException::class)
    suspend fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?,
    ): String

    /**
     * Registers this client against the backend with a Google Play Integrity token.
     *
     * @param packageName app package name.
     * @param deviceId device ID (Android ID).
     * @param token Google Play Integrity token.
     * @param registrationId registration ID to uniquely identify this registration request.
     * @return user ID of the newly created user
     */
    @Throws(SudoUserException::class)
    suspend fun registerWithGooglePlayIntegrity(
        packageName: String,
        deviceId: String,
        token: String,
        registrationId: String?,
    ): String

    /**
     * De-registers a user.
     */
    @Throws(SudoUserException::class)
    suspend fun deregister()

    /**
     * Sign into the backend using a private key. The client must have created a private/public key pair via
     * one of the *register* methods.
     *
     * @return Successful authentication result [AuthenticationTokens]
     */
    @Throws(SudoUserException::class)
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
    @Throws(SudoUserException::class)
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
    @Throws(SudoUserException::class)
    suspend fun signOut()

    /**
     * Signs out the user from all devices.
     */
    @Throws(SudoUserException::class)
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

    /**
     * Removes all data owned by the signed-in user from Sudo Platform Services without deregistering
     * the user. Should only be used in tests.
     */
    suspend fun resetUserData()
}

/**
 * Default implementation of [SudoUserClient] interface.
 *
 * @param config configuration parameters.
 * @param context Android app context.
 * @param namespace namespace to use for internal data and cryptographic keys. This should be unique
 *  per client per app to avoid name conflicts between multiple clients.
 * @param databaseName database name to use for the exportable key store database.
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
    apiClient: GraphQLClient? = null,
    credentialsProvider: CognitoCredentialsProvider? = null,
    authUI: AuthUI? = null,
    idGenerator: IdGenerator = IdGenerateImpl(),
    private val databaseName: String = AndroidSQLiteStore.DEFAULT_DATABASE_NAME,
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
        private const val CONFIG_NAMESPACE_CT_LOG_LIST_SERVICE = "ctLogListService"

        private const val CONFIG_REGION = "region"
        private const val CONFIG_POOL_ID = "poolId"
        private const val CONFIG_IDENTITY_POOL_ID = "identityPoolId"
        private const val CONFIG_API_URL = "apiUrl"
        private const val CONFIG_REFRESH_TOKEN_LIFETIME = "refreshTokenLifetime"
        private const val CONFIG_LOG_LIST_URL = "logListUrl"

        private const val SIGN_IN_PARAM_NAME_USER_KEY_ID = "userKeyId"
        private const val SIGN_IN_PARAM_NAME_CHALLENGE_TYPE = "challengeType"
        private const val SIGN_IN_PARAM_NAME_ANSWER = "answer"

        private const val SIGN_IN_PARAM_VALUE_CHALLENGE_TYPE_PLAY_INTEGRITY = "PLAY_INTEGRITY"
    }

    override val version: String = "20.0.1"

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
    private val apiClient: GraphQLClient

    /**
     * List of sign in status observers.
     */
    private val signInStatusObservers: MutableMap<String, SignInStatusObserver> = mutableMapOf()

    init {
        val identityServiceConfig: JSONObject?
        val federatedSignInConfig: JSONObject?
        val ctLogListServiceConfig: JSONObject?
        if (config != null) {
            identityServiceConfig = config.opt(CONFIG_NAMESPACE_IDENTITY_SERVICE) as JSONObject?
            federatedSignInConfig = config.opt(CONFIG_NAMESPACE_FEDERATED_SIGN_IN) as JSONObject?
            ctLogListServiceConfig = config.opt(CONFIG_NAMESPACE_CT_LOG_LIST_SERVICE) as JSONObject?
        } else {
            val configManager = DefaultSudoConfigManager(context)
            identityServiceConfig = configManager.getConfigSet(CONFIG_NAMESPACE_IDENTITY_SERVICE)
            federatedSignInConfig = configManager.getConfigSet(CONFIG_NAMESPACE_FEDERATED_SIGN_IN)
            ctLogListServiceConfig =
                configManager.getConfigSet(CONFIG_NAMESPACE_CT_LOG_LIST_SERVICE)
        }

        require(identityServiceConfig != null) { "Client configuration not found." }

        this.keyManager =
            keyManager ?: KeyManagerFactory(context).createAndroidKeyManager(
                this.namespace,
                this.databaseName,
            )
        this.identityProvider = identityProvider ?: CognitoUserPoolIdentityProvider(
            identityServiceConfig,
            context,
            this.keyManager,
            PasswordGeneratorImpl(),
            this.logger,
        )

        val apiUrl = identityServiceConfig[CONFIG_API_URL] as String?
        val region = identityServiceConfig[CONFIG_REGION] as String?
        var refreshTokenLifetime = identityServiceConfig.optInt(CONFIG_REFRESH_TOKEN_LIFETIME, 60)

        val authProvider = GraphQLAuthProvider(this)
        val logListUrl = ctLogListServiceConfig?.getString(CONFIG_LOG_LIST_URL)
        if (apiClient !== null) {
            this.apiClient = apiClient
        } else {
            val graphqlConfig = JSONObject(
                """
                {
                    'plugins': {
                        'awsAPIPlugin': {
                            '$CONFIG_NAMESPACE_IDENTITY_SERVICE': {
                                'endpointType': 'GraphQL',
                                'endpoint': '$apiUrl',
                                'region': '${Regions.fromName(region)}',
                                'authorizationType': 'AMAZON_COGNITO_USER_POOLS'
                            }
                        }
                    }
                } 
                """.trimIndent(),
            )

            val apiCategoryConfiguration = ApiCategoryConfiguration()
            apiCategoryConfiguration.populateFromJSON(graphqlConfig)
            val apiCategory = ApiCategory()
            val authProviders = ApiAuthProviders.builder().cognitoUserPoolsAuthProvider(authProvider).build()
            val awsApiPlugin = AWSApiPlugin
                .builder()
                .apiAuthProviders(authProviders)
                .configureClient(
                    CONFIG_NAMESPACE_IDENTITY_SERVICE,
                ) { builder -> this.buildOkHttpClient(builder, context, logListUrl) }
                .build()

            apiCategory.addPlugin(awsApiPlugin)
            apiCategory.configure(apiCategoryConfiguration, context)

            apiCategory.initialize(context)

            this.apiClient = GraphQLClient(apiCategory)
        }

        this.idGenerator = idGenerator

        if (federatedSignInConfig != null) {
            this.authUI = authUI ?: CognitoAuthUI(
                federatedSignInConfig,
                context,
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
            Regions.fromName(region),
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
        this.credentialsProvider.clear()
        this.credentialsProvider.clearCredentials()
        this.clearAuthTokens()
    }

    override fun close() {
        this.authUI?.close()
    }

    override suspend fun registerWithAuthenticationProvider(
        authenticationProvider: AuthenticationProvider,
        registrationId: String?,
    ): String {
        this.logger.info("Registering using external authentication provider.")

        if (!this.isRegistered()) {
            val authInfo = authenticationProvider.getAuthenticationInfo()
            val token = authInfo.encode()
            val uid = authInfo.getUsername()

            val parameters = mutableMapOf(
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_CHALLENGE_TYPE to authInfo.type,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER to token,
                CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_REGISTRATION_ID to (
                    registrationId
                        ?: this.idGenerator.generateId()
                    ),
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
            throw SudoUserException.AlreadyRegisteredException("Client is already registered.")
        }
    }

    override suspend fun registerWithGooglePlayIntegrity(
        packageName: String,
        deviceId: String,
        token: String,
        registrationId: String?,
    ): String {
        this.logger.info("Registering using Google Play Integrity.")

        if (this.isRegistered()) {
            throw SudoUserException.AlreadyRegisteredException("Client is already registered.")
        }

        val parameters = mutableMapOf(
            CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_CHALLENGE_TYPE to SIGN_IN_PARAM_VALUE_CHALLENGE_TYPE_PLAY_INTEGRITY,
            CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_DEVICE_ID to deviceId,
            CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_PACKAGE_NAME to packageName,
            CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_ANSWER to token,
            CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_REGISTRATION_ID to (
                registrationId
                    ?: this.idGenerator.generateId()
                ),
        )

        // Generate a signing key.
        val publicKey = this.generateRegistrationData()
        parameters[CognitoUserPoolIdentityProvider.REGISTRATION_PARAM_PUBLIC_KEY] =
            publicKey.encode()

        val uid = this.idGenerator.generateId()
        val userId = identityProvider.register(uid, parameters)
        this.setUserName(userId)
        return userId
    }

    override suspend fun deregister() {
        this.logger.info("De-registering user.")

        if (!this.isSignedIn()) {
            throw SudoUserException.NotSignedInException()
        }

        try {
            val response = this.apiClient.mutate<DeregisterMutation, DeregisterMutation.Data>(
                DeregisterMutation.OPERATION_DOCUMENT,
                emptyMap(),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoUserException()
            }

            val result = response.data?.deregister
            if (result != null && result.success) {
                this.reset()
            } else {
                throw SudoUserException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (t: Throwable) {
            when (t) {
                is SudoUserException -> throw t
                else -> throw SudoUserException.FailedException(cause = t)
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
                SIGN_IN_PARAM_NAME_USER_KEY_ID to userKeyId,
            )

            this.invokeSignInStatusObservers(SignInStatus.SIGNING_IN)

            try {
                val authenticationTokens = identityProvider.signIn(uid, parameters)

                storeTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime,
                )

                this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

                this.credentialsProvider.logins = getLogins()
                this.credentialsProvider.refresh()

                return registerFederatedIdAndRefreshTokens(
                    authenticationTokens.idToken,
                    authenticationTokens.accessToken,
                    authenticationTokens.refreshToken,
                    authenticationTokens.lifetime,
                )
            } catch (e: SudoUserException) {
                this.invokeSignInStatusObservers(SignInStatus.NOT_SIGNED_IN)
                throw e
            }
        } else {
            this.invokeSignInStatusObservers(SignInStatus.NOT_SIGNED_IN)
            throw SudoUserException.NotRegisteredException("Not registered.")
        }
    }

    override fun presentFederatedSignInUI(activity: Activity, callback: (SignInResult) -> Unit) {
        this.authUI?.presentFederatedSignInUI(activity) { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(

                        KEY_NAME_USER_ID,

                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        KEY_NAME_USER_ID,
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime,
                    )

                    this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

                    this.credentialsProvider.logins = this.getLogins()
                    CoroutineScope(Dispatchers.IO).launch {
                        try {
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
                                ),
                            )
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            callback(SignInResult.Failure(e))
                        }
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
        callback: (FederatedSignInResult) -> Unit,
    ) {
        this.authUI?.processFederatedSignInTokens(data) { result ->
            when (result) {
                is FederatedSignInResult.Success -> {
                    this@DefaultSudoUserClient.keyManager.deletePassword(

                        KEY_NAME_USER_ID,

                    )
                    this@DefaultSudoUserClient.keyManager.addPassword(
                        result.username.toByteArray(),
                        KEY_NAME_USER_ID,
                    )

                    this@DefaultSudoUserClient.storeTokens(
                        result.idToken,
                        result.accessToken,
                        result.refreshToken,
                        result.lifetime,
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
                                result.username,
                            ),
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
            SIGN_IN_PARAM_NAME_ANSWER to authInfo.encode(),
        )

        this.invokeSignInStatusObservers(SignInStatus.SIGNING_IN)

        try {
            val authenticationTokens = this.identityProvider.signIn(uid, parameters)

            this.storeTokens(
                authenticationTokens.idToken,
                authenticationTokens.accessToken,
                authenticationTokens.refreshToken,
                authenticationTokens.lifetime,
            )

            this.storeRefreshTokenLifetime(this.refreshTokenLifetime)

            this.credentialsProvider.logins = this.getLogins()
            this.credentialsProvider.refresh()

            return this.registerFederatedIdAndRefreshTokens(
                authenticationTokens.idToken,
                authenticationTokens.accessToken,
                authenticationTokens.refreshToken,
                authenticationTokens.lifetime,
            )
        } catch (e: SudoUserException) {
            this.invokeSignInStatusObservers(SignInStatus.NOT_SIGNED_IN)
            throw e
        }
    }

    override suspend fun refreshTokens(refreshToken: String): AuthenticationTokens {
        this.logger.info("Refreshing authentication tokens.")

        this.invokeSignInStatusObservers(SignInStatus.SIGNING_IN)

        try {
            val refreshTokenResult = identityProvider.refreshTokens(refreshToken)
            storeTokens(
                refreshTokenResult.idToken,
                refreshTokenResult.accessToken,
                refreshTokenResult.refreshToken,
                refreshTokenResult.lifetime,
            )

            this.credentialsProvider.logins = this.getLogins()
            this.credentialsProvider.refresh()

            this.invokeSignInStatusObservers(SignInStatus.SIGNED_IN)
            return AuthenticationTokens(
                refreshTokenResult.idToken,
                refreshTokenResult.accessToken,
                refreshTokenResult.refreshToken,
                refreshTokenResult.lifetime,
            )
        } catch (e: SudoUserException) {
            this.invokeSignInStatusObservers(SignInStatus.NOT_SIGNED_IN)
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
        val keyData = this.keyManager.getPublicKeyData(keyId) ?: throw KeyNotFoundException("Public key of generated key pair not found")

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

    @Synchronized
    override fun clearAuthTokens() {
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

        val refreshToken =
            this.getRefreshToken() ?: throw SudoUserException.NotSignedInException()

        try {
            identityProvider.signOut(refreshToken)
            this.clearAuthTokens()
        } catch (t: Throwable) {
            when (t) {
                is SudoUserException -> throw t
                else -> throw SudoUserException.FailedException(cause = t)
            }
        }
    }

    override suspend fun globalSignOut() {
        this.logger.info("Globally signing out user.")

        if (!this.isSignedIn()) {
            throw SudoUserException.NotSignedInException()
        }

        try {
            val response = this.apiClient.mutate<GlobalSignOutMutation, GlobalSignOutMutation.Data>(
                GlobalSignOutMutation.OPERATION_DOCUMENT,
                emptyMap(),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoUserException()
            }

            val result = response.data
            if (result != null) {
                this.clearAuthTokens()
                return
            } else {
                throw SudoUserException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (t: Throwable) {
            when (t) {
                is SudoUserException -> throw t
                is ApiException.ApiAuthException -> throw SudoUserException.NotAuthorizedException(cause = t)
                else -> throw SudoUserException.FailedException(cause = t)
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

    override fun registerSignInStatusObserver(id: String, observer: SignInStatusObserver) {
        this.signInStatusObservers[id] = observer
    }

    override fun deregisterSignInStatusObserver(id: String) {
        this.signInStatusObservers.remove(id)
    }

    override suspend fun resetUserData() {
        this.logger.info("Resetting user data.")

        if (!this.isSignedIn()) {
            throw SudoUserException.NotSignedInException()
        }

        try {
            val response = this.apiClient.mutate<ResetMutation, ResetMutation.Data>(
                ResetMutation.OPERATION_DOCUMENT,
                emptyMap(),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoUserException()
            }

            if (response.data?.reset?.success != true) {
                throw SudoUserException.FailedException("Mutation succeeded but success status was not true.")
            }
        } catch (t: Throwable) {
            when (t) {
                is SudoUserException -> throw t
                is ApiException.ApiAuthException -> throw SudoUserException.NotAuthorizedException(cause = t)

                else -> throw SudoUserException.FailedException(cause = t)
            }
        }
    }

    /**
     * Stores authentication tokens in the key store.
     *
     * @param idToken ID token.
     * @param accessToken access token.
     * @param refreshToken refresh token.
     * @param lifetime token lifetime in seconds.
     */
    @Synchronized
    private fun storeTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int,
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
            KEY_NAME_TOKEN_EXPIRY,
        )
    }

    @Synchronized
    private fun storeRefreshTokenLifetime(refreshTokenLifetime: Int) {
        this.keyManager.deletePassword(KEY_NAME_REFRESH_TOKEN_EXPIRY)
        this.keyManager.addPassword(
            "${refreshTokenLifetime * 24L * 60L * 60L * 1000L + Date().time}".toByteArray(),
            KEY_NAME_REFRESH_TOKEN_EXPIRY,
        )
    }

    private suspend fun registerFederatedIdAndRefreshTokens(
        idToken: String,
        accessToken: String,
        refreshToken: String,
        lifetime: Int,
    ): AuthenticationTokens {
        this.logger.info("Registering federated ID.")

        // If the identity ID is already in the ID token as a claim then no need to register
        // the federated identity again.
        val identityId = this.getUserClaim("custom:identityId")
        if (identityId != null) {
            this.invokeSignInStatusObservers(SignInStatus.SIGNED_IN)
            return AuthenticationTokens(idToken, accessToken, refreshToken, lifetime)
        }

        try {
            val input = RegisterFederatedIdInput(idToken)
            val response = this.apiClient.mutate<RegisterFederatedIdMutation, RegisterFederatedIdMutation.Data>(
                RegisterFederatedIdMutation.OPERATION_DOCUMENT,
                mapOf("input" to Optional.presentIfNotNull(input)),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoUserException()
            }

            val result = response.data?.registerFederatedId?.identityId
            if (result != null) {
                return refreshTokens(refreshToken)
            } else {
                throw SudoUserException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (t: Throwable) {
            when (t) {
                is SudoUserException -> throw t
                else -> throw SudoUserException.FailedException(cause = t)
            }
        }
    }

    /**
     * Construct the [OkHttpClient] configured with the certificate transparency checking interceptor.
     */
    private fun buildOkHttpClient(builder: OkHttpClient.Builder, context: Context, ctLogListUrl: String?): OkHttpClient.Builder {
        val url = ctLogListUrl ?: "https://www.gstatic.com/ct/log_list/v3/"
        this.logger.info("Using CT log list URL: $url")
        val interceptor = certificateTransparencyInterceptor {
            setLogListDataSource(
                LogListDataSourceFactory.createDataSource(
                    logListService = LogListDataSourceFactory.createLogListService(url),
                    diskCache = AndroidDiskCache(context),
                    now = {
                        // Currently there's an issue where the new version of CT library invalidates the
                        // cached log list if the log list timestamp is more than 24 hours old. This assumes
                        // Google's log list and our mirror is updated every 24 hours which is not guaranteed.
                        // We will override the definition of now to be 2 weeks in the past to be in
                        // sync with our update interval. This override only impacts the calculation of cache
                        // expiry in the CT library.
                        Instant.now().minus(14, ChronoUnit.DAYS)
                    },
                ),
            )
        }
        val okHttpClient = builder.apply {
            addInterceptor(ConvertClientErrorsInterceptor())

            // Certificate transparency checking
            addNetworkInterceptor(interceptor)
        }
        return okHttpClient
    }

    private fun invokeSignInStatusObservers(signInStatus: SignInStatus) {
        // Clone the current set of observers to allow for observers
        // to adjust the registered observers themselves (e.g. to
        // deregister themselves).
        val observers = this.signInStatusObservers.values.toList()
        observers.forEach { it.signInStatusChanged(signInStatus) }
    }
}
