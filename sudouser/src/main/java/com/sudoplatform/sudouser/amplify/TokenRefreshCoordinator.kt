/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.amplify

import com.sudoplatform.sudouser.AuthenticationTokens
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.exceptions.SudoUserException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.cancellation.CancellationException

/**
 * Coordinates token refresh operations using a single-flight pattern.
 *
 * Multiple concurrent callers that detect a 401 will share the same refresh
 * operation rather than each launching their own. A cooldown window prevents
 * redundant refreshes when stale in-flight requests complete with 401 after
 * the token has already been refreshed.
 *
 * @param client the [SudoUserClient] used to obtain and refresh tokens
 */
class TokenRefreshCoordinator(
    private val client: SudoUserClient,
) {
    companion object {
        /** Duration in milliseconds after a successful refresh during which cached results are reused. */
        internal const val COOLDOWN_DURATION_MS = 5000L
    }

    /** Guards access to shared mutable state. */
    private val mutex = Mutex()

    /** The currently in-flight refresh operation, or null if none is active. */
    private var inFlightDeferred: CompletableDeferred<AuthenticationTokens>? = null

    /** Timestamp (epoch millis) when the last successful refresh completed. */
    private var lastRefreshTime: Long = 0L

    /** Cached result from the last successful refresh. */
    private var lastResult: AuthenticationTokens? = null

    /**
     * Perform a single-flight token refresh.
     *
     * Multiple concurrent callers will share the same refresh operation.
     * If called within the cooldown window after a successful refresh, returns
     * the cached result immediately.
     *
     * @return [AuthenticationTokens] from a successful refresh
     * @throws SudoUserException.NotAuthorizedException if the refresh token is revoked or invalid
     * @throws SudoUserException.NotSignedInException if no refresh token is available
     */
    suspend fun refresh(): AuthenticationTokens {
        // Sealed result from the mutex-protected decision block
        val decision =
            mutex.withLock {
                // Check cooldown: if we refreshed recently, return the cached result
                val cached = lastResult
                if (cached != null && (System.currentTimeMillis() - lastRefreshTime) < COOLDOWN_DURATION_MS) {
                    return@withLock RefreshDecision.UseCached(cached)
                }

                // If a refresh is already in-flight, share it
                val existing = inFlightDeferred
                if (existing != null) {
                    return@withLock RefreshDecision.AwaitExisting(existing)
                }

                // Start a new refresh flight
                val deferred = CompletableDeferred<AuthenticationTokens>()
                inFlightDeferred = deferred
                RefreshDecision.Initiate(deferred)
            }

        return when (decision) {
            is RefreshDecision.UseCached -> decision.tokens
            is RefreshDecision.AwaitExisting -> decision.deferred.await()
            is RefreshDecision.Initiate -> executeRefresh(decision.deferred)
        }
    }

    /**
     * Executes the actual token refresh. Only called by the initiator of a flight.
     */
    private suspend fun executeRefresh(deferred: CompletableDeferred<AuthenticationTokens>): AuthenticationTokens {
        try {
            val refreshToken =
                client.getRefreshToken()
                    ?: throw SudoUserException.NotSignedInException("No refresh token available")

            val tokens = client.refreshTokens(refreshToken)

            // Success: update cooldown state and complete the deferred for all waiters
            mutex.withLock {
                lastRefreshTime = System.currentTimeMillis()
                lastResult = tokens
                inFlightDeferred = null
            }
            deferred.complete(tokens)

            return tokens
        } catch (e: SudoUserException.NotAuthorizedException) {
            // Terminal error: clear in-flight state and propagate to all waiters
            mutex.withLock {
                inFlightDeferred = null
            }
            deferred.completeExceptionally(e)
            throw e
        } catch (e: CancellationException) {
            // Cancellation error: clear in-flight state and propagate to all waiters
            mutex.withLock { inFlightDeferred = null }
            deferred.cancel()
            throw e
        } catch (e: Exception) {
            // Other errors: clear in-flight state and propagate to all waiters
            mutex.withLock {
                inFlightDeferred = null
            }
            deferred.completeExceptionally(e)
            throw e
        }
    }

    /** Internal sealed class representing the decision made under the mutex. */
    private sealed class RefreshDecision {
        data class UseCached(
            val tokens: AuthenticationTokens,
        ) : RefreshDecision()

        data class AwaitExisting(
            val deferred: CompletableDeferred<AuthenticationTokens>,
        ) : RefreshDecision()

        data class Initiate(
            val deferred: CompletableDeferred<AuthenticationTokens>,
        ) : RefreshDecision()
    }
}
