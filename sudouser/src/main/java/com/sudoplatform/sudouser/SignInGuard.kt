/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.lang.ref.WeakReference

/**
 * A reusable helper class that provides sign-in checking functionality for Sudo Platform libraries.
 *
 * This class encapsulates the logic for checking if a user is signed in and invoking a callback
 * to handle sign-in when needed. It is designed to be used by any SudoPlatform Client
 * to provide consistent sign-in callback behavior across the platform.
 */
class SignInGuard(
    private val userClient: SudoUserClient,
    callback: SudoPlatformSignInCallback? = null,
) {
    private val mutex = Mutex()
    private var callbackRef: WeakReference<SudoPlatformSignInCallback>? =
        callback?.let { WeakReference(it) }

    /**
     * Sets the callback to be invoked when sign-in is required.
     *
     * @param callback A callback implementing [SudoPlatformSignInCallback], or null to disable sign-in checking.
     */
    suspend fun setCallback(callback: SudoPlatformSignInCallback?) {
        mutex.withLock {
            callbackRef = callback?.let { WeakReference(it) }
        }
    }

    /**
     * Checks if the user is signed in and invokes the callback if needed.
     *
     * This method performs the following:
     * 1. If no callback is set, returns immediately
     * 2. Checks if the user is signed in using [SudoUserClient.isSignedIn]
     * 3. If not signed in, invokes the callback's [SudoPlatformSignInCallback.signIn] method
     *
     * @throws Exception Any error thrown by the callback's signIn() method, or errors from checking sign-in status.
     */
    suspend fun ensureSignedIn() {
        // Get callback in thread-safe manner
        val callback =
            mutex.withLock {
                callbackRef?.get()
            } ?: return // No callback configured - skip check (backward compatible behavior)

        // Check if user is signed in
        val isSignedIn: Boolean =
            try {
                userClient.isSignedIn()
            } catch (e: Exception) {
                // If we can't determine sign-in status, assume not signed in
                false
            }

        // If not signed in, invoke callback
        if (!isSignedIn) {
            callback.signIn()
        }
    }
}
