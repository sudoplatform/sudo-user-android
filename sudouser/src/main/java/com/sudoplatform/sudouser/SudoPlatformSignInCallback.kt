/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

/**
 * Callback interface for handling authentication when the user is not signed in.
 *
 * Implement this interface to provide custom sign-in logic when operations are attempted
 * while the user is not authenticated.
 */
interface SudoPlatformSignInCallback {
    /**
     * Called when a sudo platform operation is attempted while the user is not signed in.
     *
     * Implementations should perform the necessary sign-in logic and throw an exception
     * if sign-in fails or is cancelled.
     *
     * @throws Exception Any error that occurs during sign-in. The exception will be propagated
     *   to the caller and the original operation will not be executed.
     */
    suspend fun signIn()
}
