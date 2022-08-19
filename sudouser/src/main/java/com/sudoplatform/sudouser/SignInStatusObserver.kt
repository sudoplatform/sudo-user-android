/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

/**
 * List of possible values for sign in status.
 */
enum class SignInStatus {
    SIGNING_IN,
    SIGNED_IN,
    NOT_SIGNED_IN
}

/**
 * Protocol for sign in status observer. If you wish to observe the the changes to the progress
 * of sign in or refresh token operation then you must implement this protocol.
 */
interface SignInStatusObserver {

    /**
     * Notifies the changes to the sign in or refresh token operation.
     *
     * @param status new sign in status.
     */
    fun signInStatusChanged(status: SignInStatus)
}
