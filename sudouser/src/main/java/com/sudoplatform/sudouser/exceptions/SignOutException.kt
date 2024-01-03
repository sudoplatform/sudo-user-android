/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.exceptions

sealed class SignOutException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        SignOutException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        SignOutException(message = message, cause = cause)
}
