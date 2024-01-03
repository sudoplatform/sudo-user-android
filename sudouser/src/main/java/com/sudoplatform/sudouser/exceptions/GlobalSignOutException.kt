/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.exceptions

sealed class GlobalSignOutException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {

    class ServerException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)
}
