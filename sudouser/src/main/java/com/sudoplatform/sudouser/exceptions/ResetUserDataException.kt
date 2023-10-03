/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.exceptions

sealed class ResetUserDataException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    /**
     * Internal server error has occurred. This could be due to an outage or an unexpected fatal
     * error in the backend.
     */
    class ServerException(message: String? = null, cause: Throwable? = null) :
        ResetUserDataException(message = message, cause = cause)

    /**
     * Unexpected GraphQL error was returned. This could be due to a bug in the backend code.
     */
    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        ResetUserDataException(message = message, cause = cause)

    /**
     * The user was not authorized to perform the reset user data operation.
     */
    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        ResetUserDataException(message = message, cause = cause)

    /**
     * Unexpected error has occurred.
     */
    class FailedException(message: String? = null, cause: Throwable? = null) :
        ResetUserDataException(message = message, cause = cause)

}
