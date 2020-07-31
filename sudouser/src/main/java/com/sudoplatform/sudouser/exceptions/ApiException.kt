/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.exceptions

enum class ApiErrorCode {
    /**
     * Identity was created but not confirmed because validation failed.
     */
    IDENTITY_NOT_CONFIRMED,

    /**
     * Invalid configuration parameters were passed.
     */
    INVALID_CONFIG,

    /**
     * Invalid input parameters were passed.
     */
    INVALID_INPUT,

    /**
     * User is not authorized to perform the operation requested.
     */
    NOT_AUTHORIZED,

    /**
     * Client is not registered.
     */
    NOT_REGISTERED,

    /**
     * Client is not signed in.
     */
    NOT_SIGNED_IN,

    /**
     * Client is already registered. This could result from calling one of the register API when the client was already
     * registered.
     */
    ALREADY_REGISTERED,

    /**
     * An internal server error cause the API call to fail. The error is
     * possibly transient and retrying at a later time may cause the call
     * to complete successfully.
     */
    SERVER_ERROR,

    /**
     * GraphQL endpoint returned an error.
     */
    GRAPHQL_ERROR,

    /**
     * Unexpected error encountered. This could be a result of client or backend bug and unlikely to be user
     * recoverable.
     */
    FATAL_ERROR
}

/**
 * [SudoUserClient] exception with a specific error code and message.
 *
 * @param code error code.
 * @param message error message.
 * @constructor Creates an API exception with the specified code and message.
 */
data class ApiException(val code: ApiErrorCode, override val message: String): Exception(message)
