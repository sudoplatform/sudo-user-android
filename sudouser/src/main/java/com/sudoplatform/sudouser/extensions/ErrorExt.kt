/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.extensions

import com.apollographql.apollo.api.Error
import com.sudoplatform.sudouser.exceptions.DeregisterException
import com.sudoplatform.sudouser.exceptions.GlobalSignOutException
import com.sudoplatform.sudouser.exceptions.RegisterException

private const val GRAPHQL_ERROR_TYPE = "errorType"
private const val GRAPHQL_ERROR_SERVER_ERROR = "sudoplatform.identity.ServerError"

fun Error.toDeregisterException() : DeregisterException  {
    return if (this.customAttributes()[GRAPHQL_ERROR_TYPE] == GRAPHQL_ERROR_SERVER_ERROR) {
        DeregisterException.ServerException("$this")
    }
    else {
        DeregisterException.GraphQLException("$this")
    }
}

fun Error.toGlobalSignOutException() : GlobalSignOutException  {
    return if (this.customAttributes()[GRAPHQL_ERROR_TYPE] == GRAPHQL_ERROR_SERVER_ERROR) {
        GlobalSignOutException.ServerException("$this")
    }
    else {
        GlobalSignOutException.GraphQLException("$this")
    }
}

fun Error.toRegistrationException() : RegisterException  {
    return if (this.customAttributes()[GRAPHQL_ERROR_TYPE] == GRAPHQL_ERROR_SERVER_ERROR) {
        RegisterException.ServerException("$this")
    }
    else {
        RegisterException.GraphQLException("$this")
    }
}
