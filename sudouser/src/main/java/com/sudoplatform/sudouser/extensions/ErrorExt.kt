package com.sudoplatform.sudouser.extensions

import com.apollographql.apollo.api.Error
import com.sudoplatform.sudouser.exceptions.*

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

fun Error.toRegistrationException() : RegisterException  {
    return if (this.customAttributes()[GRAPHQL_ERROR_TYPE] == GRAPHQL_ERROR_SERVER_ERROR) {
        RegisterException.ServerException("$this")
    }
    else {
        RegisterException.GraphQLException("$this")
    }
}

