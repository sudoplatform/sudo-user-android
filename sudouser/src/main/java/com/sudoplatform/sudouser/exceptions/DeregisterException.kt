package com.sudoplatform.sudouser.exceptions

import java.lang.Exception

sealed class DeregisterException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    companion object {

        fun toApiException(e: Exception): ApiException? {
            return when (e) {
                is NotAuthorizedException -> ApiException(ApiErrorCode.NOT_AUTHORIZED, e.localizedMessage)
                is FailedException -> ApiException(ApiErrorCode.FATAL_ERROR, e.localizedMessage)
                else -> null
            }
        }

    }

    class ServerException(message: String? = null, cause: Throwable? = null) :
        DeregisterException(message = message, cause = cause)

    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        DeregisterException(message = message, cause = cause)

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        DeregisterException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        DeregisterException(message = message, cause = cause)

}


