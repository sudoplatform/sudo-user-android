package com.sudoplatform.sudouser.exceptions

import java.lang.Exception

sealed class RegisterException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    companion object {

        fun toApiException(e: Exception): ApiException? {
            return when (e) {
                is AlreadyRegisteredException -> ApiException(ApiErrorCode.ALREADY_REGISTERED, e.localizedMessage)
                is NotAuthorizedException -> ApiException(ApiErrorCode.NOT_AUTHORIZED, e.localizedMessage)
                is InvalidInputException -> ApiException(ApiErrorCode.INVALID_INPUT, e.localizedMessage)
                is ServerException -> ApiException(ApiErrorCode.SERVER_ERROR, e.localizedMessage)
                is GraphQLException -> ApiException(ApiErrorCode.GRAPHQL_ERROR, e.localizedMessage)
                is IdentityNotConfirmedException -> ApiException(ApiErrorCode.IDENTITY_NOT_CONFIRMED, e.localizedMessage)
                is FailedException -> ApiException(ApiErrorCode.FATAL_ERROR, e.localizedMessage)
                else -> null
            }
        }
    }

    class IllegalStateException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class AlreadyRegisteredException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class InvalidInputException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class ServerException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class IdentityNotConfirmedException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        RegisterException(message = message, cause = cause)

}


