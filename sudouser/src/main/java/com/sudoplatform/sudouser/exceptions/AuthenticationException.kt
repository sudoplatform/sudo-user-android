package com.sudoplatform.sudouser.exceptions

sealed class AuthenticationException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    companion object {

        fun toApiException(e: Exception): ApiException? {
            return when (e) {
                is NotAuthorizedException -> ApiException(ApiErrorCode.NOT_AUTHORIZED, e.localizedMessage)
                is FailedException -> ApiException(ApiErrorCode.FATAL_ERROR, e.localizedMessage)
                is NotRegisteredException -> ApiException(ApiErrorCode.NOT_REGISTERED, e.localizedMessage)
                else -> null
            }
        }
    }

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        AuthenticationException(message = message, cause = cause)

    class NotRegisteredException(message: String? = null, cause: Throwable? = null) :
        AuthenticationException(message = message, cause = cause)

    class NotSignedInException(message: String? = null, cause: Throwable? = null) :
        AuthenticationException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        AuthenticationException(message = message, cause = cause)

}


