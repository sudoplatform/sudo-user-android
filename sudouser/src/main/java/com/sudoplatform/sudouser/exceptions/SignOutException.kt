package com.sudoplatform.sudouser.exceptions

sealed class SignOutException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    companion object {

        fun toApiException(e: Exception): ApiException? {
            return when (e) {
                is NotAuthorizedException -> ApiException(ApiErrorCode.NOT_AUTHORIZED, e.localizedMessage)
                is FailedException -> ApiException(ApiErrorCode.FATAL_ERROR, e.localizedMessage)
                else -> null
            }
        }

    }

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        SignOutException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        SignOutException(message = message, cause = cause)

}


