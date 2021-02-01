package com.sudoplatform.sudouser.exceptions

import java.lang.Exception

sealed class RegisterException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

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


