package com.sudoplatform.sudouser.exceptions

import java.lang.Exception

sealed class GlobalSignOutException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {

    class ServerException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

    class FailedException(message: String? = null, cause: Throwable? = null) :
        GlobalSignOutException(message = message, cause = cause)

}


