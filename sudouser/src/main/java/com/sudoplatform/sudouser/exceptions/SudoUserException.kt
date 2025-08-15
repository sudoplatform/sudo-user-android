package com.sudoplatform.sudouser.exceptions

import com.amplifyframework.api.graphql.GraphQLResponse
import java.net.HttpURLConnection

const val HTTP_STATUS_CODE_KEY = "httpStatus"
const val GRAPHQL_ERROR_TYPE = "errorType"
const val GRAPHQL_ERROR_SERVICE_ERROR = "sudoplatform.ServiceError"

open class SudoUserException(
    message: String? = null,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    companion object {
        /**
         * Convert from a GraphQL [Error] into a custom exception of type [SudoUserException]
         */
        fun GraphQLResponse.Error.toSudoUserException(): SudoUserException {
            val httpStatusCode = this.extensions?.get(HTTP_STATUS_CODE_KEY) as Int?
            val errorType = this.extensions?.get(GRAPHQL_ERROR_TYPE)

            return if (httpStatusCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
                NotAuthorizedException(this.message)
            } else if (httpStatusCode != null && httpStatusCode >= HttpURLConnection.HTTP_INTERNAL_ERROR) {
                FailedException(this.message)
            } else if (errorType == GRAPHQL_ERROR_SERVICE_ERROR) {
                ServerException("$this")
            } else {
                GraphQLException("$this")
            }
        }
    }

    class NotAuthorizedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class NotRegisteredException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class NotSignedInException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class ServerException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class GraphQLException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class IllegalStateException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class AlreadyRegisteredException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class InvalidInputException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class IdentityNotConfirmedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)

    class FailedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoUserException(message = message, cause = cause)
}
