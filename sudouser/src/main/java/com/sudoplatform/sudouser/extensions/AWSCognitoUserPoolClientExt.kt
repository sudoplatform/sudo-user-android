package com.sudoplatform.sudouser.extensions

import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler
import com.amazonaws.services.cognitoidentityprovider.model.SignUpResult
import com.sudoplatform.sudouser.CognitoUserPoolIdentityProvider
import com.sudoplatform.sudouser.exceptions.ApiErrorCode
import com.sudoplatform.sudouser.exceptions.RegisterException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal suspend fun CognitoUserPool.signUp(uid: String, password: String, cognitoAttributes: CognitoUserAttributes, parameters: Map<String, String>) = suspendCoroutine<String> { cont ->

    signUp(uid, password, cognitoAttributes, parameters,
        object : SignUpHandler {

            override fun onSuccess(
                user: CognitoUser?,
                signUpResult: SignUpResult
            ) {
                if (user?.userId != null) {
                    if (signUpResult.isUserConfirmed) {
                        cont.resume(user.userId)
                    } else {
                        cont.resumeWithException(
                            RegisterException.IdentityNotConfirmedException(
                                "Identity was created but is not confirmed."
                            )
                        )
                    }
                } else {
                    cont.resumeWithException(RegisterException.IllegalStateException())
                }
            }

            override fun onFailure(exception: Exception?) {
                if (exception != null) {
                    val message = exception.message
                    if (message != null) {
                        val errorCode = getErrorCode(message)
                        if (errorCode != null) {
                            when {
                                errorCode === ApiErrorCode.NOT_AUTHORIZED -> {
                                    cont.resumeWithException(RegisterException.NotAuthorizedException(message))
                                }
                                errorCode === ApiErrorCode.INVALID_INPUT -> {
                                    cont.resumeWithException(RegisterException.InvalidInputException(message))
                                }
                                errorCode === ApiErrorCode.SERVER_ERROR -> {
                                    cont.resumeWithException(RegisterException.ServerException(message))
                                }
                            }
                        } else {
                            cont.resumeWithException(RegisterException.FailedException(cause = exception))
                        }
                    } else {
                        cont.resumeWithException(RegisterException.FailedException(cause = exception))
                    }
                } else {
                    cont.resumeWithException(RegisterException.FailedException("Expected failure detail not found."))
                }
            }

            private fun getErrorCode(message: String): ApiErrorCode? {
                if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_SERVICE_ERROR)) {
                    return ApiErrorCode.SERVER_ERROR
                } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_MISSING_REQUIRED_INPUT)
                    || message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_DECODING_ERROR)) {
                    return ApiErrorCode.INVALID_INPUT
                } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_SAFETY_NET_CHECK_FAILED)
                    || message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_VALIDATION_FAILED)
                    || message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_TEST_REG_CHECK_FAILED)
                    || message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_CHALLENGE_TYPE_NOT_SUPPORTED)) {
                    return ApiErrorCode.NOT_AUTHORIZED
                }
                return null
            }
        }
    )
}
