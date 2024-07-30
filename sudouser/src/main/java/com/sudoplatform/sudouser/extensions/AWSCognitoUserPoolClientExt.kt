/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.extensions

import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler
import com.amazonaws.services.cognitoidentityprovider.model.SignUpResult
import com.sudoplatform.sudouser.CognitoUserPoolIdentityProvider
import com.sudoplatform.sudouser.exceptions.SudoUserException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal suspend fun CognitoUserPool.signUp(uid: String, password: String, cognitoAttributes: CognitoUserAttributes, parameters: Map<String, String>) = suspendCoroutine<String> { cont ->

    signUp(
        uid,
        password,
        cognitoAttributes,
        parameters,
        object : SignUpHandler {

            override fun onSuccess(
                user: CognitoUser?,
                signUpResult: SignUpResult,
            ) {
                if (user?.userId != null) {
                    if (signUpResult.isUserConfirmed) {
                        cont.resume(user.userId)
                    } else {
                        cont.resumeWithException(
                            SudoUserException.IdentityNotConfirmedException(
                                "Identity was created but is not confirmed.",
                            ),
                        )
                    }
                } else {
                    cont.resumeWithException(SudoUserException.IllegalStateException())
                }
            }

            override fun onFailure(exception: Exception?) {
                if (exception != null) {
                    val message = exception.message
                    if (message != null) {
                        if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_SERVICE_ERROR)) {
                            cont.resumeWithException(SudoUserException.ServerException(message))
                        } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_MISSING_REQUIRED_INPUT) ||
                            message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_DECODING_ERROR)
                        ) {
                            cont.resumeWithException(SudoUserException.InvalidInputException(message))
                        } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_VALIDATION_FAILED) ||
                            message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_TEST_REG_CHECK_FAILED) ||
                            message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_CHALLENGE_TYPE_NOT_SUPPORTED)
                        ) {
                            cont.resumeWithException(SudoUserException.NotAuthorizedException(message))
                        } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_ALREADY_REGISTERED)) {
                            cont.resumeWithException(SudoUserException.AlreadyRegisteredException(message))
                        } else {
                            cont.resumeWithException(SudoUserException.FailedException(message))
                        }
                    } else {
                        cont.resumeWithException(SudoUserException.FailedException(cause = exception))
                    }
                } else {
                    cont.resumeWithException(SudoUserException.FailedException("Expected failure detail not found."))
                }
            }
        },
    )
}
