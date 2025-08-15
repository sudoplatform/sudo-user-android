/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.http

import com.amplifyframework.api.graphql.GraphQLResponse
import com.google.gson.Gson
import com.sudoplatform.sudouser.exceptions.HTTP_STATUS_CODE_KEY
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import java.net.HttpURLConnection

/**
 * Convert any client errors so that they are not swallowed by the Amplify GraphQLOperation response handler.
 */
class ConvertClientErrorsInterceptor : Interceptor {
    private class ErrorFromHttpCode(
        private val httpCode: Int,
    ) {
        override fun toString(): String {
            val errors =
                mapOf(
                    "errors" to
                        listOf(
                            GraphQLResponse.Error(
                                "Error response received from server",
                                emptyList(),
                                emptyList(),
                                mapOf(HTTP_STATUS_CODE_KEY to this.httpCode),
                            ),
                        ),
                )
            return Gson().toJson(errors)
        }
    }

    override fun intercept(chain: Interceptor.Chain): okhttp3.Response {
        val response = chain.proceed(chain.request())
        if (response.isSuccessful) {
            return response
        }
        response.body.close()
        val newResponse: ResponseBody =
            ErrorFromHttpCode(response.code)
                .toString()
                .toResponseBody("application/json".toMediaTypeOrNull())

        return response
            .newBuilder()
            .body(newResponse)
            .code(HttpURLConnection.HTTP_OK)
            .build()
    }
}
