/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.extensions

import com.apollographql.apollo.GraphQLCall
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal suspend fun <T> GraphQLCall<T>.enqueue(): Response<T> = suspendCoroutine { cont ->
    enqueue(object : GraphQLCall.Callback<T>() {
        override fun onResponse(response: Response<T>) {
            cont.resume(response)
        }
        override fun onFailure(e: ApolloException) {
            cont.resumeWithException(e)
        }
    })
}
