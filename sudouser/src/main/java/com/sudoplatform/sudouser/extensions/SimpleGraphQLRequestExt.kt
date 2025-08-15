/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.extensions

import com.amplifyframework.api.ApiCategory
import com.amplifyframework.api.ApiException
import com.amplifyframework.api.aws.GsonVariablesSerializer
import com.amplifyframework.api.graphql.GraphQLOperation
import com.amplifyframework.api.graphql.GraphQLRequest
import com.amplifyframework.api.graphql.GraphQLResponse
import com.amplifyframework.api.graphql.SimpleGraphQLRequest
import com.amplifyframework.core.Action
import com.amplifyframework.core.Consumer
import com.apollographql.apollo.api.Mutation
import com.apollographql.apollo.api.Query
import com.apollographql.apollo.api.Subscription
import com.apollographql.apollo.api.json.BufferedSourceJsonReader
import com.apollographql.apollo.api.parseData
import okio.Buffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

//
// Extensions to the SimpleGraphQLRequest to manage coroutines and simplify asynchronous invocation of the mutate and query methods.
//

/**
 * Manage callback for mutate given an apiCategory.
 */
suspend fun <T : Mutation<D>, D : Mutation.Data> SimpleGraphQLRequest<D>.mutate(
    apiCategory: ApiCategory,
    parserBuilder: () -> T,
    variablesSerializer: GraphQLRequest.VariablesSerializer? = null,
): GraphQLResponse<D> =
    suspendCoroutine { cont ->
        val actualMutation =
            SimpleGraphQLRequest<String>(
                this.query,
                this.variables,
                String::class.java,
                variablesSerializer ?: GsonVariablesSerializer(GsonFactoryExt.instance()),
            )

        apiCategory.mutate(
            actualMutation,
            {
                if (it.hasData()) {
                    val reader = BufferedSourceJsonReader(Buffer().write((it.data as String).toByteArray()))
                    val result = GraphQLResponse<D>(parserBuilder().parseData(reader), it.errors)
                    cont.resume(result)
                } else {
                    val result = GraphQLResponse<D>(null, it.errors)
                    cont.resume(result)
                }
            },
            {
                cont.resumeWithException(it)
            },
        )
    }

/**
 * Manage callback for query given an apiCategory.
 */
suspend fun <T : Query<D>, D : Query.Data> SimpleGraphQLRequest<D>.query(
    apiCategory: ApiCategory,
    parserBuilder: () -> T,
    variablesSerializer: GraphQLRequest.VariablesSerializer? = null,
): GraphQLResponse<D> =
    suspendCoroutine { cont ->
        val actualQuery =
            SimpleGraphQLRequest<String>(
                this.query,
                this.variables,
                String::class.java,
                variablesSerializer ?: GsonVariablesSerializer(GsonFactoryExt.instance()),
            )

        apiCategory.query(
            actualQuery,
            {
                if (it.hasData()) {
                    val reader = BufferedSourceJsonReader(Buffer().write((it.data as String).toByteArray()))
                    val result = GraphQLResponse<D>(parserBuilder().parseData(reader), it.errors)
                    cont.resume(result)
                } else {
                    val result = GraphQLResponse<D>(null, it.errors)
                    cont.resume(result)
                }
            },
            {
                cont.resumeWithException(it)
            },
        )
    }

internal class OnSubscriptionEstablishedWrapper<D : Subscription.Data>(
    private val consumer: Consumer<GraphQLResponse<D>>,
) : Consumer<String> {
    override fun accept(value: String) {
        this.consumer.accept(GraphQLResponse<D>(null, null))
    }
}

internal class FactoryWrapper : GraphQLResponse.Factory {
    override fun <R : Any?> buildResponse(
        request: GraphQLRequest<R>?,
        apiResponseJson: String?,
    ): GraphQLResponse<R> =
        throw ApiException(
            "FactoryWrapper.buildResponse unexpectedly called",
            "Reconsider the way in which this GraphQLOperation is being used.",
        )
}

internal class GraphQLOperationWrapper<T>(
    private val operation: GraphQLOperation<String>,
    graphQLRequest: GraphQLRequest<T>,
) : GraphQLOperation<T>(graphQLRequest, FactoryWrapper()) {
    override fun start() {
        operation.start()
    }

    override fun cancel() {
        operation.cancel()
    }
}

fun <T : Subscription<D>, D : Subscription.Data> SimpleGraphQLRequest<D>.subscribe(
    apiCategory: ApiCategory,
    parserBuilder: () -> T,
    onSubscriptionEstablished: Consumer<GraphQLResponse<D>>,
    onSubscription: Consumer<GraphQLResponse<D>>,
    onSubscriptionCompleted: Action,
    onFailure: Consumer<ApiException>,
    variablesSerializer: GraphQLRequest.VariablesSerializer? = null,
): GraphQLOperation<D>? {
    val actualSubscription =
        SimpleGraphQLRequest<String>(
            this.query,
            this.variables,
            String::class.java,
            variablesSerializer ?: GsonVariablesSerializer(GsonFactoryExt.instance()),
        )

    val actualOnSubscriptionEstablished = OnSubscriptionEstablishedWrapper(onSubscriptionEstablished)

    val operation =
        apiCategory.subscribe(
            actualSubscription,
            actualOnSubscriptionEstablished,
            {
                if (it.hasData()) {
                    val reader = BufferedSourceJsonReader(Buffer().write((it.data as String).toByteArray()))
                    val result = GraphQLResponse<D>(parserBuilder().parseData(reader), it.errors)
                    onSubscription.accept(result)
                } else {
                    val result = GraphQLResponse<D>(null, it.errors)
                    onSubscription.accept(result)
                }
            },
            onFailure,
            onSubscriptionCompleted,
        )
    return if (operation != null) GraphQLOperationWrapper(operation, this) else null
}
