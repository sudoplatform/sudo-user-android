/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.amplify

import com.amplifyframework.api.ApiCategory
import com.amplifyframework.api.ApiException
import com.amplifyframework.api.aws.GsonVariablesSerializer
import com.amplifyframework.api.graphql.GraphQLOperation
import com.amplifyframework.api.graphql.GraphQLResponse
import com.amplifyframework.api.graphql.SimpleGraphQLRequest
import com.amplifyframework.core.Action
import com.amplifyframework.core.Consumer
import com.apollographql.apollo3.api.Mutation
import com.apollographql.apollo3.api.Optional
import com.apollographql.apollo3.api.Query
import com.apollographql.apollo3.api.Subscription
import com.sudoplatform.sudouser.extensions.GsonFactoryExt
import com.sudoplatform.sudouser.extensions.mutate
import com.sudoplatform.sudouser.extensions.query
import com.sudoplatform.sudouser.extensions.subscribe

/**
 * Wrapper class around the apiCategory to maintain concept cleanliness.
 */
class GraphQLClient(var apiCategory: ApiCategory) {
    suspend inline fun <reified T : Mutation<D>, reified D : Mutation.Data> mutate(
        document: String,
        variables: Map<String, Any?>,
    ): GraphQLResponse<D> {
        val mutation = SimpleGraphQLRequest<D>(
            document,
            variables.mapValues { if (it.value is Optional<*>) (it.value as Optional<*>).getOrNull() else it.value },
            D::class.java,
            GsonVariablesSerializer(),
        )

        val response =
            mutation.mutate(this.apiCategory, {
                val constructor = T::class.constructors.first()
                constructor.call(*(variables.map { it.value }).toTypedArray())
            }, null)

        return response
    }

    suspend inline fun <reified T : Query<D>, reified D : Query.Data> query(
        document: String,
        variables: Map<String, Any?>,
    ): GraphQLResponse<D> {
        val query = SimpleGraphQLRequest<D>(
            document,
            variables.mapValues { if (it.value is Optional<*>) (it.value as Optional<*>).getOrNull() else it.value },
            D::class.java,
            GsonVariablesSerializer(),
        )

        val response =
            query.query(this.apiCategory, {
                val constructor = T::class.constructors.first()
                constructor.call(*(variables.map { it.value }).toTypedArray())
            }, GsonVariablesSerializer(GsonFactoryExt.instance()))

        return response
    }

    inline fun <reified T : Subscription<D>, reified D : Subscription.Data> subscribe(
        document: String,
        variables: Map<String, Any?>,
        onSubscriptionEstablished: Consumer<GraphQLResponse<D>>,
        onSubscription: Consumer<GraphQLResponse<D>>,
        onSubscriptionCompleted: Action,
        onFailure: Consumer<ApiException>,
    ): GraphQLOperation<D>? {
        val subscriber = SimpleGraphQLRequest<D>(
            document,
            variables.mapValues { if (it.value is Optional<*>) (it.value as Optional<*>).getOrNull() else it.value },
            D::class.java,
            GsonVariablesSerializer(),
        )

        val response =
            subscriber.subscribe(
                this.apiCategory,
                {
                    val constructor = T::class.constructors.first()
                    constructor.call(*(variables.map { it.value }).toTypedArray())
                },
                onSubscriptionEstablished,
                onSubscription,
                onSubscriptionCompleted,
                onFailure,
                null,
            )

        return response
    }
}
