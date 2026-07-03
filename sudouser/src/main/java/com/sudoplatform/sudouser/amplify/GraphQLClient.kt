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
import com.apollographql.apollo.api.Mutation
import com.apollographql.apollo.api.Optional
import com.apollographql.apollo.api.Query
import com.apollographql.apollo.api.Subscription
import com.sudoplatform.sudouser.exceptions.HTTP_STATUS_CODE_KEY
import com.sudoplatform.sudouser.extensions.GsonFactoryExt
import com.sudoplatform.sudouser.extensions.mutate
import com.sudoplatform.sudouser.extensions.query
import com.sudoplatform.sudouser.extensions.subscribe

/**
 * Wrapper class around the apiCategory to maintain concept cleanliness.
 */
class GraphQLClient(
    var apiCategory: ApiCategory,
    var tokenRefreshCoordinator: TokenRefreshCoordinator? = null,
) {
    suspend inline fun <reified T : Mutation<D>, reified D : Mutation.Data> mutate(
        document: String,
        variables: Map<String, Any?>,
    ): GraphQLResponse<D> {
        val mutation =
            SimpleGraphQLRequest<D>(
                document,
                variables.mapValues { if (it.value is Optional<*>) (it.value as Optional<*>).getOrNull() else it.value },
                D::class.java,
                GsonVariablesSerializer(GsonFactoryExt.instance()),
            )

        val response =
            mutation.mutate(this.apiCategory, {
                val constructor = T::class.constructors.first()
                constructor.call(*(variables.map { it.value }).toTypedArray())
            }, GsonVariablesSerializer(GsonFactoryExt.instance()))

        // Check for 401 errors indicating token rejection
        val coordinator = this.tokenRefreshCoordinator
        if (coordinator != null && response.errors?.any { it.extensions?.get(HTTP_STATUS_CODE_KEY) == 401 } == true) {
            // Attempt reactive token refresh (throws NotAuthorizedException if terminal)
            coordinator.refresh()

            // Retry the operation exactly once with the new token
            val retryResponse =
                mutation.mutate(this.apiCategory, {
                    val constructor = T::class.constructors.first()
                    constructor.call(*(variables.map { it.value }).toTypedArray())
                }, GsonVariablesSerializer(GsonFactoryExt.instance()))

            return retryResponse
        }

        return response
    }

    suspend inline fun <reified T : Query<D>, reified D : Query.Data> query(
        document: String,
        variables: Map<String, Any?>,
    ): GraphQLResponse<D> {
        val query =
            SimpleGraphQLRequest<D>(
                document,
                variables.mapValues { if (it.value is Optional<*>) (it.value as Optional<*>).getOrNull() else it.value },
                D::class.java,
                GsonVariablesSerializer(GsonFactoryExt.instance()),
            )

        val response =
            query.query(this.apiCategory, {
                val constructor = T::class.constructors.first()
                constructor.call(*(variables.map { it.value }).toTypedArray())
            }, GsonVariablesSerializer(GsonFactoryExt.instance()))

        // Check for 401 errors indicating token rejection
        val coordinator = this.tokenRefreshCoordinator
        if (coordinator != null && response.errors?.any { it.extensions?.get(HTTP_STATUS_CODE_KEY) == 401 } == true) {
            // Attempt reactive token refresh (throws NotAuthorizedException if terminal)
            coordinator.refresh()

            // Retry the operation exactly once with the new token
            val retryResponse =
                query.query(this.apiCategory, {
                    val constructor = T::class.constructors.first()
                    constructor.call(*(variables.map { it.value }).toTypedArray())
                }, GsonVariablesSerializer(GsonFactoryExt.instance()))

            return retryResponse
        }

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
        val subscriber =
            SimpleGraphQLRequest<D>(
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
