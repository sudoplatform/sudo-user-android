/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser.extensions

import com.amplifyframework.api.graphql.GsonResponseAdapters
import com.amplifyframework.core.model.query.predicate.GsonPredicateAdapters
import com.amplifyframework.core.model.temporal.GsonTemporalAdapters
import com.amplifyframework.core.model.types.GsonJavaTypeAdapters
import com.amplifyframework.datastore.appsync.ModelWithMetadataAdapter
import com.amplifyframework.datastore.appsync.SerializedCustomTypeAdapter
import com.amplifyframework.datastore.appsync.SerializedModelAdapter
import com.apollographql.apollo.api.Optional
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import java.lang.reflect.Type

/**
 * Based on the GsonFactory in the AmplifyFramework. Includes all builder adjustments from
 * that factory plus one of our own.
 */
class GsonFactoryExt {
    companion object {
        @Volatile
        private var gson: Gson? = null

        /**
         * Obtains a singleton instance of [Gson], configured with adapters sufficient
         * to serialize and deserialize all types the API plugin will encounter.
         * @return A configured Gson instance.
         */
        @Synchronized
        fun instance(): Gson =
            gson ?: synchronized(this) {
                gson ?: create().also { gson = it }
            }

        private fun create(): Gson {
            val builder = GsonBuilder()
            GsonTemporalAdapters.register(builder)
            GsonJavaTypeAdapters.register(builder)
            GsonPredicateAdapters.register(builder)
            GsonResponseAdapters.register(builder)
            ModelWithMetadataAdapter.register(builder)
            SerializedModelAdapter.register(builder)
            SerializedCustomTypeAdapter.register(builder)
            builder.registerTypeAdapter(Optional::class.java, JsonOptionalSerializer<Any>())
            return builder.create()
        }
    }
}

class JsonOptionalSerializer<V> : JsonSerializer<Optional<V>> {
    override fun serialize(
        src: Optional<V>?,
        typeOfSrc: Type?,
        context: JsonSerializationContext?,
    ): JsonElement {
        if (context == null) {
            throw IllegalArgumentException("Provided serialization context is null")
        }
        val result = src?.getOrNull()
        return if (result == null) {
            JsonNull.INSTANCE
        } else {
            context.serialize(result)
        }
    }
}
