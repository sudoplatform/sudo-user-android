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
import com.google.gson.TypeAdapter
import com.google.gson.TypeAdapterFactory
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter

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

            builder.registerTypeAdapterFactory(
                JsonOptionalTypeAdapterFactory(),
            )
            return builder.create()
        }
    }
}

class JsonOptionalTypeAdapterFactory : TypeAdapterFactory {
    override fun <T> create(
        gson: Gson,
        type: TypeToken<T>,
    ): TypeAdapter<T>? {
        if (type.rawType != Optional::class.java) return null

        @Suppress("UNCHECKED_CAST")
        return JsonNullableOptionalTypeAdapter<Any>(gson) as TypeAdapter<T>
    }
}

class JsonNullableOptionalTypeAdapter<V>(
    private val gson: Gson,
) : TypeAdapter<Optional<V>>() {
    override fun write(
        out: JsonWriter,
        value: Optional<V>?,
    ) {
        if (value == Optional.Absent) {
            out.nullValue()
            return
        }

        val result = value?.getOrNull()
        if (result != null) {
            gson.toJson(result, result.javaClass, out)
            return
        }

        out.serializeNulls = true
        out.nullValue()
        out.serializeNulls = false
    }

    override fun read(`in`: JsonReader): Optional<V> {
        // No serialization required as we do not read Optionals from the service
        throw NotImplementedError("Unexpected attempt to read Optional value")
    }
}
