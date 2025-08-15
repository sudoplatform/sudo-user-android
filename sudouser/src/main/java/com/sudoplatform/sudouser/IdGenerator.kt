/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

import java.util.UUID

/**
 * Interface for generating universally unique identifiers (UUIDs).
 */
interface IdGenerator {
    /**
     * Generates an UUID.
     *
     * @return UUID.
     */
    fun generateId(): String
}

/**
 * Default ID generator implementation.
 */
class IdGenerateImpl : IdGenerator {
    override fun generateId(): String = UUID.randomUUID().toString()
}
