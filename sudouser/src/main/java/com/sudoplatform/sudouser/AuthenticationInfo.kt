/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

/**
 * Encapsulates an authentication information.
 */
interface AuthenticationInfo {

    /**
     * Authentication type.
     */
    val type: String

    /**
     * Indicates whether or not the authentication information is valid.
     *
     * @return *true* if the authentication information is valid.
     */
    fun isValid(): Boolean

    /**
     *  Encodes the authentication information as [String].
     *
     *  @return encoded authentication information.
     */
    fun encode(): String

    /**
     * Returns the username associated with this authentication information.
     *
     * @return username.
     */
    fun getUsername(): String
}
