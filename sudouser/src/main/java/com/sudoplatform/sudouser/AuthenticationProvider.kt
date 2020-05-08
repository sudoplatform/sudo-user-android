/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

/**
 * Encapsulates an authentication provider responsible to generating authentication information
 * required to sign into the backend.
 */
interface AuthenticationProvider {

    /**
     * Generates and returns an authentication information.
     *
     * @return authentication information.
     */
    fun getAuthenticationInfo(): AuthenticationInfo

    /**
     * Resets internal state and releases any associated resources.
     */
    fun reset()

}