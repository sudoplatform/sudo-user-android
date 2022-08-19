/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

enum class RegistrationChallengeType {
    SAFETY_NET,
    TEST,
    FSSO
}

/**
 * Encapsulates a registration challenge.
 *
 * @param type registration challenge type. See [RegistrationChallengeType].
 * @param nonce unique nonce of the challenge
 * @param answer answer to the challenge
 */
data class RegistrationChallenge(val type: RegistrationChallengeType, var nonce: String? = null, var answer: String? = null)
