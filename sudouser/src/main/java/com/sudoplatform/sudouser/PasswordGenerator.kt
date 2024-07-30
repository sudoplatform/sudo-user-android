/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudouser

/**
 * Generates a password complying to a specific set of rules.
 */
interface PasswordGenerator {

    /**
     * Generates a random password.
     *
     * @param length password length.
     * @param upperCase *true* if 1 uppercase is required.
     * @param lowerCase *true* if 1 lowercase is required.
     * @param special *true* if 1 special character is required.
     * @param number *true* if 1 numeric character is required.
     * @return generated password.
     */
    fun generatePassword(
        length: Int,
        upperCase: Boolean,
        lowerCase: Boolean,
        special: Boolean,
        number: Boolean,
    ): String
}

/**
 * Default password generator implementation.
 */
class PasswordGeneratorImpl : PasswordGenerator {

    companion object {
        private val ALL_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!?;,&%$@#^*~".toList()
        private val UPPER_CASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toList()
        private val LOWER_CASE_CHARS = "abcdefghijklmnopqrstuvwxyz".toList()
        private val NUMBER_CHARS = "0123456789".toList()
        private val SPECIAL_CHARS = ".!?;,&%\\$@#^*~".toList()
    }

    override fun generatePassword(
        length: Int,
        upperCase: Boolean,
        lowerCase: Boolean,
        special: Boolean,
        number: Boolean,
    ): String {
        val password = mutableListOf<Char>()

        if (upperCase) {
            password += UPPER_CASE_CHARS.random()
        }

        if (lowerCase) {
            password += LOWER_CASE_CHARS.random()
        }

        if (special) {
            password += SPECIAL_CHARS.random()
        }

        if (number) {
            password += NUMBER_CHARS.random()
        }

        while (password.size < length) {
            password += ALL_CHARS.random()
        }

        password.shuffle()

        return password.joinToString("")
    }
}
