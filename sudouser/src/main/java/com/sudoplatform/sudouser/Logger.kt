package com.sudoplatform.sudouser

import com.sudoplatform.sudologging.AndroidUtilsLogDriver
import com.sudoplatform.sudologging.LogLevel
import com.sudoplatform.sudologging.Logger

/**
 * Default logger.
 */
class DefaultLogger {

    companion object {
        val instance = Logger("SudoUser", AndroidUtilsLogDriver(LogLevel.INFO))
    }

}