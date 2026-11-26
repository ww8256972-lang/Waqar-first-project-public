package com.wci.sandbox.runtime

import java.io.File
import java.util.UUID

/**
 * VolatileFileJail (S-39, S-43)
 * Provides an isolated ephemeral directory for sandbox scratch files,
 * with canonical path enforcement and recursive post-run zeroization.
 */
class VolatileFileJail(private val baseCacheDir: File) {

    private val jailId = UUID.randomUUID().toString()
    val jailDir: File = File(baseCacheDir, "sandbox_jail/$jailId").apply { mkdirs() }

    fun resolveSafeFile(relativeName: String): File {
        val rootPath = jailDir.canonicalFile.toPath().normalize()
        val target = File(jailDir, relativeName).canonicalFile
        val targetPath = target.toPath().normalize()
        if (!targetPath.startsWith(rootPath) || targetPath == rootPath) {
            throw SecurityException("PATH_TRAVERSAL_DETECTED: Attempted jail escape outside $jailDir")
        }
        return target
    }

    fun purgeJail() {
        if (jailDir.exists()) {
            jailDir.walkBottomUp().forEach { file ->
                if (file.isFile) {
                    runCatching {
                        val len = file.length().coerceAtMost(1024L * 1024L).toInt()
                        if (len > 0) file.writeBytes(ByteArray(len))
                    }
                }
            }
            jailDir.deleteRecursively()
        }
    }
}
