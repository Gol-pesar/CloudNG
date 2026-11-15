package com.example.network

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.worker.WorkerWsClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

data class Socks5ProbeResult(
    val success: Boolean,
    val latencyMs: Long? = null,
    val exitIp: String? = null,
    val errorMessage: String? = null,
    val detail: String? = null,
)

object Socks5Diagnostics {

    /**
     * Performs a real tunnel probe for either WORKER_WS or STANDARD_SOCKS5 profiles,
     * measuring handshake + CONNECT round-trip latency in ms and optionally resolving the exit IP.
     */
    suspend fun probeProfile(
        profile: ProxyProfile,
        targetHost: String = "8.8.8.8",
        targetPort: Int = 53,
        fetchExitIp: Boolean = true,
    ): Socks5ProbeResult = withContext(Dispatchers.IO) {
        val startNanos = System.nanoTime()
        try {
            if (profile.profileType == ProfileType.WORKER_WS) {
                val session = WorkerWsClient.openTunnel(
                    uuid = profile.uuid,
                    workerHost = profile.workerHost,
                    cleanIp = profile.cleanIp,
                    subproto = profile.subproto,
                    targetHost = targetHost,
                    targetPort = targetPort,
                )
                session.close()
            } else {
                Socks5Client.connect(
                    proxyHost = profile.host,
                    proxyPort = profile.port,
                    username = profile.username,
                    password = profile.password,
                    useAuth = profile.useAuth,
                    targetHost = targetHost,
                    targetPort = targetPort,
                    timeoutMs = 7000,
                ).use { _ -> }
            }

            val latencyMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(1L)

            val exitIp = if (fetchExitIp) {
                if (profile.profileType == ProfileType.WORKER_WS) {
                    resolveWorkerExitIp(profile)
                } else {
                    resolveSocks5ExitIp(profile)
                }
            } else {
                null
            }

            Socks5ProbeResult(
                success = true,
                latencyMs = latencyMs,
                exitIp = exitIp,
                detail = if (exitIp != null) {
                    "تأیید شد • پینگ ${latencyMs}ms • IP خروجی: $exitIp"
                } else {
                    "اتصال موفق • پینگ ${latencyMs}ms"
                },
            )
        } catch (t: Throwable) {
            Socks5ProbeResult(
                success = false,
                errorMessage = t.localizedMessage ?: "خطا در برقراری ارتباط با سرور",
            )
        }
    }

    private fun resolveWorkerExitIp(profile: ProxyProfile): String? {
        return runCatching {
            val req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: SocksGuard/1.0\r\nConnection: close\r\n\r\n"
            val session = WorkerWsClient.openTunnel(
                uuid = profile.uuid,
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                targetHost = "api.ipify.org",
                targetPort = 80,
                initialPayload = ByteArray(0),
            )
            try {
                if (!session.sendPlain(req.toByteArray(StandardCharsets.US_ASCII))) return@runCatching null
                val sb = StringBuilder()
                while (true) {
                    val chunk = session.readPlain() ?: break
                    sb.append(chunk.decodeToString())
                    val sepIdx = sb.indexOf("\r\n\r\n")
                    if (sepIdx >= 0) {
                        val body = sb.substring(sepIdx + 4).trim()
                        if (body.length in 7..45 && !body.contains("<")) {
                            return@runCatching body
                        }
                    }
                }
                null
            } finally {
                session.close()
            }
        }.getOrNull()
    }

    private fun resolveSocks5ExitIp(profile: ProxyProfile): String? {
        return runCatching {
            Socks5Client.connect(
                proxyHost = profile.host,
                proxyPort = profile.port,
                username = profile.username,
                password = profile.password,
                useAuth = profile.useAuth,
                targetHost = "api.ipify.org",
                targetPort = 80,
                timeoutMs = 5000,
            ).use { socket ->
                val req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: SocksGuard/1.0\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().write(req.toByteArray(StandardCharsets.US_ASCII))
                socket.getOutputStream().flush()

                val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
                var inBody = false
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val current = line.orEmpty().trim()
                    if (!inBody) {
                        if (current.isEmpty()) inBody = true
                    } else if (current.isNotEmpty()) {
                        if (current.length in 7..45 && !current.contains("<")) {
                            return@use current
                        }
                    }
                }
                null
            }
        }.getOrNull()
    }
}
