package com.example.network

import android.os.Build
import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.worker.WorkerTunnelSession
import com.example.worker.WorkerWsClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

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
     * measuring handshake + CONNECT round-trip latency in ms, resolving the exit IP,
     * and verifying Cloudflare ProxyIP TLS routing for Worker profiles.
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

            if (!fetchExitIp) {
                return@withContext Socks5ProbeResult(
                    success = true,
                    latencyMs = latencyMs,
                    detail = "اتصال موفق • پینگ ${latencyMs}ms",
                )
            }

            if (profile.profileType == ProfileType.WORKER_WS) {
                val cfTrace = resolveCloudflareProxyIpTrace(profile)
                val exitIp = cfTrace?.ip ?: resolveWorkerExitIp(profile)
                val detailText = buildString {
                    append("تأیید شد • پینگ ${latencyMs}ms")
                    if (cfTrace != null) {
                        append(" • ProxyIP فعال")
                        if (!cfTrace.colo.isNullOrBlank()) {
                            append(" (${cfTrace.colo})")
                        }
                    } else {
                        append(" • هشدار: ProxyIP پاسخ نداد")
                    }
                    if (!exitIp.isNullOrBlank()) {
                        append(" • IP خروجی: $exitIp")
                    }
                }
                Socks5ProbeResult(
                    success = true,
                    latencyMs = latencyMs,
                    exitIp = exitIp,
                    detail = detailText,
                )
            } else {
                val exitIp = resolveSocks5ExitIp(profile)
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
            }
        } catch (t: Throwable) {
            Socks5ProbeResult(
                success = false,
                errorMessage = t.localizedMessage ?: "خطا در برقراری ارتباط با سرور",
            )
        }
    }

    private data class CloudflareTrace(
        val ip: String?,
        val colo: String?,
    )

    /**
     * Connects over TLS (443) to cloudflare.com/cdn-cgi/trace inside the Worker tunnel.
     * Because Cloudflare Workers block direct TCP to Cloudflare IPs, this explicitly exercises
     * the Worker's PROXYIP fallback path end-to-end.
     */
    private fun resolveCloudflareProxyIpTrace(profile: ProxyProfile): CloudflareTrace? {
        return runCatching {
            val session = WorkerWsClient.openTunnel(
                uuid = profile.uuid,
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                targetHost = "cloudflare.com",
                targetPort = 443,
                initialPayload = ByteArray(0),
            )
            try {
                openTlsOverWorker(session, "cloudflare.com", 443, timeoutMs = 12_000) { sslSock ->
                    val req = "GET /cdn-cgi/trace HTTP/1.1\r\n" +
                        "Host: cloudflare.com\r\n" +
                        "User-Agent: CloudNG/1.0\r\n" +
                        "Connection: close\r\n\r\n"
                    val out = sslSock.getOutputStream()
                    out.write(req.toByteArray(StandardCharsets.US_ASCII))
                    out.flush()

                    val body = BufferedReader(
                        InputStreamReader(sslSock.getInputStream(), StandardCharsets.UTF_8),
                    ).readText()
                    var ip: String? = null
                    var colo: String? = null
                    for (line in body.lineSequence()) {
                        when {
                            line.startsWith("ip=") -> ip = line.removePrefix("ip=").trim()
                            line.startsWith("colo=") -> colo = line.removePrefix("colo=").trim()
                        }
                    }
                    if (ip != null || colo != null) CloudflareTrace(ip, colo) else null
                }
            } finally {
                session.close()
            }
        }.getOrNull()
    }

    private fun <T> openTlsOverWorker(
        wsSession: WorkerTunnelSession,
        sniHost: String,
        port: Int,
        timeoutMs: Int,
        block: (SSLSocket) -> T,
    ): T {
        val srv = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        srv.soTimeout = timeoutMs
        val clientSock = Socket()
        var bridgePeer: Socket? = null
        val bridgeThread = thread(isDaemon = true, name = "diag-tls-bridge") {
            runCatching {
                val peer = srv.accept()
                bridgePeer = peer
                peer.tcpNoDelay = true
                val downThread = thread(isDaemon = true, name = "diag-tls-down") {
                    runCatching {
                        val pOut = peer.getOutputStream()
                        while (true) {
                            val data = wsSession.readPlain() ?: break
                            if (data.isNotEmpty()) {
                                pOut.write(data)
                                pOut.flush()
                            }
                        }
                    }
                    runCatching { peer.shutdownOutput() }
                }
                val buf = ByteArray(16384)
                val pIn = peer.getInputStream()
                while (true) {
                    val n = pIn.read(buf)
                    if (n <= 0) break
                    if (!wsSession.sendPlain(buf, 0, n)) break
                }
                downThread.join(1000)
            }
            runCatching { bridgePeer?.close() }
        }
        try {
            clientSock.connect(srv.localSocketAddress, timeoutMs)
            clientSock.soTimeout = timeoutMs
            val factory = WorkerWsClient.getSharedSslSocketFactory()
            val sslSock = factory.createSocket(clientSock, sniHost, port, true) as SSLSocket
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                val params = sslSock.sslParameters
                params.serverNames = listOf(SNIHostName(sniHost))
                params.endpointIdentificationAlgorithm = "HTTPS"
                sslSock.sslParameters = params
            }
            sslSock.soTimeout = timeoutMs
            sslSock.startHandshake()
            return block(sslSock)
        } finally {
            runCatching { clientSock.close() }
            runCatching { bridgePeer?.close() }
            runCatching { srv.close() }
            bridgeThread.interrupt()
        }
    }

    private fun resolveWorkerExitIp(profile: ProxyProfile): String? {
        return runCatching {
            val req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: CloudNG/1.0\r\nConnection: close\r\n\r\n"
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
                val req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: CloudNG/1.0\r\nConnection: close\r\n\r\n"
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
