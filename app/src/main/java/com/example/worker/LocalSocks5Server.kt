package com.example.worker

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.network.Socks5Client
import com.example.vpn.LogLevel
import com.example.vpn.VpnStateManager
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * High-throughput local SOCKS5 listener (e.g., 127.0.0.1:40446) bridging local SOCKS5 clients
 * directly through either RawWebSocket Worker tunnel (with pool) or an upstream SOCKS5 proxy.
 */
class LocalSocks5Server(
    private val profile: ProxyProfile,
    private val listenHost: String = WorkerDefaults.LISTEN_HOST,
    private val listenPort: Int = profile.localPort,
) {
    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val srv = ServerSocket()
        srv.reuseAddress = true
        srv.bind(InetSocketAddress(listenHost, listenPort))
        serverSocket = srv

        if (profile.profileType == ProfileType.WORKER_WS) {
            WorkerWsPool.startWarming(profile.workerHost, profile.cleanIp, profile.subproto)
        }

        VpnStateManager.addLog(
            LogLevel.SUCCESS,
            "LOCAL",
            "پروکسی محلی SOCKS5 روی $listenHost:$listenPort آماده شد",
        )

        acceptThread = thread(isDaemon = true, name = "socks-accept-$listenPort") {
            while (running.get()) {
                val client = try {
                    srv.accept()
                } catch (_: Exception) {
                    break
                }
                thread(isDaemon = true, name = "socks-${client.remoteSocketAddress}") {
                    handleClient(client)
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread?.interrupt()
        acceptThread = null
    }

    private fun handleClient(cs: Socket) {
        cs.use { s ->
            s.tcpNoDelay = true
            runCatching {
                s.receiveBufferSize = 512 * 1024
                s.sendBufferSize = 512 * 1024
            }
            s.soTimeout = WorkerDefaults.HANDSHAKE_TIMEOUT_MS
            val input = s.getInputStream()
            val output = s.getOutputStream()

            val hdr = readExact(input, 2) ?: return
            if (hdr[0].toInt() != 5) return
            val nmethods = hdr[1].toInt() and 0xFF
            readExact(input, nmethods) ?: return
            output.write(byteArrayOf(5, 0))
            output.flush()

            val req = readExact(input, 4) ?: return
            if (req[0].toInt() != 5 || req[1].toInt() != 1) return
            val at = req[3].toInt() and 0xFF
            val host: String = when (at) {
                1 -> {
                    val b = readExact(input, 4) ?: return
                    InetAddress.getByAddress(b).hostAddress ?: return
                }
                3 -> {
                    val lb = readExact(input, 1) ?: return
                    val ln = lb[0].toInt() and 0xFF
                    String(readExact(input, ln) ?: return, Charsets.UTF_8)
                }
                4 -> {
                    val b = readExact(input, 16) ?: return
                    InetAddress.getByAddress(b).hostAddress ?: return
                }
                else -> return
            }
            val pb = readExact(input, 2) ?: return
            val port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)

            if (profile.profileType == ProfileType.WORKER_WS) {
                relayViaWorker(s, input, output, host, port)
            } else {
                relayViaUpstreamSocks5(s, input, output, host, port)
            }
        }
    }

    private fun relayViaWorker(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream,
        host: String,
        port: Int,
    ) {
        val session = try {
            WorkerWsClient.openTunnel(
                uuid = profile.uuid,
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                targetHost = host,
                targetPort = port,
            )
        } catch (t: Throwable) {
            runCatching {
                output.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
            }
            VpnStateManager.addLog(
                LogLevel.WARNING,
                "WS",
                "خطا در اتصال $host:$port — ${t.localizedMessage ?: "ناموفق"}",
            )
            return
        }

        VpnStateManager.incrementActiveConnections()
        VpnStateManager.addLog(LogLevel.INFO, "WS", "تونل محلی -> $host:$port")
        try {
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            clientSocket.soTimeout = 0

            val downThread = thread(isDaemon = true, name = "ws-down-$host:$port") {
                try {
                    while (true) {
                        val plain = session.readPlain() ?: break
                        if (plain.isNotEmpty()) {
                            VpnStateManager.recordRx(plain.size)
                            output.write(plain)
                            output.flush()
                        }
                    }
                } catch (_: Throwable) {
                } finally {
                    runCatching { clientSocket.close() }
                }
            }

            try {
                val buf = ByteArray(WorkerDefaults.MAX_CHUNK)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    VpnStateManager.recordTx(n)
                    if (!session.sendPlain(buf, 0, n)) break
                }
            } catch (_: Throwable) {
            } finally {
                session.close()
            }
            downThread.join(1500)
        } finally {
            VpnStateManager.decrementActiveConnections()
            session.close()
        }
    }

    private fun relayViaUpstreamSocks5(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream,
        host: String,
        port: Int,
    ) {
        try {
            Socks5Client.connect(
                proxyHost = profile.host,
                proxyPort = profile.port,
                username = profile.username,
                password = profile.password,
                useAuth = profile.useAuth,
                targetHost = host,
                targetPort = port,
                timeoutMs = 10_000,
            ).use { upstream ->
                VpnStateManager.incrementActiveConnections()
                try {
                    output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    output.flush()
                    clientSocket.soTimeout = 0
                    upstream.soTimeout = 0

                    val tUp = thread(isDaemon = true) {
                        runCatching {
                            val buf = ByteArray(WorkerDefaults.MAX_CHUNK)
                            val upOut = upstream.getOutputStream()
                            while (true) {
                                val n = input.read(buf)
                                if (n <= 0) break
                                VpnStateManager.recordTx(n)
                                upOut.write(buf, 0, n)
                                upOut.flush()
                            }
                        }
                        runCatching { upstream.shutdownOutput() }
                    }

                    val upIn = upstream.getInputStream()
                    val buf = ByteArray(WorkerDefaults.MAX_CHUNK)
                    while (true) {
                        val n = upIn.read(buf)
                        if (n <= 0) break
                        VpnStateManager.recordRx(n)
                        output.write(buf, 0, n)
                        output.flush()
                    }
                    tUp.join(1000)
                } finally {
                    VpnStateManager.decrementActiveConnections()
                }
            }
        } catch (_: Throwable) {
        }
    }

    private fun readExact(input: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) return null
            off += r
        }
        return buf
    }
}
