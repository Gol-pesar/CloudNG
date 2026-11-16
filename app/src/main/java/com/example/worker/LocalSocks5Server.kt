package com.example.worker

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.network.Socks5Client
import com.example.vpn.LogLevel
import com.example.vpn.VpnSocketProtector
import com.example.vpn.VpnStateManager
import java.io.InputStream
import java.io.OutputStream
import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-throughput local SOCKS5 listener (e.g., 127.0.0.1:40446) bridging local SOCKS5 clients
 * directly through either RawWebSocket Worker tunnel (with pool) or an upstream SOCKS5 proxy.
 */
class LocalSocks5Server(
    private val profile: ProxyProfile,
    private val listenHost: String = WorkerDefaults.LISTEN_HOST,
    private val listenPort: Int = profile.localPort,
    private val socketProtector: ((Socket) -> Boolean)? = null,
) {
    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var workerPool: ExecutorService? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val srv = ServerSocket()
        srv.reuseAddress = true
        var lastBindErr: BindException? = null
        var bound = false
        for (attempt in 0 until 5) {
            try {
                srv.bind(InetSocketAddress(listenHost, listenPort))
                bound = true
                break
            } catch (e: BindException) {
                lastBindErr = e
                Thread.sleep(60L)
            }
        }
        if (!bound) {
            running.set(false)
            runCatching { srv.close() }
            throw lastBindErr ?: BindException("پورت محلی $listenPort در حال استفاده است.")
        }
        serverSocket = srv

        val threadCounter = AtomicInteger(1)
        val exec = Executors.newCachedThreadPool { r ->
            Thread(r, "cloudng-socks-${threadCounter.getAndIncrement()}").apply {
                isDaemon = true
            }
        }
        workerPool = exec

        if (profile.profileType == ProfileType.WORKER_WS) {
            WorkerWsPool.startWarming(
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                socketProtector = socketProtector ?: VpnSocketProtector.activeProtector,
            )
        }

        VpnStateManager.addLog(
            LogLevel.SUCCESS,
            "LOCAL",
            "پروکسی محلی SOCKS5 روی $listenHost:$listenPort آماده شد",
        )

        acceptThread = Thread({
            while (running.get()) {
                val client = try {
                    srv.accept()
                } catch (_: Exception) {
                    break
                }
                try {
                    exec.execute { handleClient(client) }
                } catch (_: Throwable) {
                    runCatching { client.close() }
                }
            }
        }, "socks-accept-$listenPort").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running.set(false)
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread?.interrupt()
        acceptThread = null
        runCatching { workerPool?.shutdownNow() }
        workerPool = null
    }

    private fun handleClient(cs: Socket) {
        cs.use { s ->
            s.tcpNoDelay = true
            runCatching {
                s.receiveBufferSize = 1024 * 1024
                s.sendBufferSize = 1024 * 1024
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
                socketProtector = socketProtector ?: VpnSocketProtector.activeProtector,
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

            val downDone = AtomicBoolean(false)
            val downTask = workerPool?.submit {
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
                    downDone.set(true)
                    runCatching { clientSocket.shutdownOutput() }
                    runCatching { clientSocket.close() }
                }
            }

            try {
                val buf = ByteArray(WorkerDefaults.MAX_CHUNK)
                while (!downDone.get()) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    VpnStateManager.recordTx(n)
                    if (!session.sendPlain(buf, 0, n)) {
                        session.close()
                        break
                    }
                }
            } catch (_: Throwable) {
                session.close()
            }

            // Wait for server downstream to finish naturally instead of killing WS on client half-close
            runCatching { downTask?.get() }
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
                socketProtector = socketProtector ?: VpnSocketProtector.activeProtector,
            ).use { upstream ->
                VpnStateManager.incrementActiveConnections()
                try {
                    output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    output.flush()
                    clientSocket.soTimeout = 0
                    upstream.soTimeout = 0

                    val upTask = workerPool?.submit {
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
                    runCatching { upTask?.get() }
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
