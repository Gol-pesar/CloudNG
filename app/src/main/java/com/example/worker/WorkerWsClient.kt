package com.example.worker

import android.os.Build
import com.example.vpn.VpnSocketProtector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * High-speed, zero-compression RFC 6455 WebSocket connection over TLS SSLSocket
 * with explicit SNI (server_hostname) and shared TLS session cache for Cloudflare Clean IP routing.
 */
class RawWebSocket(
    private val socket: Socket,
    preBufferedInput: BufferedInputStream? = null,
) {
    private val input = DataInputStream(preBufferedInput ?: BufferedInputStream(socket.getInputStream(), 65536))
    private val rawOutput = socket.getOutputStream()
    private val writeLock = Any()
    private val closed = AtomicBoolean(false)
    val createdAtMs: Long = System.currentTimeMillis()

    fun isClosed(): Boolean = closed.get() || socket.isClosed

    fun setReadTimeout(timeoutMs: Int) {
        runCatching { socket.soTimeout = timeoutMs }
    }

    /**
     * Encrypts [plain] with [xorKey] (if non-null) and RFC 6455 4-byte mask
     * in a single pass, writing a single contiguous binary frame directly to the TLS socket.
     */
    fun sendBinary(plain: ByteArray, offset: Int = 0, length: Int = plain.size, xorKey: ByteArray? = null): Boolean {
        if (closed.get()) return false
        return try {
            val maskInt = ThreadLocalRandom.current().nextInt()
            val m0 = (maskInt ushr 24) and 0xFF
            val m1 = (maskInt ushr 16) and 0xFF
            val m2 = (maskInt ushr 8) and 0xFF
            val m3 = maskInt and 0xFF

            val headerSize = when {
                length < 126 -> 2 + 4
                length <= 65535 -> 4 + 4
                else -> 10 + 4
            }
            val frame = ByteArray(headerSize + length)
            frame[0] = 0x82.toByte() // FIN + Binary
            var p = 1
            when {
                length < 126 -> {
                    frame[p++] = (0x80 or length).toByte()
                }
                length <= 65535 -> {
                    frame[p++] = (0x80 or 126).toByte()
                    frame[p++] = ((length ushr 8) and 0xFF).toByte()
                    frame[p++] = (length and 0xFF).toByte()
                }
                else -> {
                    frame[p++] = (0x80 or 127).toByte()
                    val longLen = length.toLong()
                    for (shift in 56 downTo 0 step 8) {
                        frame[p++] = ((longLen ushr shift) and 0xFFL).toByte()
                    }
                }
            }
            frame[p++] = m0.toByte()
            frame[p++] = m1.toByte()
            frame[p++] = m2.toByte()
            frame[p++] = m3.toByte()

            val masks = intArrayOf(m0, m1, m2, m3)
            if (xorKey != null) {
                var i = 0
                val limit4 = length and 3.inv()
                while (i < limit4) {
                    val base = offset + i
                    val kOff = i and 15
                    frame[p + i] = (plain[base].toInt() xor xorKey[kOff].toInt() xor m0).toByte()
                    frame[p + i + 1] = (plain[base + 1].toInt() xor xorKey[(kOff + 1) and 15].toInt() xor m1).toByte()
                    frame[p + i + 2] = (plain[base + 2].toInt() xor xorKey[(kOff + 2) and 15].toInt() xor m2).toByte()
                    frame[p + i + 3] = (plain[base + 3].toInt() xor xorKey[(kOff + 3) and 15].toInt() xor m3).toByte()
                    i += 4
                }
                while (i < length) {
                    val enc = plain[offset + i].toInt() xor xorKey[i and 15].toInt()
                    frame[p + i] = (enc xor masks[i and 3]).toByte()
                    i++
                }
            } else {
                var i = 0
                val limit4 = length and 3.inv()
                while (i < limit4) {
                    val base = offset + i
                    frame[p + i] = (plain[base].toInt() xor m0).toByte()
                    frame[p + i + 1] = (plain[base + 1].toInt() xor m1).toByte()
                    frame[p + i + 2] = (plain[base + 2].toInt() xor m2).toByte()
                    frame[p + i + 3] = (plain[base + 3].toInt() xor m3).toByte()
                    i += 4
                }
                while (i < length) {
                    frame[p + i] = (plain[offset + i].toInt() xor masks[i and 3]).toByte()
                    i++
                }
            }

            synchronized(writeLock) {
                if (closed.get()) return false
                rawOutput.write(frame)
                rawOutput.flush()
            }
            true
        } catch (_: Throwable) {
            close()
            false
        }
    }

    private fun sendControlFrame(opcode: Int, payload: ByteArray) {
        synchronized(writeLock) {
            if (closed.get()) return
            runCatching {
                val maskInt = ThreadLocalRandom.current().nextInt()
                val mask = byteArrayOf(
                    ((maskInt ushr 24) and 0xFF).toByte(),
                    ((maskInt ushr 16) and 0xFF).toByte(),
                    ((maskInt ushr 8) and 0xFF).toByte(),
                    (maskInt and 0xFF).toByte(),
                )
                val len = payload.size.coerceAtMost(125)
                val hdr = ByteArray(2 + 4 + len)
                hdr[0] = (0x80 or opcode).toByte()
                hdr[1] = (0x80 or len).toByte()
                System.arraycopy(mask, 0, hdr, 2, 4)
                for (i in 0 until len) {
                    hdr[6 + i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
                }
                rawOutput.write(hdr)
                rawOutput.flush()
            }
        }
    }

    /**
     * Reads the next WebSocket data message, handling fragmentation and PING/PONG automatically.
     * Returns null on clean CLOSE/EOF.
     */
    fun readMessage(xorKey: ByteArray? = null): ByteArray? {
        var fragments: ByteArrayOutputStream? = null
        while (!closed.get()) {
            val b0: Int
            val b1: Int
            try {
                b0 = input.readUnsignedByte()
                b1 = input.readUnsignedByte()
            } catch (_: EOFException) {
                return null
            }

            val fin = (b0 and 0x80) != 0
            val opcode = b0 and 0x0F
            val masked = (b1 and 0x80) != 0
            var payloadLen = (b1 and 0x7F).toLong()

            if (payloadLen == 126L) {
                payloadLen = input.readUnsignedShort().toLong()
            } else if (payloadLen == 127L) {
                payloadLen = input.readLong()
            }
            if (payloadLen < 0 || payloadLen > 16L * 1024L * 1024L) {
                throw IOException("طول فریم WebSocket نامعتبر است: $payloadLen")
            }

            val maskKey = if (masked) ByteArray(4).also { input.readFully(it) } else null
            val payload = ByteArray(payloadLen.toInt())
            if (payload.isNotEmpty()) {
                input.readFully(payload)
                if (maskKey != null) {
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
                    }
                }
            }

            when (opcode) {
                0x08 -> { // CLOSE
                    close()
                    return null
                }
                0x09 -> { // PING -> reply PONG
                    sendControlFrame(0x0A, payload)
                    continue
                }
                0x0A -> { // PONG
                    continue
                }
                0x00, 0x01, 0x02 -> {
                    if (fin && fragments == null) {
                        if (xorKey != null) {
                            for (i in payload.indices) {
                                payload[i] = (payload[i].toInt() xor xorKey[i and 15].toInt()).toByte()
                            }
                        }
                        return payload
                    }
                    if (fragments == null) fragments = ByteArrayOutputStream()
                    fragments.write(payload)
                    if (fin) {
                        val combined = fragments.toByteArray()
                        if (xorKey != null) {
                            for (i in combined.indices) {
                                combined[i] = (combined[i].toInt() xor xorKey[i and 15].toInt()).toByte()
                            }
                        }
                        return combined
                    }
                }
                else -> throw IOException("کد عملیات ناشناخته WebSocket: $opcode")
            }
        }
        return null
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { socket.close() }
        }
    }
}

class WorkerTunnelSession(
    private val ws: RawWebSocket,
    val key: ByteArray,
) {
    fun isClosed(): Boolean = ws.isClosed()

    fun sendPlain(data: ByteArray, offset: Int = 0, length: Int = data.size): Boolean {
        if (length <= WorkerDefaults.MAX_CHUNK) {
            return ws.sendBinary(data, offset, length, xorKey = key)
        }
        var cur = 0
        while (cur < length) {
            val sliceLen = (length - cur).coerceAtMost(WorkerDefaults.MAX_CHUNK)
            if (!ws.sendBinary(data, offset + cur, sliceLen, xorKey = key)) return false
            cur += sliceLen
        }
        return true
    }

    fun readPlain(): ByteArray? =
        ws.readMessage(xorKey = key)

    fun setReadTimeout(timeoutMs: Int) {
        ws.setReadTimeout(timeoutMs)
    }

    fun close() {
        ws.close()
    }
}

/**
 * Maintains a hot pool of pre-connected TLS+WebSocket connections so browser bursts
 * execute with zero TCP/TLS/WS handshake latency.
 */
object WorkerWsPool {
    private const val POOL_SIZE = 10
    private const val MAX_IDLE_AGE_MS = 22_000L

    private data class PoolConfig(
        val workerHost: String,
        val cleanIp: String,
        val subproto: String,
    )

    private val poolScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val warmSockets = ConcurrentLinkedDeque<RawWebSocket>()
    private val refillSignal = Channel<Unit>(Channel.CONFLATED)
    @Volatile
    private var activeConfig: PoolConfig? = null
    @Volatile
    private var activeProtector: ((Socket) -> Boolean)? = null
    private var maintainerJob: Job? = null

    fun startWarming(
        workerHost: String,
        cleanIp: String,
        subproto: String,
        socketProtector: ((Socket) -> Boolean)? = null,
    ) {
        val cfg = PoolConfig(workerHost.trim(), cleanIp.trim(), subproto.trim())
        if (activeConfig != cfg) {
            clear()
            activeConfig = cfg
        }
        activeProtector = socketProtector
        if (maintainerJob?.isActive == true) {
            refillSignal.trySend(Unit)
            return
        }
        maintainerJob = poolScope.launch {
            while (isActive) {
                val cur = activeConfig ?: break
                pruneExpired()
                val deficit = POOL_SIZE - warmSockets.size
                if (deficit > 0) {
                    repeat(deficit) {
                        launch { refillOne(cur) }
                    }
                }
                withTimeoutOrNull(5000L) { refillSignal.receive() }
            }
        }
    }

    private fun refillOne(cfg: PoolConfig) {
        runCatching {
            if (activeConfig != cfg || warmSockets.size >= POOL_SIZE) return
            val ws = WorkerWsClient.connectRawWebSocket(
                workerHost = cfg.workerHost,
                cleanIp = cfg.cleanIp,
                subproto = cfg.subproto,
                socketProtector = activeProtector,
            )
            if (activeConfig == cfg && warmSockets.size < POOL_SIZE) {
                warmSockets.offerLast(ws)
            } else {
                ws.close()
            }
        }
    }

    fun acquire(workerHost: String, cleanIp: String, subproto: String): RawWebSocket? {
        val cfg = PoolConfig(workerHost.trim(), cleanIp.trim(), subproto.trim())
        if (activeConfig != cfg) return null
        val now = System.currentTimeMillis()
        while (true) {
            val ws = warmSockets.pollFirst() ?: return null
            refillSignal.trySend(Unit)
            if (warmSockets.size <= 4) {
                poolScope.launch { refillOne(cfg) }
            }
            if (!ws.isClosed() && (now - ws.createdAtMs) < MAX_IDLE_AGE_MS) {
                return ws
            }
            ws.close()
        }
    }

    fun clear() {
        activeConfig = null
        activeProtector = null
        maintainerJob?.cancel()
        maintainerJob = null
        while (true) {
            val ws = warmSockets.pollFirst() ?: break
            ws.close()
        }
    }

    private fun pruneExpired() {
        val now = System.currentTimeMillis()
        val iter = warmSockets.iterator()
        while (iter.hasNext()) {
            val ws = iter.next()
            if (ws.isClosed() || (now - ws.createdAtMs) >= MAX_IDLE_AGE_MS) {
                iter.remove()
                ws.close()
            }
        }
    }
}

object WorkerWsClient {
    private const val CONNECT_TIMEOUT_MS = 5000
    private const val TLS_HANDSHAKE_TIMEOUT_MS = 5000
    private const val POOLED_ACK_TIMEOUT_MS = 16000
    private const val DNS_CACHE_TTL_MS = 60_000L

    private val resolvedHostCache = ConcurrentHashMap<String, Pair<Long, List<InetAddress>>>()
    private val fastestCleanCandidate = ConcurrentHashMap<String, String>()

    private val sharedSslContext: SSLContext by lazy {
        SSLContext.getInstance("TLS").apply {
            init(null, null, null)
            runCatching {
                clientSessionContext.sessionCacheSize = 256
                clientSessionContext.sessionTimeout = 900
            }
        }
    }

    fun getSharedSslSocketFactory(): SSLSocketFactory =
        sharedSslContext.socketFactory as SSLSocketFactory

    private val threadLocalRng = object : ThreadLocal<SecureRandom>() {
        override fun initialValue(): SecureRandom = SecureRandom()
    }

    private data class ParsedWorkerEndpoint(
        val host: String,
        val port: Int,
        val path: String,
    )

    private fun parseWorkerEndpoint(raw: String): ParsedWorkerEndpoint {
        var s = raw.trim()
            .removePrefix("https://")
            .removePrefix("wss://")
            .removePrefix("http://")
            .removePrefix("ws://")
            .trim()
        val slashIdx = s.indexOf('/')
        val path = if (slashIdx >= 0) {
            val rawPath = s.substring(slashIdx).trim()
            s = s.substring(0, slashIdx)
            if (rawPath.startsWith("/")) rawPath else "/$rawPath"
        } else {
            "/"
        }
        val (host, port) = parseHostAndPort(s, defaultPort = 443)
        return ParsedWorkerEndpoint(host = host, port = port, path = path)
    }

    private fun parseHostAndPort(raw: String, defaultPort: Int): Pair<String, Int> {
        val clean = raw.trim()
        if (clean.startsWith("[")) {
            val closeIdx = clean.indexOf(']')
            if (closeIdx > 0) {
                val h = clean.substring(1, closeIdx)
                val rest = clean.substring(closeIdx + 1)
                val p = if (rest.startsWith(":")) {
                    rest.substring(1).toIntOrNull()?.takeIf { it in 1..65535 } ?: defaultPort
                } else {
                    defaultPort
                }
                return h to p
            }
        }
        val colonIdx = clean.lastIndexOf(':')
        if (colonIdx > 0 && clean.indexOf(':') == colonIdx) {
            val possiblePort = clean.substring(colonIdx + 1).toIntOrNull()
            if (possiblePort != null && possiblePort in 1..65535) {
                return clean.substring(0, colonIdx).trim() to possiblePort
            }
        }
        return clean.removePrefix("[").removeSuffix("]") to defaultPort
    }

    fun connectRawWebSocket(
        workerHost: String,
        cleanIp: String,
        subproto: String,
        socketProtector: ((Socket) -> Boolean)? = null,
    ): RawWebSocket {
        val endpoint = parseWorkerEndpoint(workerHost)
        val rawList = cleanIp
            .split(',', ';', '\n', ' ')
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        val cacheKey = "${endpoint.host}|${cleanIp.trim()}"
        val sticky = fastestCleanCandidate[cacheKey]
        val cleanCandidates = if (sticky != null && rawList.contains(sticky)) {
            listOf(sticky) + rawList.filter { it != sticky }
        } else {
            rawList
        }

        var firstError: Throwable? = null
        for (rawCandidate in cleanCandidates) {
            val (connectHost, connectPort) = parseHostAndPort(rawCandidate, endpoint.port)
            if (connectHost.isEmpty()) continue
            val attempt = runCatching {
                openTlsWebSocket(
                    connectHost = connectHost,
                    connectPort = connectPort,
                    sniHost = endpoint.host,
                    wsPath = endpoint.path,
                    subproto = subproto,
                    socketProtector = socketProtector,
                )
            }
            if (attempt.isSuccess) {
                fastestCleanCandidate[cacheKey] = rawCandidate
                return attempt.getOrThrow()
            }
            if (firstError == null) {
                firstError = attempt.exceptionOrNull()
            }
        }

        if (endpoint.host.isEmpty()) {
            throw firstError ?: IOException("آدرس سرور Worker خالی است.")
        }

        return try {
            openTlsWebSocket(
                connectHost = endpoint.host,
                connectPort = endpoint.port,
                sniHost = endpoint.host,
                wsPath = endpoint.path,
                subproto = subproto,
                socketProtector = socketProtector,
            )
        } catch (t: Throwable) {
            throw firstError ?: t
        }
    }

    private fun openTlsWebSocket(
        connectHost: String,
        connectPort: Int,
        sniHost: String,
        wsPath: String,
        subproto: String,
        socketProtector: ((Socket) -> Boolean)?,
    ): RawWebSocket {
        val candidates = resolvePreferIpv4(connectHost)
        var lastError: Throwable? = null
        for (addr in candidates) {
            val rawSocket = Socket()
            try {
                rawSocket.tcpNoDelay = true
                rawSocket.keepAlive = true
                runCatching {
                    rawSocket.receiveBufferSize = 1024 * 1024
                    rawSocket.sendBufferSize = 1024 * 1024
                    rawSocket.trafficClass = 0x10 // IPTOS_LOWDELAY
                }
                if (!VpnSocketProtector.protectAndBind(rawSocket, socketProtector, addr)) {
                    throw IOException("امکان محافظت سوکت از مسیر VPN وجود ندارد.")
                }
                rawSocket.connect(InetSocketAddress(addr, connectPort), CONNECT_TIMEOUT_MS)

                val factory = sharedSslContext.socketFactory as SSLSocketFactory
                val sslSocket = factory.createSocket(rawSocket, sniHost, connectPort, true) as SSLSocket
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val params = sslSocket.sslParameters
                    params.serverNames = listOf(SNIHostName(sniHost))
                    params.endpointIdentificationAlgorithm = "HTTPS"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        params.applicationProtocols = arrayOf("http/1.1")
                    }
                    sslSocket.sslParameters = params
                }
                sslSocket.soTimeout = TLS_HANDSHAKE_TIMEOUT_MS
                sslSocket.startHandshake()

                val verified = HttpsURLConnection.getDefaultHostnameVerifier()
                    .verify(sniHost, sslSocket.session)
                if (!verified) {
                    throw IOException("تأیید گواهی SSL برای $sniHost ناموفق بود.")
                }

                // RFC 6455 HTTP/1.1 Upgrade
                val nonceBytes = ByteArray(16).also { threadLocalRng.get()!!.nextBytes(it) }
                val wsKey = encodeBase64(nonceBytes)
                val hostHeader = if (connectPort == 443) sniHost else "$sniHost:$connectPort"
                val sb = StringBuilder(256)
                sb.append("GET ").append(wsPath).append(" HTTP/1.1\r\n")
                sb.append("Host: ").append(hostHeader).append("\r\n")
                sb.append("Upgrade: websocket\r\n")
                sb.append("Connection: Upgrade\r\n")
                sb.append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n")
                sb.append("Sec-WebSocket-Version: 13\r\n")
                if (subproto.isNotBlank()) {
                    sb.append("Sec-WebSocket-Protocol: ").append(subproto.trim()).append("\r\n")
                }
                sb.append("User-Agent: CloudNG/1.0\r\n")
                sb.append("\r\n")

                val out = sslSocket.getOutputStream()
                out.write(sb.toString().toByteArray(Charsets.US_ASCII))
                out.flush()

                val inStream = BufferedInputStream(sslSocket.getInputStream(), 65536)
                val statusLine = readHeaderLine(inStream)
                    ?: throw IOException("پاسخ ارتقا WebSocket از سرور دریافت نشد.")
                if (!statusLine.contains("101")) {
                    throw IOException("ارتقا به WebSocket رد شد: $statusLine")
                }
                var acceptOk = false
                val expectedAccept = computeAcceptKey(wsKey)
                while (true) {
                    val line = readHeaderLine(inStream) ?: break
                    if (line.isEmpty()) break
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        val name = line.substring(0, colon).trim()
                        val value = line.substring(colon + 1).trim()
                        if (name.equals("Sec-WebSocket-Accept", ignoreCase = true) && value == expectedAccept) {
                            acceptOk = true
                        }
                    }
                }
                if (!acceptOk) {
                    throw IOException("کلید Sec-WebSocket-Accept نامعتبر است.")
                }

                sslSocket.soTimeout = 0
                return RawWebSocket(sslSocket, preBufferedInput = inStream)
            } catch (t: Throwable) {
                lastError = t
                runCatching { rawSocket.close() }
            }
        }
        throw lastError ?: IOException("اتصال به $connectHost:$connectPort ناموفق بود.")
    }

    private fun resolvePreferIpv4(host: String): List<InetAddress> {
        val clean = host.trim().removePrefix("[").removeSuffix("]")
        val literal = parseLiteralIp(clean)
        if (literal != null) return listOf(literal)

        val now = System.currentTimeMillis()
        val cached = resolvedHostCache[clean]
        if (cached != null && (now - cached.first) < DNS_CACHE_TTL_MS) {
            return cached.second
        }

        val all = InetAddress.getAllByName(clean).toList()
        val ordered = if (all.size <= 1) {
            all
        } else {
            val v4 = all.filterIsInstance<Inet4Address>()
            val v6 = all.filterIsInstance<Inet6Address>()
            (v4 + v6).take(3)
        }
        resolvedHostCache[clean] = now to ordered
        return ordered
    }

    private fun parseLiteralIp(host: String): InetAddress? {
        if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
            val parts = host.split(".").mapNotNull { it.toIntOrNull() }
            if (parts.size == 4 && parts.all { it in 0..255 }) {
                return InetAddress.getByAddress(parts.map { it.toByte() }.toByteArray())
            }
        }
        if (host.contains(":")) {
            return runCatching { InetAddress.getByName(host) }.getOrNull()
        }
        return null
    }

    fun openTunnel(
        uuid: String,
        workerHost: String,
        cleanIp: String,
        subproto: String,
        targetHost: String,
        targetPort: Int,
        initialPayload: ByteArray = ByteArray(0),
        socketProtector: ((Socket) -> Boolean)? = null,
        ackTimeoutOverrideMs: Int? = null,
    ): WorkerTunnelSession {
        val pooledWs = WorkerWsPool.acquire(workerHost, cleanIp, subproto)
        if (pooledWs != null) {
            try {
                return performHandshake(
                    ws = pooledWs,
                    uuid = uuid,
                    targetHost = targetHost,
                    targetPort = targetPort,
                    initialPayload = initialPayload,
                    ackTimeoutMs = ackTimeoutOverrideMs ?: POOLED_ACK_TIMEOUT_MS,
                )
            } catch (_: Throwable) {
                pooledWs.close()
            }
        }

        val fresh = connectRawWebSocket(workerHost, cleanIp, subproto, socketProtector)
        return try {
            performHandshake(
                ws = fresh,
                uuid = uuid,
                targetHost = targetHost,
                targetPort = targetPort,
                initialPayload = initialPayload,
                ackTimeoutMs = ackTimeoutOverrideMs ?: WorkerDefaults.ACK_TIMEOUT_MS.toInt(),
            )
        } catch (t: Throwable) {
            fresh.close()
            throw t
        }
    }

    private fun performHandshake(
        ws: RawWebSocket,
        uuid: String,
        targetHost: String,
        targetPort: Int,
        initialPayload: ByteArray,
        ackTimeoutMs: Int,
    ): WorkerTunnelSession {
        val init = WorkerCrypto.buildInit(uuid, targetHost, targetPort, initialPayload)
        ws.setReadTimeout(ackTimeoutMs)
        if (!ws.sendBinary(init.data, xorKey = null)) {
            throw IOException("ارسال بسته اولیه به سرور Worker ناموفق بود.")
        }

        val decAck = ws.readMessage(xorKey = init.key)
            ?: throw IOException("اتصال پیش از دریافت ACK بسته شد.")
        if (decAck.size < 16 || !decAck.copyOfRange(0, 16).contentEquals(WorkerCrypto.expectedAck(init.key))) {
            throw IOException("تأیید هویت HMAC سرور Worker ناموفق بود (UUID نامعتبر).")
        }
        ws.setReadTimeout(0)
        return WorkerTunnelSession(ws, init.key)
    }

    private fun readHeaderLine(input: java.io.InputStream): String? {
        val buf = ByteArrayOutputStream(128)
        while (true) {
            val b = input.read()
            if (b == -1) return if (buf.size() == 0) null else buf.toString("US-ASCII")
            if (b == '\n'.code) {
                val bytes = buf.toByteArray()
                val len = if (bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) {
                    bytes.size - 1
                } else {
                    bytes.size
                }
                return String(bytes, 0, len, Charsets.US_ASCII)
            }
            buf.write(b)
            if (buf.size() > 8192) throw IOException("طول هدر HTTP بیش از حد مجاز است.")
        }
    }

    private fun computeAcceptKey(wsKey: String): String {
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest((wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.US_ASCII))
        return encodeBase64(sha1)
    }

    private const val B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    private fun encodeBase64(data: ByteArray): String {
        val out = StringBuilder(((data.size + 2) / 3) * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xFF else 0
            out.append(B64_CHARS[b0 ushr 2])
            out.append(B64_CHARS[((b0 and 0x03) shl 4) or (b1 ushr 4)])
            out.append(if (i + 1 < data.size) B64_CHARS[((b1 and 0x0F) shl 2) or (b2 ushr 6)] else '=')
            out.append(if (i + 2 < data.size) B64_CHARS[b2 and 0x3F] else '=')
            i += 3
        }
        return out.toString()
    }
}
