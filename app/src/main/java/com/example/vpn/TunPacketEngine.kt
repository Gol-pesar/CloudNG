package com.example.vpn

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.network.Socks5Client
import com.example.worker.WorkerTunnelSession
import com.example.worker.WorkerWsClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

/**
 * Xray-style pure-Kotlin userspace IPv4 / TCP / UDP(DNS) + ICMP(QUIC reject) TUN packet engine.
 * Features instant SYN-ACK, duplicate SYN deduplication, 0-RTT initialPayload piggybacking,
 * TCP out-of-order reassembly, DNS caching, and ICMP port-unreachable fast fallback for QUIC.
 */
class TunPacketEngine(
    private val scope: CoroutineScope,
    private val profile: ProxyProfile,
    private val dnsServer: String,
    private val remoteDnsOverTcp: Boolean,
    private val tunOutput: FileOutputStream,
    private val protectSocket: (Socket) -> Boolean,
) {
    private data class SessionKey(
        val srcIp: Int,
        val srcPort: Int,
        val dstIp: Int,
        val dstPort: Int,
    )

    private data class DnsCacheEntry(
        val responseWithoutTxId: ByteArray,
        val expiresAtMs: Long,
    )

    private class TcpSession(
        val key: SessionKey,
        val srcIpBytes: ByteArray,
        val dstIpBytes: ByteArray,
        clientNextSeqInit: Long,
        val initialServerSeq: Long,
    ) {
        val lock = Any()
        var clientNextSeq: Long = clientNextSeqInit
        var serverSeq: Long = (initialServerSeq + 1L) and 0xFFFFFFFFL
        var peerAck: Long = initialServerSeq
        var peerWindow: Int = 65535
        var socket: Socket? = null
        var workerSession: WorkerTunnelSession? = null
        var txChannel: Channel<ByteArray>? = null
        var readerJob: Job? = null
        val closed = AtomicBoolean(false)
        val established = AtomicBoolean(false)
        var clientFinReceived = false
        val firstPayloadSignal = CompletableDeferred<Unit>()
        val pendingTx = ArrayDeque<ByteArray>()
        val outOfOrder = TreeMap<Long, ByteArray> { a, b -> (a.toInt() - b.toInt()) }
    }

    private val tcpSessions = ConcurrentHashMap<SessionKey, TcpSession>()
    private val dnsCache = ConcurrentHashMap<String, DnsCacheEntry>()
    private val writeLock = Any()
    private val ipIdCounter = AtomicInteger(1)
    @OptIn(ExperimentalCoroutinesApi::class)
    private val tunnelDispatcher = Dispatchers.IO.limitedParallelism(128)

    fun processPacket(packet: ByteArray, length: Int) {
        if (length < 20) return
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return

        val totalLength = readU16(packet, 2).coerceAtMost(length)
        val protocol = packet[9].toInt() and 0xFF
        val srcIpBytes = packet.copyOfRange(12, 16)
        val dstIpBytes = packet.copyOfRange(16, 20)
        val srcIpInt = readI32(packet, 12)
        val dstIpInt = readI32(packet, 16)

        when (protocol) {
            PROTO_TCP -> handleTcpPacket(packet, ihl, totalLength, srcIpInt, dstIpInt, srcIpBytes, dstIpBytes)
            PROTO_UDP -> handleUdpPacket(packet, ihl, totalLength, srcIpBytes, dstIpBytes)
        }
    }

    private fun handleTcpPacket(
        packet: ByteArray,
        ihl: Int,
        totalLength: Int,
        srcIpInt: Int,
        dstIpInt: Int,
        srcIpBytes: ByteArray,
        dstIpBytes: ByteArray,
    ) {
        if (totalLength < ihl + 20) return
        val srcPort = readU16(packet, ihl)
        val dstPort = readU16(packet, ihl + 2)
        val seq = readU32(packet, ihl + 4)
        val ackNum = readU32(packet, ihl + 8)
        val dataOffset = ((packet[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffset < 20 || totalLength < ihl + dataOffset) return

        val flags = packet[ihl + 13].toInt() and 0xFF
        val window = readU16(packet, ihl + 14)
        val isSyn = (flags and FLAG_SYN) != 0
        val isAck = (flags and FLAG_ACK) != 0
        val isFin = (flags and FLAG_FIN) != 0
        val isRst = (flags and FLAG_RST) != 0

        val payloadStart = ihl + dataOffset
        val payloadLen = (totalLength - payloadStart).coerceAtLeast(0)
        val payload = if (payloadLen > 0) packet.copyOfRange(payloadStart, payloadStart + payloadLen) else ByteArray(0)

        val key = SessionKey(srcIpInt, srcPort, dstIpInt, dstPort)

        if (isRst) {
            closeSession(key, sendRst = false)
            return
        }

        if (isSyn && !isAck) {
            val existing = tcpSessions[key]
            if (existing != null && !existing.closed.get()) {
                // Retransmitted SYN: re-acknowledge immediately without killing the active tunnel!
                sendTcpSynAck(existing, existing.initialServerSeq, existing.clientNextSeq)
                return
            }

            val initialServerSeq = (Random.nextInt() and 0x7FFFFFFF).toLong()
            val clientNextSeq = (seq + 1L) and 0xFFFFFFFFL
            val session = TcpSession(
                key = key,
                srcIpBytes = srcIpBytes,
                dstIpBytes = dstIpBytes,
                clientNextSeqInit = clientNextSeq,
                initialServerSeq = initialServerSeq,
            )
            tcpSessions[key] = session

            // Reply SYN-ACK immediately (<1ms) so browser sends TLS ClientHello right away
            sendTcpSynAck(session, initialServerSeq, clientNextSeq)

            val dstHost = InetAddress.getByAddress(dstIpBytes).hostAddress ?: return
            session.readerJob = scope.launch(tunnelDispatcher) {
                if (profile.profileType == ProfileType.WORKER_WS) {
                    openWorkerTcpTunnel(session, dstHost, dstPort)
                } else {
                    openSocks5TcpTunnel(session, dstHost, dstPort)
                }
            }
            return
        }

        val session = tcpSessions[key] ?: return
        if (session.closed.get()) return

        var contiguousPayload: ByteArray? = null
        var ackToSend = 0L
        var serverSeqSnap = 0L
        var sendAck = false
        var establishedNow = false
        var socketToWrite: Socket? = null
        var txChanToWrite: Channel<ByteArray>? = null

        synchronized(session.lock) {
            if (isAck) {
                session.peerAck = ackNum
                session.peerWindow = window.coerceAtLeast(1400)
            }

            if (payload.isNotEmpty()) {
                val diff = seq.toInt() - session.clientNextSeq.toInt()
                if (diff == 0) {
                    val merged = ByteArrayOutputStream(payload.size)
                    merged.write(payload)
                    session.clientNextSeq = (session.clientNextSeq + payload.size.toLong()) and 0xFFFFFFFFL
                    drainOutOfOrderLocked(session, merged)
                    contiguousPayload = merged.toByteArray()
                } else if (diff < 0) {
                    val overlap = -diff
                    if (overlap < payload.size) {
                        val tail = payload.copyOfRange(overlap, payload.size)
                        val merged = ByteArrayOutputStream(tail.size)
                        merged.write(tail)
                        session.clientNextSeq = (session.clientNextSeq + tail.size.toLong()) and 0xFFFFFFFFL
                        drainOutOfOrderLocked(session, merged)
                        contiguousPayload = merged.toByteArray()
                    }
                } else if (diff in 1..2_000_000 && session.outOfOrder.size < 64) {
                    session.outOfOrder[seq] = payload
                }

                val dataReady = contiguousPayload
                if (dataReady != null && dataReady.isNotEmpty()) {
                    if (session.established.get()) {
                        establishedNow = true
                        socketToWrite = session.socket
                        txChanToWrite = session.txChannel
                    } else {
                        session.pendingTx.addLast(dataReady)
                        session.firstPayloadSignal.complete(Unit)
                    }
                }

                ackToSend = session.clientNextSeq
                serverSeqSnap = session.serverSeq
                sendAck = true
            }
        }

        if (sendAck) {
            sendTcpControlPacket(
                session = session,
                flags = FLAG_ACK,
                seq = serverSeqSnap,
                ack = ackToSend,
                payload = ByteArray(0),
            )
        }

        val readyData = contiguousPayload
        if (readyData != null && readyData.isNotEmpty()) {
            VpnStateManager.recordTx(readyData.size)
            if (establishedNow) {
                if (socketToWrite != null) {
                    scope.launch(tunnelDispatcher) {
                        runCatching {
                            val out = socketToWrite!!.getOutputStream()
                            out.write(readyData)
                            out.flush()
                        }.onFailure {
                            closeSession(key, sendRst = true)
                        }
                    }
                } else if (txChanToWrite != null) {
                    txChanToWrite!!.trySend(readyData)
                }
            }
        }

        if (isFin) {
            val ackForFin: Long
            val srvSeq: Long
            var chanToClose: Channel<ByteArray>? = null
            var sockToShutdown: Socket? = null
            synchronized(session.lock) {
                val expectedFinSeq = (seq + payload.size.toLong()) and 0xFFFFFFFFL
                if (expectedFinSeq == session.clientNextSeq || payload.isEmpty()) {
                    session.clientNextSeq = (session.clientNextSeq + 1L) and 0xFFFFFFFFL
                }
                ackForFin = session.clientNextSeq
                srvSeq = session.serverSeq
                session.clientFinReceived = true
                chanToClose = session.txChannel
                sockToShutdown = session.socket
            }
            sendTcpControlPacket(
                session = session,
                flags = FLAG_ACK,
                seq = srvSeq,
                ack = ackForFin,
                payload = ByteArray(0),
            )
            // Support TCP half-close: stop upstream writes while keeping downstream reads open until server finishes
            chanToClose?.close()
            if (sockToShutdown != null) {
                runCatching { sockToShutdown?.shutdownOutput() }
            }
        }
    }

    private fun drainOutOfOrderLocked(session: TcpSession, out: ByteArrayOutputStream) {
        while (session.outOfOrder.isNotEmpty()) {
            val firstKey = session.outOfOrder.firstKey()
            val diff = firstKey.toInt() - session.clientNextSeq.toInt()
            if (diff > 0) break
            val seg = session.outOfOrder.remove(firstKey) ?: break
            val overlap = -diff
            if (overlap < seg.size) {
                val len = seg.size - overlap
                out.write(seg, overlap, len)
                session.clientNextSeq = (session.clientNextSeq + len.toLong()) and 0xFFFFFFFFL
            }
        }
    }

    private suspend fun openWorkerTcpTunnel(session: TcpSession, dstHost: String, dstPort: Int) {
        var counted = false
        try {
            // Wait briefly (max 15ms; returns immediately on first packet) ONLY to sniff TLS SNI / HTTP Host
            // Keep payload in pendingTx so it is transmitted via sendPlain() AFTER Worker ACK (matching Cl2.py)
            withTimeoutOrNull(15L) { session.firstPayloadSignal.await() }
            if (session.closed.get()) return

            val sniffedHost = synchronized(session.lock) {
                session.pendingTx.firstOrNull()?.let { firstChunk ->
                    TrafficSniffer.sniffDomain(firstChunk, dstPort)
                }
            }
            val effectiveTargetHost = when {
                sniffedHost != null -> sniffedHost
                (dstPort == 53 || dstPort == 853) && (dstHost == "1.1.1.1" || dstHost == "1.0.0.1") -> "8.8.8.8"
                else -> dstHost
            }

            val wsSession = WorkerWsClient.openTunnel(
                uuid = profile.uuid,
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                targetHost = effectiveTargetHost,
                targetPort = dstPort,
                initialPayload = ByteArray(0),
                socketProtector = protectSocket,
            )
            if (session.closed.get()) {
                wsSession.close()
                return
            }

            VpnStateManager.incrementActiveConnections()
            counted = true
            VpnStateManager.addLog(LogLevel.INFO, "WS", "اتصال $effectiveTargetHost:$dstPort")

            val chan = Channel<ByteArray>(capacity = Channel.UNLIMITED)
            val remainingPayloads = mutableListOf<ByteArray>()
            var finAlreadyReceived = false
            synchronized(session.lock) {
                session.workerSession = wsSession
                session.txChannel = chan
                session.established.set(true)
                finAlreadyReceived = session.clientFinReceived
                while (session.pendingTx.isNotEmpty()) {
                    remainingPayloads.add(session.pendingTx.removeFirst())
                }
            }

            for (chunk in remainingPayloads) {
                if (!wsSession.sendPlain(chunk)) break
            }
            if (finAlreadyReceived) {
                chan.close()
            }

            val upJob = scope.launch(tunnelDispatcher) {
                try {
                    for (chunk in chan) {
                        if (session.closed.get()) break
                        if (!wsSession.sendPlain(chunk)) break
                    }
                } catch (_: Throwable) {
                }
            }

            while (!session.closed.get()) {
                val dec = wsSession.readPlain() ?: break
                if (dec.isEmpty()) continue
                VpnStateManager.recordRx(dec.size)

                var offset = 0
                while (offset < dec.size && !session.closed.get()) {
                    val end = (offset + 1400).coerceAtMost(dec.size)
                    val slice = dec.copyOfRange(offset, end)
                    val isLastSlice = end >= dec.size
                    val seqSnap: Long
                    val ackSnap: Long
                    synchronized(session.lock) {
                        seqSnap = session.serverSeq
                        ackSnap = session.clientNextSeq
                        session.serverSeq = (session.serverSeq + slice.size.toLong()) and 0xFFFFFFFFL
                    }
                    sendTcpControlPacket(
                        session = session,
                        flags = if (isLastSlice) (FLAG_PSH or FLAG_ACK) else FLAG_ACK,
                        seq = seqSnap,
                        ack = ackSnap,
                        payload = slice,
                    )
                    offset = end
                }
            }
            upJob.cancel()

            if (!session.closed.get()) {
                val finSeq: Long
                val finAck: Long
                synchronized(session.lock) {
                    finSeq = session.serverSeq
                    finAck = session.clientNextSeq
                    session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                }
                sendTcpControlPacket(
                    session = session,
                    flags = FLAG_FIN or FLAG_ACK,
                    seq = finSeq,
                    ack = finAck,
                    payload = ByteArray(0),
                )
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            if (!session.closed.get()) {
                VpnStateManager.addLog(
                    LogLevel.WARNING,
                    "WS",
                    "خطا در $dstHost:$dstPort — ${t.localizedMessage ?: "ناموفق"}",
                )
                sendRst(session)
            }
        } finally {
            if (counted) VpnStateManager.decrementActiveConnections()
            closeSession(session.key, sendRst = false)
        }
    }

    private suspend fun openSocks5TcpTunnel(session: TcpSession, dstHost: String, dstPort: Int) {
        var counted = false
        try {
            withTimeoutOrNull(35L) { session.firstPayloadSignal.await() }
            if (session.closed.get()) return

            val initialMerged = ByteArrayOutputStream()
            synchronized(session.lock) {
                while (session.pendingTx.isNotEmpty()) {
                    initialMerged.write(session.pendingTx.removeFirst())
                }
            }
            val initialPayload = initialMerged.toByteArray()
            val effectiveTargetHost = TrafficSniffer.sniffDomain(initialPayload, dstPort) ?: dstHost

            val socket = Socks5Client.connect(
                proxyHost = profile.host,
                proxyPort = profile.port,
                username = profile.username,
                password = profile.password,
                useAuth = profile.useAuth,
                targetHost = effectiveTargetHost,
                targetPort = dstPort,
                timeoutMs = 10_000,
                socketProtector = protectSocket,
            )
            socket.soTimeout = 0
            if (session.closed.get()) {
                runCatching { socket.close() }
                return
            }

            VpnStateManager.incrementActiveConnections()
            counted = true
            VpnStateManager.addLog(LogLevel.INFO, "TCP", "اتصال $effectiveTargetHost:$dstPort از طریق SOCKS5")

            val bufferedPayloads = mutableListOf<ByteArray>()
            var finAlreadyReceived = false
            synchronized(session.lock) {
                session.socket = socket
                session.established.set(true)
                finAlreadyReceived = session.clientFinReceived
                while (session.pendingTx.isNotEmpty()) {
                    bufferedPayloads.add(session.pendingTx.removeFirst())
                }
            }

            if (initialPayload.isNotEmpty() || bufferedPayloads.isNotEmpty()) {
                val out = socket.getOutputStream()
                if (initialPayload.isNotEmpty()) out.write(initialPayload)
                for (chunk in bufferedPayloads) out.write(chunk)
                out.flush()
            }
            if (finAlreadyReceived) {
                runCatching { socket.shutdownOutput() }
            }

            val input: InputStream = socket.getInputStream()
            val buffer = ByteArray(1400)
            while (!session.closed.get()) {
                val read = input.read(buffer)
                if (read <= 0) break
                val chunk = buffer.copyOf(read)
                VpnStateManager.recordRx(read)

                val seqSnap: Long
                val ackSnap: Long
                synchronized(session.lock) {
                    seqSnap = session.serverSeq
                    ackSnap = session.clientNextSeq
                    session.serverSeq = (session.serverSeq + read.toLong()) and 0xFFFFFFFFL
                }
                sendTcpControlPacket(
                    session = session,
                    flags = FLAG_PSH or FLAG_ACK,
                    seq = seqSnap,
                    ack = ackSnap,
                    payload = chunk,
                )
            }

            if (!session.closed.get()) {
                val finSeq: Long
                val finAck: Long
                synchronized(session.lock) {
                    finSeq = session.serverSeq
                    finAck = session.clientNextSeq
                    session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                }
                sendTcpControlPacket(
                    session = session,
                    flags = FLAG_FIN or FLAG_ACK,
                    seq = finSeq,
                    ack = finAck,
                    payload = ByteArray(0),
                )
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            if (!session.closed.get()) {
                VpnStateManager.addLog(
                    LogLevel.WARNING,
                    "TCP",
                    "خطای اتصال به $dstHost:$dstPort — ${t.localizedMessage ?: "ناموفق"}",
                )
                sendRst(session)
            }
        } finally {
            if (counted) VpnStateManager.decrementActiveConnections()
            closeSession(session.key, sendRst = false)
        }
    }

    private fun handleUdpPacket(
        packet: ByteArray,
        ihl: Int,
        totalLength: Int,
        srcIpBytes: ByteArray,
        dstIpBytes: ByteArray,
    ) {
        if (totalLength < ihl + 8) return
        val srcPort = readU16(packet, ihl)
        val dstPort = readU16(packet, ihl + 2)
        val udpLen = readU16(packet, ihl + 4)
        if (udpLen < 8 || totalLength < ihl + udpLen) return

        // Fast-reject QUIC (UDP:443) via ICMP Port Unreachable so Chrome switches to TCP HTTPS in 0ms
        if (dstPort == 443) {
            sendIcmpPortUnreachable(
                origPacket = packet,
                origIhl = ihl,
                origTotalLen = totalLength,
                srcIp = dstIpBytes,
                dstIp = srcIpBytes,
            )
            return
        }

        if (dstPort != 53 || !remoteDnsOverTcp) return
        val payload = packet.copyOfRange(ihl + 8, ihl + udpLen)
        if (payload.size < 12) return

        // Serve from in-memory DNS cache if fresh
        val cacheKey = payload.copyOfRange(2, payload.size).joinToString("") { "%02x".format(it) }
        val now = System.currentTimeMillis()
        val cached = dnsCache[cacheKey]
        if (cached != null && cached.expiresAtMs > now) {
            val resp = ByteArray(2 + cached.responseWithoutTxId.size)
            resp[0] = payload[0]
            resp[1] = payload[1]
            System.arraycopy(cached.responseWithoutTxId, 0, resp, 2, cached.responseWithoutTxId.size)
            writeUdpPacketToTun(
                srcIp = dstIpBytes,
                srcPort = 53,
                dstIp = srcIpBytes,
                dstPort = srcPort,
                payload = resp,
            )
            return
        }

        val targetDnsIp = InetAddress.getByAddress(dstIpBytes).hostAddress ?: dnsServer
        scope.launch(tunnelDispatcher) {
            if (profile.profileType == ProfileType.WORKER_WS) {
                forwardDnsOverWorkerTcp(srcIpBytes, srcPort, dstIpBytes, targetDnsIp, payload, cacheKey)
            } else {
                forwardDnsOverSocks5Tcp(srcIpBytes, srcPort, dstIpBytes, targetDnsIp, payload, cacheKey)
            }
        }
    }

    private fun forwardDnsOverWorkerTcp(
        clientIpBytes: ByteArray,
        clientPort: Int,
        dnsIpBytes: ByteArray,
        targetDnsHost: String,
        dnsQuery: ByteArray,
        cacheKey: String,
    ) {
        try {
            VpnStateManager.recordTx(dnsQuery.size)
            val framed = ByteArray(2 + dnsQuery.size)
            framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
            framed[1] = (dnsQuery.size and 0xFF).toByte()
            System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)

            val effectiveDnsHost = if (targetDnsHost == "1.1.1.1" || targetDnsHost == "1.0.0.1") {
                "8.8.8.8"
            } else {
                targetDnsHost
            }

            val wsSession = WorkerWsClient.openTunnel(
                uuid = profile.uuid,
                workerHost = profile.workerHost,
                cleanIp = profile.cleanIp,
                subproto = profile.subproto,
                targetHost = effectiveDnsHost,
                targetPort = 53,
                initialPayload = ByteArray(0),
                socketProtector = protectSocket,
            )
            try {
                if (!wsSession.sendPlain(framed)) return
                val acc = ByteArrayOutputStream()
                while (true) {
                    val chunk = wsSession.readPlain() ?: break
                    acc.write(chunk)
                    val bytes = acc.toByteArray()
                    if (bytes.size >= 2) {
                        val expectedLen = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
                        if (bytes.size >= 2 + expectedLen && expectedLen in 12..4096) {
                            val dnsResp = bytes.copyOfRange(2, 2 + expectedLen)
                            VpnStateManager.recordRx(dnsResp.size)
                            cacheDnsResponse(cacheKey, dnsResp)
                            writeUdpPacketToTun(
                                srcIp = dnsIpBytes,
                                srcPort = 53,
                                dstIp = clientIpBytes,
                                dstPort = clientPort,
                                payload = dnsResp,
                            )
                            break
                        }
                    }
                }
            } finally {
                wsSession.close()
            }
        } catch (_: Throwable) {
        }
    }

    private fun forwardDnsOverSocks5Tcp(
        clientIpBytes: ByteArray,
        clientPort: Int,
        dnsIpBytes: ByteArray,
        targetDnsHost: String,
        dnsQuery: ByteArray,
        cacheKey: String,
    ) {
        try {
            VpnStateManager.recordTx(dnsQuery.size)
            Socks5Client.connect(
                proxyHost = profile.host,
                proxyPort = profile.port,
                username = profile.username,
                password = profile.password,
                useAuth = profile.useAuth,
                targetHost = targetDnsHost,
                targetPort = 53,
                timeoutMs = 6000,
                socketProtector = protectSocket,
            ).use { socket ->
                val out = socket.getOutputStream()
                val framed = ByteArray(2 + dnsQuery.size)
                framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
                framed[1] = (dnsQuery.size and 0xFF).toByte()
                System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)
                out.write(framed)
                out.flush()

                val input = DataInputStream(socket.getInputStream())
                val respLen = input.readUnsignedShort()
                if (respLen in 12..4096) {
                    val dnsResp = ByteArray(respLen)
                    input.readFully(dnsResp)
                    VpnStateManager.recordRx(dnsResp.size)
                    cacheDnsResponse(cacheKey, dnsResp)
                    writeUdpPacketToTun(
                        srcIp = dnsIpBytes,
                        srcPort = 53,
                        dstIp = clientIpBytes,
                        dstPort = clientPort,
                        payload = dnsResp,
                    )
                }
            }
        } catch (_: Throwable) {
        }
    }

    private fun cacheDnsResponse(cacheKey: String, dnsResp: ByteArray) {
        if (dnsResp.size < 12) return
        if (dnsCache.size > 512) dnsCache.clear()
        dnsCache[cacheKey] = DnsCacheEntry(
            responseWithoutTxId = dnsResp.copyOfRange(2, dnsResp.size),
            expiresAtMs = System.currentTimeMillis() + 60_000L,
        )
    }

    fun closeAll() {
        val keys = tcpSessions.keys.toList()
        for (k in keys) {
            closeSession(k, sendRst = false)
        }
        dnsCache.clear()
    }

    private fun closeSession(key: SessionKey, sendRst: Boolean) {
        val session = tcpSessions.remove(key) ?: return
        if (session.closed.compareAndSet(false, true)) {
            session.firstPayloadSignal.complete(Unit)
            if (sendRst) sendRst(session)
            session.txChannel?.close()
            runCatching { session.socket?.close() }
            session.workerSession?.close()
            session.readerJob?.cancel()
        }
    }

    private fun sendRst(session: TcpSession) {
        val seqSnap: Long
        val ackSnap: Long
        synchronized(session.lock) {
            seqSnap = session.serverSeq
            ackSnap = session.clientNextSeq
        }
        sendTcpControlPacket(
            session = session,
            flags = FLAG_RST or FLAG_ACK,
            seq = seqSnap,
            ack = ackSnap,
            payload = ByteArray(0),
        )
    }

    private fun sendTcpSynAck(session: TcpSession, seq: Long, ack: Long) {
        val options = byteArrayOf(0x02, 0x04, 0x05, 0x78) // MSS = 1400
        writeTcpPacketToTun(
            srcIp = session.dstIpBytes,
            srcPort = session.key.dstPort,
            dstIp = session.srcIpBytes,
            dstPort = session.key.srcPort,
            seq = seq,
            ack = ack,
            flags = FLAG_SYN or FLAG_ACK,
            options = options,
            payload = ByteArray(0),
        )
    }

    private fun sendTcpControlPacket(
        session: TcpSession,
        flags: Int,
        seq: Long,
        ack: Long,
        payload: ByteArray,
    ) {
        writeTcpPacketToTun(
            srcIp = session.dstIpBytes,
            srcPort = session.key.dstPort,
            dstIp = session.srcIpBytes,
            dstPort = session.key.srcPort,
            seq = seq,
            ack = ack,
            flags = flags,
            options = ByteArray(0),
            payload = payload,
        )
    }

    private fun sendIcmpPortUnreachable(
        origPacket: ByteArray,
        origIhl: Int,
        origTotalLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
    ) {
        val quotedLen = (origIhl + 8).coerceAtMost(origTotalLen)
        val icmpLen = 8 + quotedLen
        val totalLen = 20 + icmpLen
        val pkt = ByteArray(totalLen)

        fillIpHeader(pkt, totalLen, PROTO_ICMP, srcIp, dstIp)

        val ic = 20
        pkt[ic] = 3.toByte() // Destination Unreachable
        pkt[ic + 1] = 3.toByte() // Port Unreachable
        writeU16(pkt, ic + 2, 0)
        writeU32(pkt, ic + 4, 0L)
        System.arraycopy(origPacket, 0, pkt, ic + 8, quotedLen)

        val icmpChecksum = onesComplementChecksum(pkt, ic, icmpLen)
        writeU16(pkt, ic + 2, icmpChecksum)
        writePacketToTun(pkt)
    }

    private fun writeTcpPacketToTun(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        options: ByteArray,
        payload: ByteArray,
    ) {
        val tcpHeaderLen = 20 + options.size
        val totalLen = 20 + tcpHeaderLen + payload.size
        val pkt = ByteArray(totalLen)

        fillIpHeader(pkt, totalLen, PROTO_TCP, srcIp, dstIp)

        val t = 20
        writeU16(pkt, t, srcPort)
        writeU16(pkt, t + 2, dstPort)
        writeU32(pkt, t + 4, seq)
        writeU32(pkt, t + 8, ack)
        pkt[t + 12] = (((tcpHeaderLen / 4) shl 4) and 0xF0).toByte()
        pkt[t + 13] = (flags and 0xFF).toByte()
        writeU16(pkt, t + 14, 65535)
        writeU16(pkt, t + 16, 0)
        writeU16(pkt, t + 18, 0)

        if (options.isNotEmpty()) System.arraycopy(options, 0, pkt, t + 20, options.size)
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, pkt, t + tcpHeaderLen, payload.size)

        val tcpChecksum = computeTransportChecksum(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTO_TCP,
            transportBytes = pkt,
            offset = t,
            length = tcpHeaderLen + payload.size,
        )
        writeU16(pkt, t + 16, tcpChecksum)

        writePacketToTun(pkt)
    }

    private fun writeUdpPacketToTun(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ) {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)

        fillIpHeader(pkt, totalLen, PROTO_UDP, srcIp, dstIp)

        val u = 20
        writeU16(pkt, u, srcPort)
        writeU16(pkt, u + 2, dstPort)
        writeU16(pkt, u + 4, udpLen)
        writeU16(pkt, u + 6, 0)
        System.arraycopy(payload, 0, pkt, u + 8, payload.size)

        val udpChecksum = computeTransportChecksum(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTO_UDP,
            transportBytes = pkt,
            offset = u,
            length = udpLen,
        )
        writeU16(pkt, u + 6, if (udpChecksum == 0) 0xFFFF else udpChecksum)

        writePacketToTun(pkt)
    }

    private fun fillIpHeader(
        pkt: ByteArray,
        totalLen: Int,
        protocol: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
    ) {
        pkt[0] = 0x45.toByte()
        pkt[1] = 0x00
        writeU16(pkt, 2, totalLen)
        writeU16(pkt, 4, ipIdCounter.getAndIncrement() and 0xFFFF)
        writeU16(pkt, 6, 0x4000)
        pkt[8] = 64.toByte()
        pkt[9] = (protocol and 0xFF).toByte()
        writeU16(pkt, 10, 0)
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        val ipChecksum = onesComplementChecksum(pkt, 0, 20)
        writeU16(pkt, 10, ipChecksum)
    }

    private fun writePacketToTun(pkt: ByteArray) {
        synchronized(writeLock) {
            runCatching { tunOutput.write(pkt) }
        }
    }

    private fun computeTransportChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        transportBytes: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        val pseudo = ByteArrayOutputStream(12 + length)
        pseudo.write(srcIp)
        pseudo.write(dstIp)
        pseudo.write(0)
        pseudo.write(protocol and 0xFF)
        pseudo.write((length ushr 8) and 0xFF)
        pseudo.write(length and 0xFF)
        pseudo.write(transportBytes, offset, length)
        val combined = pseudo.toByteArray()
        return onesComplementChecksum(combined, 0, combined.size)
    }

    private fun onesComplementChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word.toLong()
            i += 2
        }
        if (i < end) sum += ((buf[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFFL).toInt()
    }

    private fun readU16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readU32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
            ((buf[offset + 1].toLong() and 0xFF) shl 16) or
            ((buf[offset + 2].toLong() and 0xFF) shl 8) or
            (buf[offset + 3].toLong() and 0xFF)

    private fun readI32(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 24) or
            ((buf[offset + 1].toInt() and 0xFF) shl 16) or
            ((buf[offset + 2].toInt() and 0xFF) shl 8) or
            (buf[offset + 3].toInt() and 0xFF)

    private fun writeU16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value ushr 24) and 0xFF).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 3] = (value and 0xFF).toByte()
    }

    companion object {
        private const val PROTO_ICMP = 1
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17
        private const val FLAG_FIN = 0x01
        private const val FLAG_SYN = 0x02
        private const val FLAG_RST = 0x04
        private const val FLAG_PSH = 0x08
        private const val FLAG_ACK = 0x10
    }
}
