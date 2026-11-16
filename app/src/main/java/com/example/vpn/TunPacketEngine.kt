package com.example.vpn

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.network.Socks5Client
import com.example.worker.WorkerDefaults
import com.example.worker.WorkerTunnelSession
import com.example.worker.WorkerWsClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * High-speed pure-Kotlin userspace IPv4/IPv6 -> TCP / UDP(DNS) + ICMP(QUIC reject) TUN engine.
 * Optimizations for real Android mobile/WiFi networks:
 * - Non-blocking single-writer TUN output channel + zero-allocation checksums
 * - Real 40ms RTO retransmission timer + Fast Retransmit + Slow-Start congestion window (cwnd)
 * - Pipelined rxChannel decoupling WebSocket/SOCKS5 reads from TUN TCP flow control
 * - Ordered upload channel for both Worker WS and Standard SOCKS5 (64KB coalescing + proactive window updates)
 * - 120ms SNI peek + multi-segment Post-Quantum TLS ClientHello coalescing
 * - Persistent reusable Worker TCP:53 DNS tunnel + in-flight deduplication + 0ms AAAA NOERROR fast-path
 * - 0ms IPv6 TCP RST / ICMPv6 Port Unreachable fast fallback to eliminate carrier IPv6 stalls
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

    private class UnackedSegment(
        val seq: Long,
        val data: ByteArray,
        var sentAtMs: Long,
        var retries: Int = 0,
    )

    private class TcpSession(
        val key: SessionKey,
        val srcIpBytes: ByteArray,
        val dstIpBytes: ByteArray,
        val clientInitSeq: Long,
        clientNextSeqInit: Long,
        val initialServerSeq: Long,
        val useWindowScale: Boolean,
        val clientWindowShift: Int,
        initialPeerWindowBytes: Long,
    ) {
        val lock = Any()
        var clientNextSeq: Long = clientNextSeqInit
        var sendBase: Long = (initialServerSeq + 1L) and 0xFFFFFFFFL
        var serverSeq: Long = (initialServerSeq + 1L) and 0xFFFFFFFFL
        var peerWindowBytes: Long = initialPeerWindowBytes
        var cwndBytes: Long = INITIAL_CWND_BYTES
        var rtoMs: Long = INITIAL_RTO_MS
        var dupAckCount: Int = 0
        var lastAdvertisedWinBytes: Int = MAX_UPSTREAM_BUFFER_BYTES
        var socket: Socket? = null
        var workerSession: WorkerTunnelSession? = null
        var txChannel: Channel<ByteArray>? = null
        var readerJob: Job? = null
        val closed = AtomicBoolean(false)
        val established = AtomicBoolean(false)
        var clientFinReceived = false
        val firstPayloadSignal = CompletableDeferred<Unit>()
        val secondPayloadSignal = CompletableDeferred<Unit>()
        val ackSignal = Channel<Unit>(Channel.CONFLATED)
        val pendingTxBytes = AtomicInteger(0)
        val pendingTx = ArrayDeque<ByteArray>()
        val outOfOrder = TreeMap<Long, ByteArray> { a, b -> Integer.compare(a.toInt() - b.toInt(), 0) }
        val unacked = TreeMap<Long, UnackedSegment> { a, b -> Integer.compare(a.toInt() - b.toInt(), 0) }
        val lastActivityMs = AtomicLong(System.currentTimeMillis())
    }

    private val tcpSessions = ConcurrentHashMap<SessionKey, TcpSession>()
    private val dnsCache = ConcurrentHashMap<String, DnsCacheEntry>()
    private val inFlightDns = ConcurrentHashMap<String, CompletableDeferred<ByteArray?>>()
    private val writeLock = Any()
    private val tunWriteChannel = Channel<ByteArray>(capacity = 2048)
    private val engineClosed = AtomicBoolean(false)
    private val ipIdCounter = AtomicInteger(1)
    private val dnsSessionLock = Any()
    @Volatile
    private var persistentDnsSession: WorkerTunnelSession? = null

    @OptIn(ExperimentalCoroutinesApi::class)
    private val tunnelDispatcher = Dispatchers.IO.limitedParallelism(128)

    private val tunWriterJob: Job = scope.launch(Dispatchers.IO) {
        try {
            for (pkt in tunWriteChannel) {
                synchronized(writeLock) {
                    runCatching { tunOutput.write(pkt) }
                }
            }
        } catch (_: CancellationException) {
        }
    }

    private val rtoTickerJob: Job = scope.launch(Dispatchers.IO) {
        while (isActive && !engineClosed.get()) {
            delay(40L)
            if (tcpSessions.isEmpty()) continue
            val now = System.currentTimeMillis()
            for ((key, session) in tcpSessions) {
                if (session.closed.get()) {
                    tcpSessions.remove(key, session)
                    continue
                }
                var rstNeeded = false
                var segmentsToRetransmit: MutableList<Pair<Long, ByteArray>>? = null
                var ackSnap = 0L
                var winSnap = 65535

                synchronized(session.lock) {
                    val firstEntry = session.unacked.firstEntry()
                    if (firstEntry != null) {
                        val oldest = firstEntry.value
                        if (now - oldest.sentAtMs >= session.rtoMs) {
                            if (oldest.retries >= MAX_RTO_RETRIES) {
                                rstNeeded = true
                            } else {
                                session.cwndBytes = (session.cwndBytes / 2L).coerceAtLeast(MIN_CWND_BYTES)
                                session.rtoMs = (session.rtoMs * 2L).coerceAtMost(MAX_RTO_MS)
                                ackSnap = session.clientNextSeq
                                winSnap = computeReceiveWindowLocked(session)
                                val list = mutableListOf<Pair<Long, ByteArray>>()
                                var count = 0
                                for (entry in session.unacked.values) {
                                    entry.sentAtMs = now
                                    entry.retries++
                                    list.add(entry.seq to entry.data)
                                    count++
                                    if (count >= 4) break
                                }
                                segmentsToRetransmit = list
                            }
                        }
                    } else if (session.clientFinReceived && (now - session.lastActivityMs.get()) > 20_000L) {
                        rstNeeded = true
                    }
                }

                if (rstNeeded) {
                    closeSession(key, sendRst = true)
                } else if (segmentsToRetransmit != null) {
                    for ((seq, data) in segmentsToRetransmit!!) {
                        sendTcpControlPacket(
                            session = session,
                            flags = FLAG_PSH or FLAG_ACK,
                            seq = seq,
                            ack = ackSnap,
                            window = winSnap,
                            payload = data,
                        )
                    }
                }
            }
        }
    }

    fun processPacket(packet: ByteArray, length: Int) {
        if (length < 20 || engineClosed.get()) return
        val version = (packet[0].toInt() ushr 4) and 0x0F
        when (version) {
            4 -> processIpv4Packet(packet, length)
            6 -> processIpv6Packet(packet, length)
        }
    }

    private fun processIpv4Packet(packet: ByteArray, length: Int) {
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
            PROTO_UDP -> handleUdpPacket(packet, ihl, totalLength, srcIpBytes, dstIpBytes, isIpv6 = false)
        }
    }

    /**
     * Immediately fast-rejects direct IPv6 TCP/QUIC packets with TCPv6 RST / ICMPv6 Port Unreachable
     * and answers/forwards IPv6 UDP:53 DNS so carrier IPv6 never stalls or leaks.
     */
    private fun processIpv6Packet(packet: ByteArray, length: Int) {
        if (length < 40) return
        val payloadLen = readU16(packet, 4)
        val totalLength = (40 + payloadLen).coerceAtMost(length)
        val nextHeader = packet[6].toInt() and 0xFF
        val srcIp = packet.copyOfRange(8, 24)
        val dstIp = packet.copyOfRange(24, 40)

        when (nextHeader) {
            PROTO_TCP -> {
                if (totalLength < 60) return
                val srcPort = readU16(packet, 40)
                val dstPort = readU16(packet, 42)
                val seq = readU32(packet, 44)
                val flags = packet[53].toInt() and 0xFF
                if ((flags and FLAG_RST) != 0) return
                val isSyn = (flags and FLAG_SYN) != 0
                val dataOff = ((packet[52].toInt() ushr 4) and 0x0F) * 4
                val segPayloadLen = (totalLength - 40 - dataOff).coerceAtLeast(0)
                val ackForClient = (seq + segPayloadLen.toLong() + (if (isSyn) 1L else 0L)) and 0xFFFFFFFFL
                writeTcp6PacketToTun(
                    srcIp = dstIp,
                    srcPort = dstPort,
                    dstIp = srcIp,
                    dstPort = srcPort,
                    seq = 0L,
                    ack = ackForClient,
                    flags = FLAG_RST or FLAG_ACK,
                )
            }
            PROTO_UDP -> {
                if (totalLength < 48) return
                val srcPort = readU16(packet, 40)
                val dstPort = readU16(packet, 42)
                if (dstPort == 53 && remoteDnsOverTcp) {
                    handleUdpPacket(packet, 40, totalLength, srcIp, dstIp, isIpv6 = true)
                } else {
                    sendIcmpv6PortUnreachable(
                        origPacket = packet,
                        origTotalLen = totalLength,
                        srcIp = dstIp,
                        dstIp = srcIp,
                    )
                }
            }
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
        val rawWindow = readU16(packet, ihl + 14)
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
                if (existing.clientInitSeq == seq) {
                    sendTcpSynAck(existing)
                    return
                } else {
                    closeSession(key, sendRst = false)
                }
            }

            val clientWscale = parseTcpWindowScale(packet, ihl + 20, ihl + dataOffset)
            val useWscale = clientWscale != null
            val initialServerSeq = (Random.nextInt() and 0x7FFFFFFF).toLong()
            val clientNextSeq = (seq + 1L) and 0xFFFFFFFFL
            val session = TcpSession(
                key = key,
                srcIpBytes = srcIpBytes,
                dstIpBytes = dstIpBytes,
                clientInitSeq = seq,
                clientNextSeqInit = clientNextSeq,
                initialServerSeq = initialServerSeq,
                useWindowScale = useWscale,
                clientWindowShift = (clientWscale ?: 0).coerceIn(0, 14),
                initialPeerWindowBytes = rawWindow.toLong().coerceAtLeast(1360L),
            )
            tcpSessions[key] = session

            // Reply SYN-ACK immediately (<1ms) so browser sends TLS ClientHello right away
            sendTcpSynAck(session)

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
        session.lastActivityMs.set(System.currentTimeMillis())

        var contiguousPayload: ByteArray? = null
        var ackToSend = 0L
        var serverSeqSnap = 0L
        var windowToAdvertise = 65535
        var sendAck = false
        var establishedNow = false
        var txChanToWrite: Channel<ByteArray>? = null
        var fastRetransmitSeq: Long? = null
        var fastRetransmitPayload: ByteArray? = null
        var fastRetransmitAck = 0L
        var fastRetransmitWin = 65535

        synchronized(session.lock) {
            if (isAck) {
                val scaledWindow = if (session.useWindowScale) {
                    rawWindow.toLong() shl session.clientWindowShift
                } else {
                    rawWindow.toLong()
                }
                val prevWindow = session.peerWindowBytes
                session.peerWindowBytes = scaledWindow

                val ackAdvance = ackNum.toInt() - session.sendBase.toInt()
                val remainingInFlight = session.serverSeq.toInt() - ackNum.toInt()

                if (ackAdvance > 0 && remainingInFlight >= 0) {
                    session.sendBase = ackNum
                    session.dupAckCount = 0
                    session.rtoMs = INITIAL_RTO_MS
                    session.cwndBytes = (session.cwndBytes + ackAdvance.toLong()).coerceAtMost(MAX_CWND_BYTES)
                    purgeAckedSegmentsLocked(session, ackNum)
                    session.ackSignal.trySend(Unit)
                } else if (
                    ackAdvance == 0 &&
                    payload.isEmpty() &&
                    !isFin &&
                    session.unacked.isNotEmpty() &&
                    scaledWindow > 0L
                ) {
                    session.dupAckCount++
                    if (session.dupAckCount == 3 || (session.dupAckCount > 3 && session.dupAckCount % 3 == 0)) {
                        val firstEntry = session.unacked.firstEntry()
                        if (firstEntry != null) {
                            session.cwndBytes = (session.cwndBytes / 2L).coerceAtLeast(MIN_CWND_BYTES)
                            firstEntry.value.sentAtMs = System.currentTimeMillis()
                            fastRetransmitSeq = firstEntry.key
                            fastRetransmitPayload = firstEntry.value.data
                            fastRetransmitAck = session.clientNextSeq
                            fastRetransmitWin = computeReceiveWindowLocked(session)
                        }
                    }
                } else if (prevWindow == 0L && scaledWindow > 0L) {
                    session.ackSignal.trySend(Unit)
                }
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
                } else if (diff in 1..4_000_000 && session.outOfOrder.size < 192) {
                    session.outOfOrder[seq] = payload
                }

                val dataReady = contiguousPayload
                if (dataReady != null && dataReady.isNotEmpty()) {
                    session.pendingTxBytes.addAndGet(dataReady.size)
                    if (session.established.get()) {
                        establishedNow = true
                        txChanToWrite = session.txChannel
                    } else {
                        val wasEmpty = session.pendingTx.isEmpty()
                        session.pendingTx.addLast(dataReady)
                        if (wasEmpty) {
                            session.firstPayloadSignal.complete(Unit)
                        } else {
                            session.secondPayloadSignal.complete(Unit)
                        }
                    }
                }

                ackToSend = session.clientNextSeq
                serverSeqSnap = session.serverSeq
                windowToAdvertise = computeReceiveWindowLocked(session)
                sendAck = true
            }
        }

        if (fastRetransmitPayload != null && fastRetransmitSeq != null) {
            sendTcpControlPacket(
                session = session,
                flags = FLAG_PSH or FLAG_ACK,
                seq = fastRetransmitSeq!!,
                ack = fastRetransmitAck,
                window = fastRetransmitWin,
                payload = fastRetransmitPayload!!,
            )
        }

        if (sendAck) {
            sendTcpControlPacket(
                session = session,
                flags = FLAG_ACK,
                seq = serverSeqSnap,
                ack = ackToSend,
                window = windowToAdvertise,
                payload = ByteArray(0),
            )
        }

        val readyData = contiguousPayload
        if (readyData != null && readyData.isNotEmpty()) {
            VpnStateManager.recordTx(readyData.size)
            if (establishedNow && txChanToWrite != null) {
                txChanToWrite!!.trySend(readyData)
            }
        }

        if (isFin) {
            val ackForFin: Long
            val srvSeq: Long
            val winSnap: Int
            var chanToClose: Channel<ByteArray>? = null
            synchronized(session.lock) {
                val expectedFinSeq = (seq + payload.size.toLong()) and 0xFFFFFFFFL
                if (expectedFinSeq == session.clientNextSeq || payload.isEmpty()) {
                    session.clientNextSeq = (session.clientNextSeq + 1L) and 0xFFFFFFFFL
                }
                ackForFin = session.clientNextSeq
                srvSeq = session.serverSeq
                winSnap = computeReceiveWindowLocked(session)
                session.clientFinReceived = true
                chanToClose = session.txChannel
            }
            sendTcpControlPacket(
                session = session,
                flags = FLAG_ACK,
                seq = srvSeq,
                ack = ackForFin,
                window = winSnap,
                payload = ByteArray(0),
            )
            chanToClose?.close()
        }
    }

    private fun parseTcpWindowScale(packet: ByteArray, optionsStart: Int, optionsEnd: Int): Int? {
        var i = optionsStart
        while (i < optionsEnd) {
            val kind = packet[i].toInt() and 0xFF
            when (kind) {
                0 -> return null
                1 -> i++
                else -> {
                    if (i + 1 >= optionsEnd) return null
                    val len = packet[i + 1].toInt() and 0xFF
                    if (len < 2 || i + len > optionsEnd) return null
                    if (kind == 3 && len == 3) {
                        return packet[i + 2].toInt() and 0xFF
                    }
                    i += len
                }
            }
        }
        return null
    }

    private fun computeReceiveWindowLocked(session: TcpSession): Int {
        val queued = session.pendingTxBytes.get().coerceAtLeast(0)
        val freeBytes = (MAX_UPSTREAM_BUFFER_BYTES - queued).coerceAtLeast(0)
        session.lastAdvertisedWinBytes = freeBytes
        return if (session.useWindowScale) {
            (freeBytes ushr OUR_WSCALE_SHIFT).coerceIn(0, 65535)
        } else {
            freeBytes.coerceIn(0, 65535)
        }
    }

    private fun purgeAckedSegmentsLocked(session: TcpSession, ackNum: Long) {
        val iter = session.unacked.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            val segSeq = entry.key
            val segData = entry.value.data
            val segEnd = (segSeq + segData.size.toLong()) and 0xFFFFFFFFL
            val diffEnd = segEnd.toInt() - ackNum.toInt()
            if (diffEnd <= 0) {
                iter.remove()
            } else {
                val ackedBytes = ackNum.toInt() - segSeq.toInt()
                if (ackedBytes > 0 && ackedBytes < segData.size) {
                    val remaining = segData.copyOfRange(ackedBytes, segData.size)
                    iter.remove()
                    session.unacked[ackNum] = UnackedSegment(
                        seq = ackNum,
                        data = remaining,
                        sentAtMs = entry.value.sentAtMs,
                        retries = 0,
                    )
                }
                break
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

    private suspend fun sniffTargetHost(session: TcpSession, dstHost: String, dstPort: Int): String? {
        // Wakes in <1ms on first payload; 120ms max wait protects slow phones from missing SNI
        withTimeoutOrNull(120L) { session.firstPayloadSignal.await() }
        if (session.closed.get()) return null

        val firstChunk = synchronized(session.lock) { session.pendingTx.firstOrNull() }
        if (firstChunk != null && TrafficSniffer.isIncompleteTlsClientHello(firstChunk)) {
            // Wait briefly for segment 2 of modern Post-Quantum TLS 1.3 ClientHello
            withTimeoutOrNull(45L) { session.secondPayloadSignal.await() }
        }
        if (session.closed.get()) return null

        val combinedFirst = synchronized(session.lock) {
            when (session.pendingTx.size) {
                0 -> null
                1 -> session.pendingTx.first()
                else -> {
                    val out = ByteArrayOutputStream(2048)
                    for (c in session.pendingTx) {
                        out.write(c)
                        if (out.size() >= 4096) break
                    }
                    out.toByteArray()
                }
            }
        }
        val sniffed = combinedFirst?.let { TrafficSniffer.sniffDomain(it, dstPort) }
        return when {
            sniffed != null -> sniffed
            (dstPort == 53 || dstPort == 853) && (dstHost == "1.1.1.1" || dstHost == "1.0.0.1") -> "8.8.8.8"
            else -> dstHost
        }
    }

    private suspend fun openWorkerTcpTunnel(session: TcpSession, dstHost: String, dstPort: Int) {
        var counted = false
        try {
            val effectiveTargetHost = sniffTargetHost(session, dstHost, dstPort) ?: return
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

            val txChan = Channel<ByteArray>(capacity = Channel.UNLIMITED)
            val remainingPayloads = mutableListOf<ByteArray>()
            var finAlreadyReceived = false
            synchronized(session.lock) {
                session.workerSession = wsSession
                session.txChannel = txChan
                session.established.set(true)
                finAlreadyReceived = session.clientFinReceived
                while (session.pendingTx.isNotEmpty()) {
                    remainingPayloads.add(session.pendingTx.removeFirst())
                }
            }

            if (remainingPayloads.isNotEmpty()) {
                val mergedInit = ByteArrayOutputStream()
                for (chunk in remainingPayloads) {
                    session.pendingTxBytes.addAndGet(-chunk.size)
                    mergedInit.write(chunk)
                }
                if (!wsSession.sendPlain(mergedInit.toByteArray())) {
                    throw java.io.IOException("خطا در ارسال ClientHello به Worker")
                }
                maybeSendWindowUpdate(session)
            }
            if (finAlreadyReceived) {
                txChan.close()
            }

            val upJob = scope.launch(tunnelDispatcher) {
                try {
                    while (!session.closed.get()) {
                        val first = txChan.receiveCatching().getOrNull() ?: break
                        session.pendingTxBytes.addAndGet(-first.size)
                        val nextFirst = txChan.tryReceive().getOrNull()
                        val sentOk = if (nextFirst == null) {
                            maybeSendWindowUpdate(session)
                            wsSession.sendPlain(first)
                        } else {
                            val batch = ByteArrayOutputStream(first.size + nextFirst.size)
                            batch.write(first)
                            session.pendingTxBytes.addAndGet(-nextFirst.size)
                            batch.write(nextFirst)
                            while (batch.size() < WorkerDefaults.MAX_CHUNK) {
                                val more = txChan.tryReceive().getOrNull() ?: break
                                session.pendingTxBytes.addAndGet(-more.size)
                                batch.write(more)
                            }
                            maybeSendWindowUpdate(session)
                            wsSession.sendPlain(batch.toByteArray())
                        }
                        if (!sentOk) break
                    }
                } catch (_: Throwable) {
                }
            }

            // Pipelined downstream: readPlain() feeds bounded rxChannel while downJob writes to TUN
            val rxChan = Channel<ByteArray>(capacity = 16)
            val downJob = scope.launch(tunnelDispatcher) {
                try {
                    for (chunk in rxChan) {
                        if (session.closed.get()) break
                        sendDownstreamWithFlowControl(session, chunk)
                    }
                } catch (_: Throwable) {
                }
            }

            try {
                while (!session.closed.get()) {
                    val dec = wsSession.readPlain() ?: break
                    if (dec.isEmpty()) continue
                    VpnStateManager.recordRx(dec.size)
                    rxChan.send(dec)
                }
            } finally {
                rxChan.close()
                downJob.join()
                upJob.cancel()
            }

            if (!session.closed.get()) {
                drainRemainingUnacked(session)
                sendFinAck(session)
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
            val effectiveTargetHost = sniffTargetHost(session, dstHost, dstPort) ?: return
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
            socket.tcpNoDelay = true
            if (session.closed.get()) {
                runCatching { socket.close() }
                return
            }

            VpnStateManager.incrementActiveConnections()
            counted = true
            VpnStateManager.addLog(LogLevel.INFO, "TCP", "اتصال $effectiveTargetHost:$dstPort از طریق SOCKS5")

            val txChan = Channel<ByteArray>(capacity = Channel.UNLIMITED)
            val bufferedPayloads = mutableListOf<ByteArray>()
            var finAlreadyReceived = false
            synchronized(session.lock) {
                session.socket = socket
                session.txChannel = txChan
                session.established.set(true)
                finAlreadyReceived = session.clientFinReceived
                while (session.pendingTx.isNotEmpty()) {
                    bufferedPayloads.add(session.pendingTx.removeFirst())
                }
            }

            val sockOut = socket.getOutputStream()
            if (bufferedPayloads.isNotEmpty()) {
                for (chunk in bufferedPayloads) {
                    session.pendingTxBytes.addAndGet(-chunk.size)
                    sockOut.write(chunk)
                }
                sockOut.flush()
                maybeSendWindowUpdate(session)
            }
            if (finAlreadyReceived) {
                txChan.close()
            }

            // Single ordered uploader coroutine (prevents concurrent write scrambling TLS records)
            val upJob = scope.launch(tunnelDispatcher) {
                try {
                    while (!session.closed.get()) {
                        val first = txChan.receiveCatching().getOrNull() ?: break
                        session.pendingTxBytes.addAndGet(-first.size)
                        sockOut.write(first)
                        var coalesced = first.size
                        while (coalesced < WorkerDefaults.MAX_CHUNK) {
                            val more = txChan.tryReceive().getOrNull() ?: break
                            session.pendingTxBytes.addAndGet(-more.size)
                            sockOut.write(more)
                            coalesced += more.size
                        }
                        sockOut.flush()
                        maybeSendWindowUpdate(session)
                    }
                    runCatching { socket.shutdownOutput() }
                } catch (_: Throwable) {
                }
            }

            val rxChan = Channel<ByteArray>(capacity = 16)
            val downJob = scope.launch(tunnelDispatcher) {
                try {
                    for (chunk in rxChan) {
                        if (session.closed.get()) break
                        sendDownstreamWithFlowControl(session, chunk)
                    }
                } catch (_: Throwable) {
                }
            }

            val input: InputStream = socket.getInputStream()
            val buffer = ByteArray(32768)
            try {
                while (!session.closed.get()) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    val chunk = buffer.copyOf(read)
                    VpnStateManager.recordRx(read)
                    rxChan.send(chunk)
                }
            } finally {
                rxChan.close()
                downJob.join()
                upJob.cancel()
            }

            if (!session.closed.get()) {
                drainRemainingUnacked(session)
                sendFinAck(session)
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

    private fun maybeSendWindowUpdate(session: TcpSession) {
        val shouldSend: Boolean
        val seqSnap: Long
        val ackSnap: Long
        val winSnap: Int
        synchronized(session.lock) {
            val queued = session.pendingTxBytes.get().coerceAtLeast(0)
            val freeBytes = (MAX_UPSTREAM_BUFFER_BYTES - queued).coerceAtLeast(0)
            val prevWin = session.lastAdvertisedWinBytes
            shouldSend = (prevWin < 256 * 1024 && freeBytes >= prevWin + 128 * 1024) ||
                (prevWin < 64 * 1024 && freeBytes >= 64 * 1024)
            if (shouldSend) {
                seqSnap = session.serverSeq
                ackSnap = session.clientNextSeq
                winSnap = computeReceiveWindowLocked(session)
            } else {
                seqSnap = 0L
                ackSnap = 0L
                winSnap = 0
            }
        }
        if (shouldSend) {
            sendTcpControlPacket(
                session = session,
                flags = FLAG_ACK,
                seq = seqSnap,
                ack = ackSnap,
                window = winSnap,
                payload = ByteArray(0),
            )
        }
    }

    private suspend fun sendDownstreamWithFlowControl(session: TcpSession, data: ByteArray) {
        var offset = 0
        var stallCycles = 0
        while (offset < data.size && !session.closed.get()) {
            var sliceToSend: ByteArray? = null
            var seqSnap = 0L
            var ackSnap = 0L
            var winSnap = 65535

            synchronized(session.lock) {
                val inFlight = (session.serverSeq.toInt() - session.sendBase.toInt()).toLong().coerceAtLeast(0L)
                val effectiveWindow = minOf(session.peerWindowBytes, session.cwndBytes)
                val availWindow = (effectiveWindow - inFlight).coerceAtLeast(0L)
                if (availWindow > 0L) {
                    val remaining = data.size - offset
                    // Avoid Silly Window tiny slices unless this is the tail of the chunk
                    if (availWindow >= MSS_BYTES || remaining <= availWindow) {
                        val maxLen = availWindow.coerceAtMost(MSS_BYTES.toLong()).toInt()
                        val end = (offset + maxLen).coerceAtMost(data.size)
                        val slice = data.copyOfRange(offset, end)
                        seqSnap = session.serverSeq
                        ackSnap = session.clientNextSeq
                        winSnap = computeReceiveWindowLocked(session)
                        session.unacked[seqSnap] = UnackedSegment(
                            seq = seqSnap,
                            data = slice,
                            sentAtMs = System.currentTimeMillis(),
                        )
                        session.serverSeq = (session.serverSeq + slice.size.toLong()) and 0xFFFFFFFFL
                        sliceToSend = slice
                        offset = end
                        stallCycles = 0
                    }
                }
            }

            if (sliceToSend != null) {
                val isLast = offset >= data.size
                sendTcpControlPacket(
                    session = session,
                    flags = if (isLast) (FLAG_PSH or FLAG_ACK) else FLAG_ACK,
                    seq = seqSnap,
                    ack = ackSnap,
                    window = winSnap,
                    payload = sliceToSend!!,
                )
            } else {
                // Background rtoTickerJob handles retransmissions every 40ms; wait for ACK signal here
                val signaled = withTimeoutOrNull(180L) { session.ackSignal.receive() }
                if (signaled == null && !session.closed.get()) {
                    stallCycles++
                    if (stallCycles > 60) break
                }
            }
        }
    }

    private suspend fun drainRemainingUnacked(session: TcpSession) {
        var rounds = 0
        while (!session.closed.get() && rounds < 25) {
            val hasUnacked = synchronized(session.lock) { session.unacked.isNotEmpty() }
            if (!hasUnacked) break
            withTimeoutOrNull(160L) { session.ackSignal.receive() }
            rounds++
        }
    }

    private fun sendFinAck(session: TcpSession) {
        val finSeq: Long
        val finAck: Long
        val winSnap: Int
        synchronized(session.lock) {
            finSeq = session.serverSeq
            finAck = session.clientNextSeq
            winSnap = computeReceiveWindowLocked(session)
            session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
        }
        sendTcpControlPacket(
            session = session,
            flags = FLAG_FIN or FLAG_ACK,
            seq = finSeq,
            ack = finAck,
            window = winSnap,
            payload = ByteArray(0),
        )
    }

    private fun handleUdpPacket(
        packet: ByteArray,
        ihl: Int,
        totalLength: Int,
        srcIpBytes: ByteArray,
        dstIpBytes: ByteArray,
        isIpv6: Boolean,
    ) {
        if (totalLength < ihl + 8) return
        val srcPort = readU16(packet, ihl)
        val dstPort = readU16(packet, ihl + 2)
        val udpLen = readU16(packet, ihl + 4)
        if (udpLen < 8 || totalLength < ihl + udpLen) return

        // Fast-reject QUIC (UDP:443) via ICMP Port Unreachable so Chrome switches to TCP HTTPS in 0ms
        if (dstPort == 443) {
            if (!isIpv6) {
                sendIcmpPortUnreachable(
                    origPacket = packet,
                    origIhl = ihl,
                    origTotalLen = totalLength,
                    srcIp = dstIpBytes,
                    dstIp = srcIpBytes,
                )
            } else {
                sendIcmpv6PortUnreachable(
                    origPacket = packet,
                    origTotalLen = totalLength,
                    srcIp = dstIpBytes,
                    dstIp = srcIpBytes,
                )
            }
            return
        }

        if (dstPort != 53 || !remoteDnsOverTcp) return
        val payload = packet.copyOfRange(ihl + 8, ihl + udpLen)
        if (payload.size < 12) return

        // 0ms fast-path: synthesize empty NOERROR for AAAA (QTYPE=28) so apps never stall on carrier IPv6
        if (isAaaaQuery(payload)) {
            val emptyNoError = buildEmptyNoErrorDnsResponse(payload)
            writeDnsReply(srcIpBytes, srcPort, dstIpBytes, emptyNoError, isIpv6)
            return
        }

        // Serve from in-memory DNS cache if fresh
        val cacheKey = payload.copyOfRange(2, payload.size).joinToString("") { "%02x".format(it) }
        val now = System.currentTimeMillis()
        val cached = dnsCache[cacheKey]
        if (cached != null && cached.expiresAtMs > now) {
            val resp = ByteArray(2 + cached.responseWithoutTxId.size)
            resp[0] = payload[0]
            resp[1] = payload[1]
            System.arraycopy(cached.responseWithoutTxId, 0, resp, 2, cached.responseWithoutTxId.size)
            writeDnsReply(srcIpBytes, srcPort, dstIpBytes, resp, isIpv6)
            return
        }

        val targetDnsIp = if (isIpv6) {
            dnsServer
        } else {
            InetAddress.getByAddress(dstIpBytes).hostAddress ?: dnsServer
        }
        scope.launch(tunnelDispatcher) {
            // Deduplicate concurrent identical DNS queries (e.g. Android UDP retries)
            val existing = inFlightDns[cacheKey]
            if (existing != null) {
                val sharedResp = withTimeoutOrNull(6000L) { existing.await() }
                if (sharedResp != null && sharedResp.size >= 12) {
                    val patched = sharedResp.copyOf()
                    patched[0] = payload[0]
                    patched[1] = payload[1]
                    writeDnsReply(srcIpBytes, srcPort, dstIpBytes, patched, isIpv6)
                }
                return@launch
            }

            val deferred = CompletableDeferred<ByteArray?>()
            val raced = inFlightDns.putIfAbsent(cacheKey, deferred)
            if (raced != null) {
                val sharedResp = withTimeoutOrNull(6000L) { raced.await() }
                if (sharedResp != null && sharedResp.size >= 12) {
                    val patched = sharedResp.copyOf()
                    patched[0] = payload[0]
                    patched[1] = payload[1]
                    writeDnsReply(srcIpBytes, srcPort, dstIpBytes, patched, isIpv6)
                }
                return@launch
            }

            try {
                val resp = if (profile.profileType == ProfileType.WORKER_WS) {
                    resolveDnsOverPersistentWorkerTcp(targetDnsIp, payload, cacheKey)
                } else {
                    resolveDnsOverSocks5Tcp(targetDnsIp, payload, cacheKey)
                }
                deferred.complete(resp)
                if (resp != null) {
                    writeDnsReply(srcIpBytes, srcPort, dstIpBytes, resp, isIpv6)
                }
            } catch (_: Throwable) {
                deferred.complete(null)
            } finally {
                inFlightDns.remove(cacheKey, deferred)
            }
        }
    }

    private fun writeDnsReply(
        clientIpBytes: ByteArray,
        clientPort: Int,
        dnsIpBytes: ByteArray,
        dnsResp: ByteArray,
        isIpv6: Boolean,
    ) {
        if (isIpv6) {
            writeUdp6PacketToTun(
                srcIp = dnsIpBytes,
                srcPort = 53,
                dstIp = clientIpBytes,
                dstPort = clientPort,
                payload = dnsResp,
            )
        } else {
            writeUdpPacketToTun(
                srcIp = dnsIpBytes,
                srcPort = 53,
                dstIp = clientIpBytes,
                dstPort = clientPort,
                payload = dnsResp,
            )
        }
    }

    private fun resolveDnsOverPersistentWorkerTcp(
        targetDnsHost: String,
        dnsQuery: ByteArray,
        cacheKey: String,
    ): ByteArray? {
        VpnStateManager.recordTx(dnsQuery.size)
        val framed = ByteArray(2 + dnsQuery.size)
        framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
        framed[1] = (dnsQuery.size and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)

        val effectiveDnsHost = if (targetDnsHost == "1.1.1.1" || targetDnsHost == "1.0.0.1" || targetDnsHost.contains(':')) {
            "8.8.8.8"
        } else {
            targetDnsHost
        }

        synchronized(dnsSessionLock) {
            for (attempt in 0 until 2) {
                var wsSession = persistentDnsSession
                if (wsSession == null || wsSession.isClosed()) {
                    wsSession = WorkerWsClient.openTunnel(
                        uuid = profile.uuid,
                        workerHost = profile.workerHost,
                        cleanIp = profile.cleanIp,
                        subproto = profile.subproto,
                        targetHost = effectiveDnsHost,
                        targetPort = 53,
                        initialPayload = ByteArray(0),
                        socketProtector = protectSocket,
                    )
                    wsSession.setReadTimeout(4500)
                    persistentDnsSession = wsSession
                }

                try {
                    if (!wsSession.sendPlain(framed)) {
                        throw EOFException("DNS WS send failed")
                    }
                    val acc = ByteArrayOutputStream()
                    while (true) {
                        val chunk = wsSession.readPlain() ?: throw EOFException("DNS WS closed")
                        acc.write(chunk)
                        val bytes = acc.toByteArray()
                        if (bytes.size >= 2) {
                            val expectedLen = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
                            if (bytes.size >= 2 + expectedLen && expectedLen in 12..4096) {
                                val dnsResp = bytes.copyOfRange(2, 2 + expectedLen)
                                VpnStateManager.recordRx(dnsResp.size)
                                cacheDnsResponse(cacheKey, dnsResp)
                                return dnsResp
                            }
                        }
                    }
                } catch (_: Throwable) {
                    runCatching { wsSession.close() }
                    if (persistentDnsSession === wsSession) {
                        persistentDnsSession = null
                    }
                    if (attempt == 1) return null
                }
            }
        }
        return null
    }

    private fun resolveDnsOverSocks5Tcp(
        targetDnsHost: String,
        dnsQuery: ByteArray,
        cacheKey: String,
    ): ByteArray? {
        VpnStateManager.recordTx(dnsQuery.size)
        val effectiveDnsHost = if (targetDnsHost.contains(':')) "8.8.8.8" else targetDnsHost
        Socks5Client.connect(
            proxyHost = profile.host,
            proxyPort = profile.port,
            username = profile.username,
            password = profile.password,
            useAuth = profile.useAuth,
            targetHost = effectiveDnsHost,
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
                return dnsResp
            }
        }
        return null
    }

    private fun isAaaaQuery(query: ByteArray): Boolean {
        if (query.size < 18) return false
        val qdCount = readU16(query, 4)
        if (qdCount != 1) return false
        var p = 12
        while (p < query.size) {
            val len = query[p].toInt() and 0xFF
            if (len == 0) {
                p++
                break
            }
            if ((len and 0xC0) != 0) return false
            p += 1 + len
        }
        if (p + 4 > query.size) return false
        val qType = readU16(query, p)
        val qClass = readU16(query, p + 2)
        return qType == 28 && qClass == 1
    }

    private fun buildEmptyNoErrorDnsResponse(query: ByteArray): ByteArray {
        // Locate end of first question section
        var p = 12
        while (p < query.size) {
            val len = query[p].toInt() and 0xFF
            if (len == 0) {
                p += 5 // null(1) + QTYPE(2) + QCLASS(2)
                break
            }
            p += 1 + len
        }
        val respLen = p.coerceAtMost(query.size)
        val resp = query.copyOfRange(0, respLen)
        // Flags: QR=1, copy RD, RA=1, RCODE=0 (NOERROR)
        val rd = query[2].toInt() and 0x01
        resp[2] = (0x81 or rd).toByte()
        resp[3] = 0x80.toByte()
        writeU16(resp, 4, 1) // QDCOUNT = 1
        writeU16(resp, 6, 0) // ANCOUNT = 0
        writeU16(resp, 8, 0) // NSCOUNT = 0
        writeU16(resp, 10, 0) // ARCOUNT = 0
        return resp
    }

    private fun cacheDnsResponse(cacheKey: String, dnsResp: ByteArray) {
        if (dnsResp.size < 12) return
        if (dnsCache.size > 768) dnsCache.clear()
        dnsCache[cacheKey] = DnsCacheEntry(
            responseWithoutTxId = dnsResp.copyOfRange(2, dnsResp.size),
            expiresAtMs = System.currentTimeMillis() + 180_000L,
        )
    }

    fun closeAll() {
        engineClosed.set(true)
        rtoTickerJob.cancel()
        val keys = tcpSessions.keys.toList()
        for (k in keys) {
            closeSession(k, sendRst = false)
        }
        runCatching { persistentDnsSession?.close() }
        persistentDnsSession = null
        inFlightDns.values.forEach { it.complete(null) }
        inFlightDns.clear()
        dnsCache.clear()

        // Flush any pending queued packets to TUN before stopping writer
        tunWriteChannel.close()
        tunWriterJob.cancel()
        synchronized(writeLock) {
            while (true) {
                val pkt = tunWriteChannel.tryReceive().getOrNull() ?: break
                runCatching { tunOutput.write(pkt) }
            }
            runCatching { tunOutput.flush() }
        }
    }

    private fun closeSession(key: SessionKey, sendRst: Boolean) {
        val session = tcpSessions.remove(key) ?: return
        if (session.closed.compareAndSet(false, true)) {
            session.firstPayloadSignal.complete(Unit)
            session.secondPayloadSignal.complete(Unit)
            session.ackSignal.close()
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
            window = 65535,
            payload = ByteArray(0),
        )
    }

    private fun sendTcpSynAck(session: TcpSession) {
        // SYN-ACK window is always unscaled per RFC 1323; MSS = 1360 (0x05, 0x50)
        val options = if (session.useWindowScale) {
            byteArrayOf(
                0x02, 0x04, 0x05, 0x50,
                0x01,
                0x03, 0x03, OUR_WSCALE_SHIFT.toByte(),
            )
        } else {
            byteArrayOf(0x02, 0x04, 0x05, 0x50)
        }
        writeTcpPacketToTun(
            srcIp = session.dstIpBytes,
            srcPort = session.key.dstPort,
            dstIp = session.srcIpBytes,
            dstPort = session.key.srcPort,
            seq = session.initialServerSeq,
            ack = session.clientNextSeq,
            flags = FLAG_SYN or FLAG_ACK,
            window = 65535,
            options = options,
            payload = ByteArray(0),
        )
    }

    private fun sendTcpControlPacket(
        session: TcpSession,
        flags: Int,
        seq: Long,
        ack: Long,
        window: Int = 65535,
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
            window = window,
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
        pkt[ic] = 3.toByte()
        pkt[ic + 1] = 3.toByte()
        writeU16(pkt, ic + 2, 0)
        writeU32(pkt, ic + 4, 0L)
        System.arraycopy(origPacket, 0, pkt, ic + 8, quotedLen)

        val icmpChecksum = onesComplementChecksum(pkt, ic, icmpLen)
        writeU16(pkt, ic + 2, icmpChecksum)
        enqueuePacketToTun(pkt)
    }

    private fun sendIcmpv6PortUnreachable(
        origPacket: ByteArray,
        origTotalLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
    ) {
        val quotedLen = origTotalLen.coerceAtMost(1232)
        val icmpLen = 8 + quotedLen
        val pkt = ByteArray(40 + icmpLen)

        fillIpv6Header(pkt, icmpLen, PROTO_ICMPV6, srcIp, dstIp)
        val ic = 40
        pkt[ic] = 1.toByte() // Destination Unreachable
        pkt[ic + 1] = 4.toByte() // Port Unreachable
        writeU16(pkt, ic + 2, 0)
        writeU32(pkt, ic + 4, 0L)
        System.arraycopy(origPacket, 0, pkt, ic + 8, quotedLen)

        val csum = computeTransportChecksumIpv6(srcIp, dstIp, PROTO_ICMPV6, pkt, ic, icmpLen)
        writeU16(pkt, ic + 2, csum)
        enqueuePacketToTun(pkt)
    }

    private fun writeTcpPacketToTun(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
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
        writeU16(pkt, t + 14, window.coerceIn(0, 65535))
        writeU16(pkt, t + 16, 0)
        writeU16(pkt, t + 18, 0)

        if (options.isNotEmpty()) System.arraycopy(options, 0, pkt, t + 20, options.size)
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, pkt, t + tcpHeaderLen, payload.size)

        val tcpChecksum = computeTransportChecksumIpv4(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTO_TCP,
            pkt = pkt,
            offset = t,
            length = tcpHeaderLen + payload.size,
        )
        writeU16(pkt, t + 16, tcpChecksum)

        enqueuePacketToTun(pkt)
    }

    private fun writeTcp6PacketToTun(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
    ) {
        val tcpLen = 20
        val pkt = ByteArray(40 + tcpLen)
        fillIpv6Header(pkt, tcpLen, PROTO_TCP, srcIp, dstIp)
        val t = 40
        writeU16(pkt, t, srcPort)
        writeU16(pkt, t + 2, dstPort)
        writeU32(pkt, t + 4, seq)
        writeU32(pkt, t + 8, ack)
        pkt[t + 12] = 0x50.toByte()
        pkt[t + 13] = (flags and 0xFF).toByte()
        writeU16(pkt, t + 14, 0)
        writeU16(pkt, t + 16, 0)
        writeU16(pkt, t + 18, 0)
        val csum = computeTransportChecksumIpv6(srcIp, dstIp, PROTO_TCP, pkt, t, tcpLen)
        writeU16(pkt, t + 16, csum)
        enqueuePacketToTun(pkt)
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

        val udpChecksum = computeTransportChecksumIpv4(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTO_UDP,
            pkt = pkt,
            offset = u,
            length = udpLen,
        )
        writeU16(pkt, u + 6, if (udpChecksum == 0) 0xFFFF else udpChecksum)

        enqueuePacketToTun(pkt)
    }

    private fun writeUdp6PacketToTun(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ) {
        val udpLen = 8 + payload.size
        val pkt = ByteArray(40 + udpLen)

        fillIpv6Header(pkt, udpLen, PROTO_UDP, srcIp, dstIp)

        val u = 40
        writeU16(pkt, u, srcPort)
        writeU16(pkt, u + 2, dstPort)
        writeU16(pkt, u + 4, udpLen)
        writeU16(pkt, u + 6, 0)
        System.arraycopy(payload, 0, pkt, u + 8, payload.size)

        val udpChecksum = computeTransportChecksumIpv6(srcIp, dstIp, PROTO_UDP, pkt, u, udpLen)
        writeU16(pkt, u + 6, if (udpChecksum == 0) 0xFFFF else udpChecksum)

        enqueuePacketToTun(pkt)
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

    private fun fillIpv6Header(
        pkt: ByteArray,
        payloadLen: Int,
        nextHeader: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
    ) {
        pkt[0] = 0x60.toByte()
        pkt[1] = 0x00
        pkt[2] = 0x00
        pkt[3] = 0x00
        writeU16(pkt, 4, payloadLen)
        pkt[6] = (nextHeader and 0xFF).toByte()
        pkt[7] = 64.toByte()
        System.arraycopy(srcIp, 0, pkt, 8, 16)
        System.arraycopy(dstIp, 0, pkt, 24, 16)
    }

    private fun enqueuePacketToTun(pkt: ByteArray) {
        if (engineClosed.get()) return
        tunWriteChannel.trySend(pkt)
    }

    private fun computeTransportChecksumIpv4(
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        pkt: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += (protocol and 0xFF).toLong()
        sum += (length and 0xFFFF).toLong()
        return finalizeTransportChecksum(sum, pkt, offset, length)
    }

    private fun computeTransportChecksumIpv6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        nextHeader: Int,
        pkt: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        var i = 0
        while (i < 16) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
            i += 2
        }
        sum += ((length ushr 16) and 0xFFFF).toLong()
        sum += (length and 0xFFFF).toLong()
        sum += (nextHeader and 0xFF).toLong()
        return finalizeTransportChecksum(sum, pkt, offset, length)
    }

    private fun finalizeTransportChecksum(initialSum: Long, buf: ByteArray, offset: Int, length: Int): Int {
        var sum = initialSum
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((buf[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFFL).toInt()
    }

    private fun onesComplementChecksum(buf: ByteArray, offset: Int, length: Int): Int =
        finalizeTransportChecksum(0L, buf, offset, length)

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
        private const val PROTO_ICMPV6 = 58
        private const val FLAG_FIN = 0x01
        private const val FLAG_SYN = 0x02
        private const val FLAG_RST = 0x04
        private const val FLAG_PSH = 0x08
        private const val FLAG_ACK = 0x10
        private const val OUR_WSCALE_SHIFT = 7
        private const val MSS_BYTES = 1360
        private const val INITIAL_CWND_BYTES = 14L * MSS_BYTES
        private const val MIN_CWND_BYTES = 4L * MSS_BYTES
        private const val MAX_CWND_BYTES = 512L * 1024L
        private const val INITIAL_RTO_MS = 150L
        private const val MAX_RTO_MS = 2000L
        private const val MAX_RTO_RETRIES = 12
        private const val MAX_UPSTREAM_BUFFER_BYTES = 2 * 1024 * 1024
    }
}
