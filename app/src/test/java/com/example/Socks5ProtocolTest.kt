package com.example

import com.example.network.Socks5Client
import com.example.network.Socks5Exception
import com.example.vpn.RouteCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

class Socks5ProtocolTest {

    @Test
    fun `socks5 handshake with username password auth and domain connect succeeds`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val serverThread = thread {
            server.use { srv ->
                srv.accept().use { client ->
                    val input = DataInputStream(client.getInputStream())
                    val out = client.getOutputStream()

                    // Read greeting
                    val ver = input.readUnsignedByte()
                    val nMethods = input.readUnsignedByte()
                    val methods = ByteArray(nMethods)
                    input.readFully(methods)
                    assertEquals(0x05, ver)
                    assertTrue(methods.contains(0x02.toByte()))

                    // Select user/pass auth (0x02)
                    out.write(byteArrayOf(0x05, 0x02))
                    out.flush()

                    // Read RFC 1929 auth
                    val authVer = input.readUnsignedByte()
                    val uLen = input.readUnsignedByte()
                    val user = ByteArray(uLen).also { input.readFully(it) }.decodeToString()
                    val pLen = input.readUnsignedByte()
                    val pass = ByteArray(pLen).also { input.readFully(it) }.decodeToString()
                    assertEquals(0x01, authVer)
                    assertEquals("ali", user)
                    assertEquals("s3cr3t", pass)

                    out.write(byteArrayOf(0x01, 0x00))
                    out.flush()

                    // Read CONNECT request
                    assertEquals(0x05, input.readUnsignedByte())
                    assertEquals(0x01, input.readUnsignedByte())
                    assertEquals(0x00, input.readUnsignedByte())
                    val atyp = input.readUnsignedByte()
                    assertEquals(0x03, atyp)
                    val dLen = input.readUnsignedByte()
                    val domain = ByteArray(dLen).also { input.readFully(it) }.decodeToString()
                    val port = input.readUnsignedShort()
                    assertEquals("example.com", domain)
                    assertEquals(443, port)

                    // Reply success
                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    out.flush()

                    // Echo payload
                    val buf = ByteArray(4)
                    input.readFully(buf)
                    out.write(buf)
                    out.flush()
                }
            }
        }

        val socket = Socks5Client.connect(
            proxyHost = "127.0.0.1",
            proxyPort = server.localPort,
            username = "ali",
            password = "s3cr3t",
            useAuth = true,
            targetHost = "example.com",
            targetPort = 443,
            timeoutMs = 4000,
        )
        socket.use { s ->
            s.getOutputStream().write("PING".toByteArray())
            s.getOutputStream().flush()
            val resp = ByteArray(4)
            DataInputStream(s.getInputStream()).readFully(resp)
            assertEquals("PING", resp.decodeToString())
        }
        serverThread.join(3000)
    }

    @Test(expected = Socks5Exception::class)
    fun `socks5 rejects bad credentials with Socks5Exception`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val serverThread = thread {
            server.use { srv ->
                srv.accept().use { client ->
                    val input = DataInputStream(client.getInputStream())
                    val out = client.getOutputStream()
                    input.readUnsignedByte()
                    val nMethods = input.readUnsignedByte()
                    input.readFully(ByteArray(nMethods))
                    out.write(byteArrayOf(0x05, 0x02))
                    out.flush()

                    input.readUnsignedByte()
                    val uLen = input.readUnsignedByte()
                    input.readFully(ByteArray(uLen))
                    val pLen = input.readUnsignedByte()
                    input.readFully(ByteArray(pLen))
                    out.write(byteArrayOf(0x01, 0x01)) // auth failed
                    out.flush()
                }
            }
        }
        try {
            Socks5Client.connect(
                proxyHost = "127.0.0.1",
                proxyPort = server.localPort,
                username = "wrong",
                password = "bad",
                useAuth = true,
                targetHost = "1.1.1.1",
                targetPort = 80,
                timeoutMs = 3000,
            )
        } finally {
            serverThread.join(2000)
        }
    }

    @Test
    fun `route calculator excludes RFC1918 private ranges`() {
        val blocks = RouteCalculator.publicRoutesExcludingPrivate()
        assertTrue(blocks.isNotEmpty())
        assertFalse(blocks.any { it.address == "192.168.0.0" && it.prefix == 16 })
        assertFalse(blocks.any { it.address == "10.0.0.0" && it.prefix == 8 })
        assertFalse(blocks.any { it.address == "172.16.0.0" && it.prefix == 12 })
    }

    @Test
    fun `worker crypto init packet structure and xor roundtrip are valid`() {
        val uuid = "11111111-2222-3333-4444-555555555555"
        val pkt = com.example.worker.WorkerCrypto.buildInit(uuid, "example.com", 443, byteArrayOf(1, 2, 3))
        assertEquals(16, pkt.key.size)
        // 16 nonce + (1 ver + 2 port + 1 atyp + 1 len + 11 domain + 3 payload) + 8 mac = 43 bytes
        assertEquals(16 + 19 + 8, pkt.data.size)

        val plain = "Hello Worker Tunnel!".toByteArray()
        val enc = com.example.worker.WorkerCrypto.xorWithKey(plain, pkt.key)
        val dec = com.example.worker.WorkerCrypto.xorWithKey(enc, pkt.key)
        assertTrue(plain.contentEquals(dec))

        val ack = com.example.worker.WorkerCrypto.expectedAck(pkt.key)
        assertEquals(16, ack.size)
    }

    @Test
    fun `worker crypto buildInit handles ipv4 ipv6 and ipv4-mapped ipv6 cleanly`() {
        val uuid = "11111111-2222-3333-4444-555555555555"
        // Standard IPv4: 16 nonce + (1 ver + 2 port + 1 atyp + 4 ip) + 8 mac = 32 bytes; atyp=1
        val v4 = com.example.worker.WorkerCrypto.buildInit(uuid, "172.67.70.244", 443)
        assertEquals(32, v4.data.size)
        assertEquals(1, (v4.data[16 + 3].toInt() xor v4.key[3].toInt()) and 0xFF)

        // IPv4-mapped IPv6 (InetAddress returns 4-byte IPv4): must still encode as atyp=1, length=32
        val mapped = com.example.worker.WorkerCrypto.buildInit(uuid, "::ffff:172.67.70.244", 443)
        assertEquals(32, mapped.data.size)
        assertEquals(1, (mapped.data[16 + 3].toInt() xor mapped.key[3].toInt()) and 0xFF)

        // Real IPv6: 16 nonce + (1 ver + 2 port + 1 atyp + 16 ip) + 8 mac = 44 bytes; atyp=3
        val v6 = com.example.worker.WorkerCrypto.buildInit(uuid, "2606:4700:4700::1111", 443)
        assertEquals(44, v6.data.size)
        assertEquals(3, (v6.data[16 + 3].toInt() xor v6.key[3].toInt()) and 0xFF)
    }

    @Test
    fun `traffic sniffer extracts TLS SNI and HTTP Host`() {
        val hostBytes = "www.wikipedia.org".toByteArray(Charsets.US_ASCII)
        val sniEntry = ByteArray(3 + hostBytes.size)
        sniEntry[0] = 0x00 // host_name
        sniEntry[1] = 0x00
        sniEntry[2] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, sniEntry, 3, hostBytes.size)

        val sniExtPayload = ByteArray(2 + sniEntry.size)
        sniExtPayload[0] = 0x00
        sniExtPayload[1] = sniEntry.size.toByte()
        System.arraycopy(sniEntry, 0, sniExtPayload, 2, sniEntry.size)

        val extBlock = ByteArray(4 + sniExtPayload.size)
        extBlock[0] = 0x00; extBlock[1] = 0x00 // server_name ext
        extBlock[2] = 0x00; extBlock[3] = sniExtPayload.size.toByte()
        System.arraycopy(sniExtPayload, 0, extBlock, 4, sniExtPayload.size)

        // Build minimal TLS 1.2 ClientHello
        val body = java.io.ByteArrayOutputStream()
        body.write(byteArrayOf(0x03, 0x03)) // TLS 1.2
        body.write(ByteArray(32)) // random
        body.write(0x00) // session id len = 0
        body.write(byteArrayOf(0x00, 0x02, 0x13, 0x01)) // cipher suites
        body.write(byteArrayOf(0x01, 0x00)) // compression methods
        body.write(byteArrayOf(0x00, extBlock.size.toByte())) // extensions len
        body.write(extBlock)
        val bodyBytes = body.toByteArray()

        val hsLen = bodyBytes.size
        val recLen = 4 + hsLen
        val clientHello = ByteArray(5 + recLen)
        clientHello[0] = 0x16 // Handshake
        clientHello[1] = 0x03; clientHello[2] = 0x01
        clientHello[3] = ((recLen ushr 8) and 0xFF).toByte()
        clientHello[4] = (recLen and 0xFF).toByte()
        clientHello[5] = 0x01 // ClientHello
        clientHello[6] = 0x00
        clientHello[7] = ((hsLen ushr 8) and 0xFF).toByte()
        clientHello[8] = (hsLen and 0xFF).toByte()
        System.arraycopy(bodyBytes, 0, clientHello, 9, bodyBytes.size)

        assertEquals("www.wikipedia.org", com.example.vpn.TrafficSniffer.sniffDomain(clientHello, 443))

        val httpReq = "GET /index.html HTTP/1.1\r\nHost: example.org:8080\r\nConnection: close\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        assertEquals("example.org", com.example.vpn.TrafficSniffer.sniffDomain(httpReq, 80))
    }

    @Test
    fun `raw websocket exchanges xor binary frames and auto replies pong to ping`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val xorKey = ByteArray(16) { (it * 7 + 3).toByte() }
        val serverThread = thread {
            server.use { srv ->
                srv.accept().use { peer ->
                    val input = DataInputStream(peer.getInputStream())
                    val out = peer.getOutputStream()

                    // Read masked client binary frame
                    val b0 = input.readUnsignedByte()
                    val b1 = input.readUnsignedByte()
                    assertEquals(0x82, b0)
                    assertTrue((b1 and 0x80) != 0)
                    val len = b1 and 0x7F
                    val mask = ByteArray(4).also { input.readFully(it) }
                    val payload = ByteArray(len).also { input.readFully(it) }
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor mask[i and 3].toInt() xor xorKey[i and 15].toInt()).toByte()
                    }
                    assertEquals("fast-xray-kotlin", payload.decodeToString())

                    // Send PING (0x89)
                    out.write(byteArrayOf(0x89.toByte(), 0x02, 0x41, 0x42))
                    out.flush()

                    // Verify client sends PONG (0x8A) masked with "AB"
                    val pb0 = input.readUnsignedByte()
                    val pb1 = input.readUnsignedByte()
                    assertEquals(0x8A, pb0)
                    assertEquals(0x82, pb1)
                    val pMask = ByteArray(4).also { input.readFully(it) }
                    val pData = ByteArray(2).also { input.readFully(it) }
                    for (i in pData.indices) {
                        pData[i] = (pData[i].toInt() xor pMask[i and 3].toInt()).toByte()
                    }
                    assertEquals("AB", pData.decodeToString())

                    // Send unmasked server binary frame (XOR encrypted)
                    val reply = "ACK-OK".toByteArray()
                    val enc = com.example.worker.WorkerCrypto.xorWithKey(reply, xorKey)
                    out.write(byteArrayOf(0x82.toByte(), enc.size.toByte()))
                    out.write(enc)
                    out.flush()
                }
            }
        }

        val sock = java.net.Socket("127.0.0.1", server.localPort)
        val ws = com.example.worker.RawWebSocket(sock)
        ws.useCompat {
            assertTrue(ws.sendBinary("fast-xray-kotlin".toByteArray(), xorKey = xorKey))
            val msg = ws.readMessage(xorKey = xorKey)
            assertEquals("ACK-OK", msg?.decodeToString())
        }
        serverThread.join(3000)
    }

    private inline fun com.example.worker.RawWebSocket.useCompat(block: () -> Unit) {
        try {
            block()
        } finally {
            close()
        }
    }

    @Test
    fun `tun packet engine sends syn-ack and icmp port unreachable for quic`() {
        val tempOut = java.io.File.createTempFile("tun_out_test", ".bin")
        tempOut.deleteOnExit()
        val fos = java.io.FileOutputStream(tempOut)
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob())
        val profile = com.example.data.ProxyProfile(
            name = "Test",
            host = "127.0.0.1",
            port = 1,
        )
        val engine = com.example.vpn.TunPacketEngine(
            scope = scope,
            profile = profile,
            dnsServer = "8.8.8.8",
            remoteDnsOverTcp = true,
            tunOutput = fos,
            protectSocket = { true },
        )

        // Build UDP packet to port 443 (QUIC)
        val udpPkt = ByteArray(28)
        udpPkt[0] = 0x45
        udpPkt[3] = 28
        udpPkt[8] = 64
        udpPkt[9] = 17 // UDP
        // src 10.8.0.2 -> dst 8.8.8.8
        udpPkt[12] = 10; udpPkt[13] = 8; udpPkt[14] = 0; udpPkt[15] = 2
        udpPkt[16] = 8; udpPkt[17] = 8; udpPkt[18] = 8; udpPkt[19] = 8
        // srcPort 50000 -> dstPort 443
        udpPkt[20] = (50000 ushr 8).toByte(); udpPkt[21] = (50000 and 0xFF).toByte()
        udpPkt[22] = (443 ushr 8).toByte(); udpPkt[23] = (443 and 0xFF).toByte()
        udpPkt[25] = 8 // udpLen = 8

        engine.processPacket(udpPkt, udpPkt.size)
        fos.flush()
        engine.closeAll()
        fos.close()

        val outBytes = tempOut.readBytes()
        assertEquals(56, outBytes.size) // 20 IP + 8 ICMP + 28 quoted
        assertEquals(1, outBytes[9].toInt() and 0xFF) // ICMP protocol
        assertEquals(3, outBytes[20].toInt() and 0xFF) // Type 3 Unreachable
        assertEquals(3, outBytes[21].toInt() and 0xFF) // Code 3 Port Unreachable
    }

    @Test
    fun `tun packet engine negotiates tcp window scale on syn-ack`() {
        val tempOut = java.io.File.createTempFile("tun_syn_test", ".bin")
        tempOut.deleteOnExit()
        val fos = java.io.FileOutputStream(tempOut)
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob())
        val profile = com.example.data.ProxyProfile(
            name = "Test",
            host = "127.0.0.1",
            port = 1,
        )
        val engine = com.example.vpn.TunPacketEngine(
            scope = scope,
            profile = profile,
            dnsServer = "8.8.8.8",
            remoteDnsOverTcp = true,
            tunOutput = fos,
            protectSocket = { true },
        )

        // Build TCP SYN packet (20 IP + 24 TCP with Window Scale option = 44 bytes)
        val synPkt = ByteArray(44)
        synPkt[0] = 0x45
        synPkt[3] = 44
        synPkt[8] = 64
        synPkt[9] = 6 // TCP
        synPkt[12] = 10; synPkt[13] = 8; synPkt[14] = 0; synPkt[15] = 2
        synPkt[16] = 93; synPkt[17] = 184.toByte(); synPkt[18] = 216.toByte(); synPkt[19] = 34
        synPkt[20] = (51000 ushr 8).toByte(); synPkt[21] = (51000 and 0xFF).toByte()
        synPkt[22] = (443 ushr 8).toByte(); synPkt[23] = (443 and 0xFF).toByte()
        synPkt[32] = 0x60 // dataOffset = 6 (24 bytes)
        synPkt[33] = 0x02 // SYN
        synPkt[34] = 0xFF.toByte(); synPkt[35] = 0xFF.toByte()
        // Option: NOP (1), WSCALE (3, 3, 6)
        synPkt[40] = 1; synPkt[41] = 3; synPkt[42] = 3; synPkt[43] = 6

        engine.processPacket(synPkt, synPkt.size)
        fos.flush()
        engine.closeAll()
        fos.close()

        val outBytes = tempOut.readBytes()
        assertEquals(48, outBytes.size) // 20 IP + 28 TCP (MSS + NOP + WSCALE)
        assertEquals(6, outBytes[9].toInt() and 0xFF)
        assertEquals(0x12, outBytes[33].toInt() and 0xFF) // SYN + ACK
        assertEquals(0x70, outBytes[32].toInt() and 0xFF) // dataOffset = 7 (28 bytes)
        assertEquals(2, outBytes[40].toInt() and 0xFF) // MSS option kind
        assertEquals(0x05, outBytes[42].toInt() and 0xFF) // MSS 1440 hi byte
        assertEquals(0xA0, outBytes[43].toInt() and 0xFF) // MSS 1440 lo byte
        assertEquals(3, outBytes[45].toInt() and 0xFF) // WSCALE option kind
        assertEquals(7, outBytes[47].toInt() and 0xFF) // our shift = 7
    }

    @Test
    fun `traffic sniffer detects incomplete post-quantum tls client hello`() {
        val partialHello = ByteArray(100)
        partialHello[0] = 0x16 // Handshake
        partialHello[1] = 0x03; partialHello[2] = 0x01
        // Declare record length 1800 bytes (> 100 bytes present)
        partialHello[3] = (1800 ushr 8).toByte()
        partialHello[4] = (1800 and 0xFF).toByte()
        partialHello[5] = 0x01 // ClientHello
        assertTrue(com.example.vpn.TrafficSniffer.isIncompleteTlsClientHello(partialHello))

        val smallComplete = ByteArray(100)
        smallComplete[0] = 0x16
        smallComplete[1] = 0x03; smallComplete[2] = 0x01
        smallComplete[3] = 0x00; smallComplete[4] = 60
        smallComplete[5] = 0x01
        assertFalse(com.example.vpn.TrafficSniffer.isIncompleteTlsClientHello(smallComplete))
    }

    @Test
    fun `tun packet engine returns fast empty NOERROR for AAAA dns queries and rejects ipv6 tcp`() {
        val tempOut = java.io.File.createTempFile("tun_v6_aaaa_test", ".bin")
        tempOut.deleteOnExit()
        val fos = java.io.FileOutputStream(tempOut)
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob())
        val profile = com.example.data.ProxyProfile(
            name = "Test",
            host = "127.0.0.1",
            port = 1,
        )
        val engine = com.example.vpn.TunPacketEngine(
            scope = scope,
            profile = profile,
            dnsServer = "8.8.8.8",
            remoteDnsOverTcp = true,
            tunOutput = fos,
            protectSocket = { true },
        )

        // Build IPv4 UDP:53 AAAA query for "a.com"
        val dnsQuery = byteArrayOf(
            0x12, 0x34, // TXID
            0x01, 0x00, // RD=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 'a'.code.toByte(), 0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 28, // QTYPE = AAAA (28)
            0x00, 1,  // QCLASS = IN (1)
        )
        val udpTotal = 20 + 8 + dnsQuery.size
        val dnsPkt = ByteArray(udpTotal)
        dnsPkt[0] = 0x45
        dnsPkt[2] = (udpTotal ushr 8).toByte(); dnsPkt[3] = (udpTotal and 0xFF).toByte()
        dnsPkt[8] = 64
        dnsPkt[9] = 17 // UDP
        dnsPkt[12] = 10; dnsPkt[13] = 8; dnsPkt[14] = 0; dnsPkt[15] = 2
        dnsPkt[16] = 8; dnsPkt[17] = 8; dnsPkt[18] = 8; dnsPkt[19] = 8
        dnsPkt[20] = (52000 ushr 8).toByte(); dnsPkt[21] = (52000 and 0xFF).toByte()
        dnsPkt[22] = 0; dnsPkt[23] = 53
        val udpLen = 8 + dnsQuery.size
        dnsPkt[24] = (udpLen ushr 8).toByte(); dnsPkt[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, dnsPkt, 28, dnsQuery.size)

        engine.processPacket(dnsPkt, dnsPkt.size)

        // Also send IPv6 TCP SYN (40 IPv6 + 20 TCP = 60 bytes)
        val tcp6 = ByteArray(60)
        tcp6[0] = 0x60 // IPv6
        tcp6[4] = 0; tcp6[5] = 20 // payloadLen = 20
        tcp6[6] = 6 // TCP
        tcp6[7] = 64
        tcp6[23] = 2 // src ::2
        tcp6[24] = 0x20; tcp6[39] = 1 // dst 2000::1
        tcp6[40] = (54000 ushr 8).toByte(); tcp6[41] = (54000 and 0xFF).toByte()
        tcp6[42] = 0x01; tcp6[43] = 0xBB.toByte() // 443
        tcp6[52] = 0x50 // dataOff=5
        tcp6[53] = 0x02 // SYN
        engine.processPacket(tcp6, tcp6.size)

        // Allow writer coroutine a moment then closeAll() flushes remaining
        Thread.sleep(50L)
        engine.closeAll()
        fos.close()

        val outBytes = tempOut.readBytes()
        // Packet 1 = IPv4 DNS reply (28 + dnsQuery.size), Packet 2 = IPv6 TCP RST+ACK (60)
        assertEquals(udpTotal + 60, outBytes.size)
        // Verify DNS QR=1 (0x81) and ANCOUNT=0, RCODE=0
        assertEquals(0x12, outBytes[28].toInt() and 0xFF)
        assertEquals(0x34, outBytes[29].toInt() and 0xFF)
        assertEquals(0x81, outBytes[30].toInt() and 0xFF)
        assertEquals(0, outBytes[31].toInt() and 0x0F) // NOERROR
        assertEquals(0, outBytes[35].toInt() and 0xFF) // ANCOUNT = 0
        // Verify Packet 2 is IPv6 TCP RST+ACK (0x14)
        assertEquals(6, (outBytes[udpTotal].toInt() ushr 4) and 0x0F)
        assertEquals(0x14, outBytes[udpTotal + 53].toInt() and 0xFF)
    }

    @Test
    fun `vpn socket protector binds socket fd before protect callback and honors selfUidBypassed`() {
        val v4Target = InetAddress.getByName("127.0.0.1")
        try {
            com.example.vpn.VpnSocketProtector.activeProtector = null
            com.example.vpn.VpnSocketProtector.underlyingNetwork = null
            com.example.vpn.VpnSocketProtector.selfUidBypassed = false

            // 1. Socket must already be bound (native FD allocated) before protector runs
            java.net.Socket().use { sock1 ->
                assertFalse(sock1.isBound)
                var wasBoundWhenProtectCalled = false
                var localPortWhenProtectCalled = -1
                val ok = com.example.vpn.VpnSocketProtector.protectAndBind(
                    socket = sock1,
                    explicitProtector = { s ->
                        wasBoundWhenProtectCalled = s.isBound
                        localPortWhenProtectCalled = s.localPort
                        true
                    },
                    targetAddress = v4Target,
                )
                assertTrue(ok)
                assertTrue(wasBoundWhenProtectCalled)
                assertTrue(localPortWhenProtectCalled > 0)
            }

            // 2. When protector returns false and selfUidBypassed == false, protectAndBind returns false
            java.net.Socket().use { sock2 ->
                val rejected = com.example.vpn.VpnSocketProtector.protectAndBind(
                    socket = sock2,
                    explicitProtector = { false },
                    targetAddress = v4Target,
                )
                assertFalse(rejected)
            }

            // 3. When protector returns false but selfUidBypassed == true, protectAndBind succeeds
            com.example.vpn.VpnSocketProtector.selfUidBypassed = true
            java.net.Socket().use { sock3 ->
                val bypassedOk = com.example.vpn.VpnSocketProtector.protectAndBind(
                    socket = sock3,
                    explicitProtector = { false },
                    targetAddress = v4Target,
                )
                assertTrue(bypassedOk)
            }
        } finally {
            com.example.vpn.VpnSocketProtector.activeProtector = null
            com.example.vpn.VpnSocketProtector.underlyingNetwork = null
            com.example.vpn.VpnSocketProtector.selfUidBypassed = false
        }
    }

    @Test
    fun `raw websocket unrolled 4-byte masking handles medium non-aligned payloads`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val xorKey = ByteArray(16) { (it * 13 + 5).toByte() }
        val payloadSize = 515 // > 126 (16-bit extended length) and not divisible by 4 or 16
        val testPayload = ByteArray(payloadSize) { ((it * 31 + 17) and 0xFF).toByte() }
        val receivedOnServer = java.util.concurrent.atomic.AtomicReference<ByteArray?>()

        val serverThread = thread {
            server.use { srv ->
                srv.accept().use { peer ->
                    val input = DataInputStream(peer.getInputStream())
                    val b0 = input.readUnsignedByte()
                    val b1 = input.readUnsignedByte()
                    assertEquals(0x82, b0)
                    assertEquals(0xFE, b1) // masked + 126 extended len
                    val len = input.readUnsignedShort()
                    assertEquals(payloadSize, len)
                    val mask = ByteArray(4).also { input.readFully(it) }
                    val buf = ByteArray(len).also { input.readFully(it) }
                    for (i in buf.indices) {
                        buf[i] = (buf[i].toInt() xor mask[i and 3].toInt() xor xorKey[i and 15].toInt()).toByte()
                    }
                    receivedOnServer.set(buf)
                }
            }
        }

        val sock = java.net.Socket("127.0.0.1", server.localPort)
        val ws = com.example.worker.RawWebSocket(sock)
        ws.useCompat {
            assertTrue(ws.sendBinary(testPayload, offset = 0, length = testPayload.size, xorKey = xorKey))
        }
        serverThread.join(3000)
        assertTrue(testPayload.contentEquals(receivedOnServer.get()))
    }
}


