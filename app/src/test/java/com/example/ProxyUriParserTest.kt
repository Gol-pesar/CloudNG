package com.example

import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.data.ProxyUriParser
import com.example.ui.QrCodeUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ProxyUriParserTest {

    @Test
    fun `parses socks5 uri with credentials and fragment name`() {
        val parsed = ProxyUriParser.parse("socks5://user1:pass%40123@185.10.20.30:1080#Germany%20Node").getOrThrow()
        assertEquals("Germany Node", parsed.name)
        assertEquals("185.10.20.30", parsed.host)
        assertEquals(1080, parsed.port)
        assertTrue(parsed.useAuth)
        assertEquals("user1", parsed.username)
        assertEquals("pass@123", parsed.password)
    }

    @Test
    fun `parses telegram socks link`() {
        val parsed = ProxyUriParser.parse("tg://socks?server=91.100.1.2&port=443&user=myuser&pass=mypw").getOrThrow()
        assertEquals("91.100.1.2", parsed.host)
        assertEquals(443, parsed.port)
        assertEquals("myuser", parsed.username)
        assertEquals("mypw", parsed.password)
        assertTrue(parsed.useAuth)
    }

    @Test
    fun `parses colon separated proxy string`() {
        val parsed = ProxyUriParser.parse("192.0.2.5:9050:alice:secret").getOrThrow()
        assertEquals("192.0.2.5", parsed.host)
        assertEquals(9050, parsed.port)
        assertEquals("alice", parsed.username)
        assertEquals("secret", parsed.password)
        assertTrue(parsed.useAuth)
    }

    @Test
    fun `exports and parses amir worker ws uri and qr code roundtrip`() {
        val original = ProxyProfile(
            name = "My CloudNG Worker",
            profileType = ProfileType.WORKER_WS,
            uuid = "11111111-2222-3333-4444-555555555555",
            workerHost = "edge.example.workers.dev",
            cleanIp = "172.67.70.244",
            subproto = "chat.v2",
            localPort = 40446,
        )
        val uri = ProxyUriParser.toUri(original)
        assertTrue(uri.startsWith("amir://"))

        val parsed = ProxyUriParser.parse(uri).getOrThrow()
        assertEquals(ProfileType.WORKER_WS, parsed.profileType)
        assertEquals(original.uuid, parsed.uuid)
        assertEquals(original.workerHost, parsed.workerHost)
        assertEquals(original.cleanIp, parsed.cleanIp)
        assertEquals(original.subproto, parsed.subproto)
        assertEquals(original.localPort, parsed.localPort)
        assertEquals(original.name, parsed.name)

        // Verify QR encode -> decode roundtrip
        val qrBitmap = QrCodeUtils.generateQrBitmap(uri, 400)
        assertNotNull(qrBitmap)
        val decoded = QrCodeUtils.decodeQrFromBitmap(qrBitmap!!)
        assertEquals(uri, decoded)
    }

    @Test
    fun `exports and parses amir standard socks5 uri and batch`() {
        val socks = ProxyProfile(
            name = "NL Node",
            profileType = ProfileType.STANDARD_SOCKS5,
            host = "203.0.113.10",
            port = 1080,
            username = "amir",
            password = "p@ssword",
            useAuth = true,
            udpRelay = true,
        )
        val uri = ProxyUriParser.toUri(socks)
        assertTrue(uri.startsWith("amir://"))
        val parsed = ProxyUriParser.parse(uri).getOrThrow()
        assertEquals(ProfileType.STANDARD_SOCKS5, parsed.profileType)
        assertEquals("203.0.113.10", parsed.host)
        assertEquals(1080, parsed.port)
        assertEquals("amir", parsed.username)
        assertEquals("p@ssword", parsed.password)
        assertTrue(parsed.useAuth)
        assertEquals("NL Node", parsed.name)

        val batch = ProxyUriParser.parseBatch("$uri\namir://test-uuid@worker.example.dev?type=ws&cleanIp=1.1.1.1#WS2")
        assertEquals(2, batch.size)
        assertEquals(ProfileType.STANDARD_SOCKS5, batch[0].profileType)
        assertEquals(ProfileType.WORKER_WS, batch[1].profileType)
    }
}
