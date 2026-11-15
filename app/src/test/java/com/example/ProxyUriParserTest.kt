package com.example

import com.example.data.ProxyUriParser
import org.junit.Assert.assertEquals
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
    fun `parses and serializes ws-socks worker uri`() {
        val original = com.example.data.ProxyProfile(
            name = "My Worker",
            profileType = com.example.data.ProfileType.WORKER_WS,
            uuid = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd",
            workerHost = "twilight-dream-9e3c.aliahmadiphotoofficial.workers.dev",
            cleanIp = "172.67.70.244",
            subproto = "chat.v2",
            localPort = 40446,
        )
        val uri = ProxyUriParser.toUri(original)
        val parsed = ProxyUriParser.parse(uri).getOrThrow()
        assertEquals(com.example.data.ProfileType.WORKER_WS, parsed.profileType)
        assertEquals(original.uuid, parsed.uuid)
        assertEquals(original.workerHost, parsed.workerHost)
        assertEquals(original.cleanIp, parsed.cleanIp)
        assertEquals(original.subproto, parsed.subproto)
        assertEquals(original.localPort, parsed.localPort)
        assertEquals(original.name, parsed.name)
    }
}
