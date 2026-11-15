package com.example.vpn

/**
 * Pure-Kotlin Xray-style protocol sniffer for TLS ClientHello SNI and HTTP Host headers.
 * Allows routing by domain name (remote DNS resolution on the Worker/SOCKS5 exit)
 * even when the client connects using an IP address from local/cached/DoH DNS.
 */
object TrafficSniffer {

    private val HTTP_METHODS = listOf(
        "GET ",
        "POST ",
        "HEAD ",
        "PUT ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
    )

    fun sniffDomain(payload: ByteArray, dstPort: Int): String? {
        if (payload.isEmpty()) return null
        // Check TLS ClientHello first (works on 443 and non-standard TLS ports)
        sniffTlsSni(payload)?.let { return it }
        // Fallback to HTTP Host header on HTTP ports or clear HTTP payloads
        if (dstPort == 80 || dstPort == 8080 || looksLikeHttp(payload)) {
            sniffHttpHost(payload)?.let { return it }
        }
        return null
    }

    fun sniffTlsSni(data: ByteArray): String? {
        // Minimum TLS record header (5) + handshake header (4) + ClientHello fixed fields (34)
        if (data.size < 43) return null
        if ((data[0].toInt() and 0xFF) != 0x16) return null // ContentType = Handshake
        val major = data[1].toInt() and 0xFF
        if (major != 0x03) return null // SSL 3.0 / TLS 1.x

        val recordLen = readU16(data, 3)
        val recordEnd = (5 + recordLen).coerceAtMost(data.size)
        if (recordEnd < 43) return null

        var pos = 5
        if ((data[pos].toInt() and 0xFF) != 0x01) return null // HandshakeType = ClientHello
        pos += 4 // skip type(1) + length(3)
        if (pos + 34 > recordEnd) return null

        pos += 2 // client_version
        pos += 32 // random

        // Session ID
        if (pos + 1 > recordEnd) return null
        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > recordEnd) return null

        // Cipher suites
        val cipherSuitesLen = readU16(data, pos)
        pos += 2 + cipherSuitesLen
        if (pos + 1 > recordEnd) return null

        // Compression methods
        val compressionLen = data[pos].toInt() and 0xFF
        pos += 1 + compressionLen
        if (pos + 2 > recordEnd) return null

        // Extensions length
        val extensionsLen = readU16(data, pos)
        pos += 2
        val extensionsEnd = (pos + extensionsLen).coerceAtMost(recordEnd)

        while (pos + 4 <= extensionsEnd) {
            val extType = readU16(data, pos)
            val extLen = readU16(data, pos + 2)
            pos += 4
            if (pos + extLen > extensionsEnd) break

            if (extType == 0x0000 && extLen >= 5) { // server_name extension
                val listLen = readU16(data, pos)
                var sniPos = pos + 2
                val listEnd = (sniPos + listLen).coerceAtMost(pos + extLen)
                while (sniPos + 3 <= listEnd) {
                    val nameType = data[sniPos].toInt() and 0xFF
                    val nameLen = readU16(data, sniPos + 1)
                    sniPos += 3
                    if (sniPos + nameLen > listEnd) break
                    if (nameType == 0x00 && nameLen in 1..253) {
                        val host = String(data, sniPos, nameLen, Charsets.US_ASCII).trim().lowercase()
                        if (isValidDomain(host)) return host
                    }
                    sniPos += nameLen
                }
            }
            pos += extLen
        }
        return null
    }

    fun sniffHttpHost(data: ByteArray): String? {
        if (!looksLikeHttp(data)) return null
        val limit = data.size.coerceAtMost(2048)
        val headerText = String(data, 0, limit, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n", "\n")
        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isEmpty()) break
            if (line.startsWith("Host:", ignoreCase = true)) {
                val raw = line.substring(5).trim()
                val withoutPort = if (raw.startsWith("[")) {
                    raw
                } else {
                    raw.substringBefore(':')
                }.trim().lowercase()
                if (isValidDomain(withoutPort)) return withoutPort
            }
        }
        return null
    }

    private fun looksLikeHttp(data: ByteArray): Boolean {
        val sampleLen = data.size.coerceAtMost(10)
        if (sampleLen < 4) return false
        val prefix = String(data, 0, sampleLen, Charsets.US_ASCII)
        return HTTP_METHODS.any { prefix.startsWith(it) }
    }

    private fun isValidDomain(host: String): Boolean {
        if (host.isEmpty() || host.length > 253) return false
        if (host.all { it.isDigit() || it == '.' }) return false // ignore bare IPv4
        if (host.contains(':')) return false // ignore IPv6
        return host.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' || it == '_' }
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
}
