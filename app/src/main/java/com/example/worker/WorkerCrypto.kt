package com.example.worker

import java.net.InetAddress
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object WorkerDefaults {
    const val UUID_STR = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"
    const val WORKER_HOST = "twilight-dream-9e3c.aliahmadiphotoofficial.workers.dev"
    const val CLEAN_IP = "172.67.70.244"
    const val LISTEN_HOST = "127.0.0.1"
    const val LISTEN_PORT = 40446
    const val SUBPROTO = "chat.v2"
    const val MAX_CHUNK = 65536
    const val BUFFER_MAX = 4194304
    const val HANDSHAKE_TIMEOUT_MS = 5000
    const val CONNECT_TIMEOUT_MS = 15000L
    const val ACK_TIMEOUT_MS = 10000L
}

data class InitPacket(val data: ByteArray, val key: ByteArray)

object WorkerCrypto {
    private val rng = SecureRandom()

    fun deriveKey(uuidStr: String, nonce: ByteArray): ByteArray {
        val uuidBytes = uuidStr.toByteArray(Charsets.US_ASCII)
        val out = ByteArray(16)
        for (i in 0 until 16) {
            out[i] = (uuidBytes[i % uuidBytes.size].toInt() xor nonce[i].toInt()).toByte()
        }
        return out
    }

    fun buildInit(
        uuidStr: String,
        host: String,
        port: Int,
        payload: ByteArray = ByteArray(0),
    ): InitPacket {
        val nonce = ByteArray(16).also { rng.nextBytes(it) }
        val key = deriveKey(uuidStr, nonce)

        val addrType: Int
        val addrBytes: ByteArray
        val cleanHost = host.trim().removePrefix("[").removeSuffix("]")
        val isV4 = cleanHost.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
        val isV6 = cleanHost.contains(":")
        if (isV4) {
            addrType = 1
            addrBytes = InetAddress.getByName(cleanHost).address
        } else if (isV6) {
            addrType = 3
            addrBytes = InetAddress.getByName(cleanHost).address
        } else {
            addrType = 2
            val hb = cleanHost.toByteArray(Charsets.UTF_8)
            addrBytes = ByteArray(1 + hb.size)
            addrBytes[0] = hb.size.toByte()
            System.arraycopy(hb, 0, addrBytes, 1, hb.size)
        }

        val bodyLen = 1 + 2 + 1 + addrBytes.size + payload.size
        val body = ByteArray(bodyLen)
        var p = 0
        body[p++] = 1
        body[p++] = ((port ushr 8) and 0xFF).toByte()
        body[p++] = (port and 0xFF).toByte()
        body[p++] = addrType.toByte()
        System.arraycopy(addrBytes, 0, body, p, addrBytes.size)
        p += addrBytes.size
        System.arraycopy(payload, 0, body, p, payload.size)

        val enc = ByteArray(bodyLen)
        for (i in 0 until bodyLen) {
            enc[i] = (body[i].toInt() xor key[i % 16].toInt()).toByte()
        }

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val tag = mac.doFinal(enc).copyOfRange(0, 8)

        val out = ByteArray(16 + bodyLen + 8)
        System.arraycopy(nonce, 0, out, 0, 16)
        System.arraycopy(enc, 0, out, 16, bodyLen)
        System.arraycopy(tag, 0, out, 16 + bodyLen, 8)
        return InitPacket(out, key)
    }

    fun expectedAck(key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal("OK".toByteArray(Charsets.US_ASCII)).copyOfRange(0, 16)
    }

    fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        for (i in data.indices) {
            out[i] = (data[i].toInt() xor key[i % 16].toInt()).toByte()
        }
        return out
    }
}
