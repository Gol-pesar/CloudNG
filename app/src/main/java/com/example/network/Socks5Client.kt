package com.example.network

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

class Socks5Exception(
    message: String,
    val replyCode: Int? = null,
    cause: Throwable? = null,
) : IOException(message, cause)

object Socks5Client {
    private const val SOCKS_VERSION = 0x05
    private const val AUTH_NONE = 0x00
    private const val AUTH_USER_PASS = 0x02
    private const val AUTH_NO_ACCEPTABLE = 0xFF
    private const val USER_PASS_SUB_VERSION = 0x01

    private const val CMD_CONNECT = 0x01
    private const val RSV = 0x00

    private const val ATYP_IPV4 = 0x01
    private const val ATYP_DOMAIN = 0x03
    private const val ATYP_IPV6 = 0x04

    /**
     * Opens a TCP socket to the SOCKS5 server, performs RFC 1928/1929 handshake & authentication,
     * and establishes a CONNECT tunnel to [targetHost]:[targetPort].
     *
     * Caller owns the returned [Socket] and must close it when finished.
     */
    fun connect(
        proxyHost: String,
        proxyPort: Int,
        username: String = "",
        password: String = "",
        useAuth: Boolean = false,
        targetHost: String,
        targetPort: Int,
        timeoutMs: Int = 8000,
        socketProtector: ((Socket) -> Boolean)? = null,
    ): Socket {
        val socket = Socket()
        try {
            socketProtector?.let { protect ->
                if (!protect(socket)) {
                    throw Socks5Exception("امکان محافظت سوکت در سرویس VPN وجود ندارد.")
                }
            }
            socket.soTimeout = timeoutMs
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)

            val out = socket.getOutputStream()
            val input = DataInputStream(socket.getInputStream())

            // 1. Greeting: VER | NMETHODS | METHODS...
            val methods = if (useAuth && username.isNotEmpty()) {
                byteArrayOf(AUTH_NONE.toByte(), AUTH_USER_PASS.toByte())
            } else {
                byteArrayOf(AUTH_NONE.toByte())
            }
            val greeting = ByteArray(2 + methods.size)
            greeting[0] = SOCKS_VERSION.toByte()
            greeting[1] = methods.size.toByte()
            System.arraycopy(methods, 0, greeting, 2, methods.size)
            out.write(greeting)
            out.flush()

            // 2. Method selection response: VER | METHOD
            val ver = input.readUnsignedByte()
            if (ver != SOCKS_VERSION) {
                throw Socks5Exception("پاسخ سرور با پروتکل SOCKS5 سازگار نیست (نسخه: $ver).")
            }
            val chosenMethod = input.readUnsignedByte()
            when (chosenMethod) {
                AUTH_NONE -> Unit
                AUTH_USER_PASS -> {
                    if (!useAuth) {
                        throw Socks5Exception("سرور نیاز به نام کاربری و رمز عبور دارد.")
                    }
                    performUserPassAuth(out, input, username, password)
                }
                AUTH_NO_ACCEPTABLE -> {
                    throw Socks5Exception("روش احراز هویت مورد تایید سرور نیست.")
                }
                else -> {
                    throw Socks5Exception("روش احراز هویت پشتیبانی نمی‌شود (کد $chosenMethod).")
                }
            }

            // 3. CONNECT request
            val request = buildConnectRequest(targetHost, targetPort)
            out.write(request)
            out.flush()

            // 4. CONNECT reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            val repVer = input.readUnsignedByte()
            if (repVer != SOCKS_VERSION) {
                throw Socks5Exception("نسخه پاسخ اتصال نامعتبر است: $repVer")
            }
            val repCode = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            consumeBoundAddress(input, atyp)

            if (repCode != 0x00) {
                throw Socks5Exception(mapReplyCodeToPersian(repCode), replyCode = repCode)
            }

            return socket
        } catch (t: Throwable) {
            runCatching { socket.close() }
            if (t is Socks5Exception) throw t
            throw Socks5Exception(
                message = t.localizedMessage ?: "خطا در برقراری ارتباط با سرور SOCKS5",
                cause = t,
            )
        }
    }

    private fun performUserPassAuth(
        out: java.io.OutputStream,
        input: DataInputStream,
        username: String,
        password: String,
    ) {
        val userBytes = username.toByteArray(StandardCharsets.UTF_8)
        val passBytes = password.toByteArray(StandardCharsets.UTF_8)
        if (userBytes.size > 255 || passBytes.size > 255) {
            throw Socks5Exception("طول نام کاربری یا رمز عبور بیش از حد مجاز است.")
        }
        val packet = ByteArrayOutputStream(3 + userBytes.size + passBytes.size)
        packet.write(USER_PASS_SUB_VERSION)
        packet.write(userBytes.size)
        packet.write(userBytes)
        packet.write(passBytes.size)
        packet.write(passBytes)
        out.write(packet.toByteArray())
        out.flush()

        val authVer = input.readUnsignedByte()
        val status = input.readUnsignedByte()
        if (authVer != USER_PASS_SUB_VERSION || status != 0x00) {
            throw Socks5Exception("نام کاربری یا رمز عبور پروکسی اشتباه است.")
        }
    }

    private fun buildConnectRequest(targetHost: String, targetPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(SOCKS_VERSION)
        out.write(CMD_CONNECT)
        out.write(RSV)

        val numericIp = parseLiteralIp(targetHost)
        when (numericIp) {
            is Inet4Address -> {
                out.write(ATYP_IPV4)
                out.write(numericIp.address)
            }
            is Inet6Address -> {
                out.write(ATYP_IPV6)
                out.write(numericIp.address)
            }
            else -> {
                val hostBytes = targetHost.toByteArray(StandardCharsets.UTF_8)
                if (hostBytes.isEmpty() || hostBytes.size > 255) {
                    throw Socks5Exception("آدرس مقصد نامعتبر است: $targetHost")
                }
                out.write(ATYP_DOMAIN)
                out.write(hostBytes.size)
                out.write(hostBytes)
            }
        }
        out.write((targetPort ushr 8) and 0xFF)
        out.write(targetPort and 0xFF)
        return out.toByteArray()
    }

    private fun consumeBoundAddress(input: DataInputStream, atyp: Int) {
        when (atyp) {
            ATYP_IPV4 -> {
                val addr = ByteArray(4)
                input.readFully(addr)
            }
            ATYP_IPV6 -> {
                val addr = ByteArray(16)
                input.readFully(addr)
            }
            ATYP_DOMAIN -> {
                val len = input.readUnsignedByte()
                val addr = ByteArray(len)
                input.readFully(addr)
            }
            else -> throw Socks5Exception("نوع آدرس بازگشتی ناشناخته است: $atyp")
        }
        // 2-byte BND.PORT
        input.readUnsignedShort()
    }

    private fun parseLiteralIp(host: String): InetAddress? {
        val clean = host.trim().removePrefix("[").removeSuffix("]")
        val ipv4Regex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        if (ipv4Regex.matches(clean)) {
            val parts = clean.split(".").mapNotNull { it.toIntOrNull() }
            if (parts.size == 4 && parts.all { it in 0..255 }) {
                return InetAddress.getByAddress(parts.map { it.toByte() }.toByteArray())
            }
        }
        if (clean.contains(":")) {
            return runCatching { InetAddress.getByName(clean) }.getOrNull() as? Inet6Address
        }
        return null
    }

    fun mapReplyCodeToPersian(code: Int): String = when (code) {
        0x01 -> "خطای عمومی سرور SOCKS5"
        0x02 -> "اتصال توسط قوانین سرور مجاز نیست"
        0x03 -> "شبکه مقصد در دسترس نیست"
        0x04 -> "میزبان مقصد در دسترس نیست"
        0x05 -> "اتصال توسط مقصد رد شد"
        0x06 -> "زمان اعتبار بسته (TTL) به پایان رسید"
        0x07 -> "دستور ارسالی پشتیبانی نمی‌شود"
        0x08 -> "نوع آدرس مقصد پشتیبانی نمی‌شود"
        else -> "خطای ناشناخته SOCKS5 (کد $code)"
    }
}
