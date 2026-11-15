package com.example.data

import android.net.Uri
import com.example.worker.WorkerDefaults
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object ProxyUriParser {

    fun parse(rawInput: String): Result<ProxyProfile> {
        val input = rawInput.trim()
        if (input.isEmpty()) {
            return Result.failure(IllegalArgumentException("ورودی لینک یا آدرس خالی است."))
        }

        if (input.startsWith("ws-socks://", ignoreCase = true)) {
            return parseWorkerUri(input)
        }

        if (input.startsWith("tg://socks", ignoreCase = true) ||
            input.contains("t.me/socks", ignoreCase = true)
        ) {
            return parseTelegramSocksLink(input)
        }

        if (input.startsWith("socks5://", ignoreCase = true) ||
            input.startsWith("socks://", ignoreCase = true) ||
            input.startsWith("socks5h://", ignoreCase = true)
        ) {
            return parseStandardSocksUri(input)
        }

        return parseColonFormat(input)
    }

    private fun parseWorkerUri(input: String): Result<ProxyProfile> {
        return runCatching {
            val uri = Uri.parse(input)
            val uuid = uri.userInfo?.let { decode(it) }?.trim().orEmpty()
            val workerHost = uri.host?.trim().orEmpty()
            if (uuid.isEmpty() || workerHost.isEmpty()) {
                throw IllegalArgumentException("UUID یا آدرس Worker در لینک نامعتبر است.")
            }
            val cleanIp = uri.getQueryParameter("cleanIp")?.trim().orEmpty()
            val subproto = uri.getQueryParameter("subproto")?.trim().orEmpty()
                .ifEmpty { WorkerDefaults.SUBPROTO }
            val localPort = uri.getQueryParameter("localPort")?.trim()?.toIntOrNull()
                ?.takeIf { it in 1024..65535 } ?: WorkerDefaults.LISTEN_PORT
            val name = uri.fragment?.let { decode(it) }?.trim().orEmpty()
                .ifEmpty { workerHost }

            ProxyProfile(
                name = name,
                profileType = ProfileType.WORKER_WS,
                uuid = uuid,
                workerHost = workerHost,
                cleanIp = cleanIp,
                subproto = subproto,
                localPort = localPort,
            )
        }
    }

    private fun parseTelegramSocksLink(input: String): Result<ProxyProfile> {
        return runCatching {
            val uri = Uri.parse(input)
            val server = uri.getQueryParameter("server")?.trim().orEmpty()
            val port = uri.getQueryParameter("port")?.trim()?.toIntOrNull()
                ?: throw IllegalArgumentException("پورت نامعتبر در لینک تلگرام")
            if (server.isEmpty() || port !in 1..65535) {
                throw IllegalArgumentException("آدرس یا پورت سرور نامعتبر است.")
            }
            val user = uri.getQueryParameter("user")?.trim().orEmpty()
            val pass = uri.getQueryParameter("pass")?.trim().orEmpty()
            val useAuth = user.isNotEmpty() || pass.isNotEmpty()
            ProxyProfile(
                name = server,
                profileType = ProfileType.STANDARD_SOCKS5,
                host = server,
                port = port,
                username = user,
                password = pass,
                useAuth = useAuth,
            )
        }
    }

    private fun parseStandardSocksUri(input: String): Result<ProxyProfile> {
        return runCatching {
            val normalized = input
                .replaceFirst(Regex("^socks5h://", RegexOption.IGNORE_CASE), "socks5://")
                .replaceFirst(Regex("^socks://", RegexOption.IGNORE_CASE), "socks5://")
            val uri = Uri.parse(normalized)
            val host = uri.host?.trim().orEmpty()
            val port = if (uri.port > 0) uri.port else 1080
            if (host.isEmpty() || port !in 1..65535) {
                throw IllegalArgumentException("آدرس یا پورت سرور در لینک معتبر نیست.")
            }
            val userInfo = uri.encodedUserInfo
            var username = ""
            var password = ""
            var useAuth = false
            if (!userInfo.isNullOrEmpty()) {
                useAuth = true
                val idx = userInfo.indexOf(':')
                if (idx >= 0) {
                    username = decode(userInfo.substring(0, idx))
                    password = decode(userInfo.substring(idx + 1))
                } else {
                    username = decode(userInfo)
                }
            }
            val fragmentName = uri.fragment?.let { decode(it) }?.trim().orEmpty()
            val name = fragmentName.ifEmpty { "$host:$port" }
            ProxyProfile(
                name = name,
                profileType = ProfileType.STANDARD_SOCKS5,
                host = host,
                port = port,
                username = username,
                password = password,
                useAuth = useAuth,
            )
        }
    }

    private fun parseColonFormat(input: String): Result<ProxyProfile> {
        return runCatching {
            val parts = input.split(":")
            if (parts.size < 2) {
                throw IllegalArgumentException("فرمت صحیح نیست. مثال: socks5://user:pass@host:1080 یا ws-socks://...")
            }
            val host = parts[0].trim()
            val port = parts[1].trim().toIntOrNull()
                ?: throw IllegalArgumentException("شماره پورت باید عدد بین ۱ تا ۶۵۵۳۵ باشد.")
            if (host.isEmpty() || port !in 1..65535) {
                throw IllegalArgumentException("آدرس یا پورت سرور نامعتبر است.")
            }
            val username = parts.getOrNull(2)?.trim().orEmpty()
            val password = parts.getOrNull(3)?.trim().orEmpty()
            val useAuth = username.isNotEmpty() || password.isNotEmpty()
            ProxyProfile(
                name = "$host:$port",
                profileType = ProfileType.STANDARD_SOCKS5,
                host = host,
                port = port,
                username = username,
                password = password,
                useAuth = useAuth,
            )
        }
    }

    fun toUri(profile: ProxyProfile): String {
        if (profile.profileType == ProfileType.WORKER_WS) {
            val tag = if (profile.name.isNotBlank()) "#${encode(profile.name)}" else ""
            return "ws-socks://${encode(profile.uuid)}@${profile.workerHost}" +
                "?cleanIp=${encode(profile.cleanIp)}" +
                "&subproto=${encode(profile.subproto)}" +
                "&localPort=${profile.localPort}$tag"
        }

        val authPart = if (profile.useAuth && profile.username.isNotEmpty()) {
            val u = encode(profile.username)
            val p = encode(profile.password)
            "$u:$p@"
        } else {
            ""
        }
        val hostPart = if (profile.host.contains(":") && !profile.host.startsWith("[")) {
            "[${profile.host}]"
        } else {
            profile.host
        }
        val tag = if (profile.name.isNotBlank() && profile.name != profile.endpoint) {
            "#${encode(profile.name)}"
        } else {
            ""
        }
        return "socks5://$authPart$hostPart:${profile.port}$tag"
    }

    private fun decode(value: String): String =
        URLDecoder.decode(value, StandardCharsets.UTF_8.name())

    private fun encode(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20")
}
