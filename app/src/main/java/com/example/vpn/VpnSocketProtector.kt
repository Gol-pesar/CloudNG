package com.example.vpn

import java.net.Socket

/**
 * Global socket-protection hook registered while [Socks5VpnService] is active so any
 * outbound socket opened by CloudNG (diagnostics, local SOCKS5, WS pool) always bypasses TUN.
 */
object VpnSocketProtector {
    @Volatile
    var activeProtector: ((Socket) -> Boolean)? = null

    fun protectIfActive(socket: Socket): Boolean {
        val protector = activeProtector ?: return true
        return protector(socket)
    }
}
