package com.example.vpn

import android.net.Network
import android.os.Build
import java.net.Socket

/**
 * Global socket-protection hook registered while [Socks5VpnService] is active so any
 * outbound socket opened by CloudNG (diagnostics, local SOCKS5, WS pool) always bypasses TUN
 * and binds to the active underlying physical network when available.
 */
object VpnSocketProtector {
    @Volatile
    var activeProtector: ((Socket) -> Boolean)? = null

    @Volatile
    var underlyingNetwork: Network? = null

    fun protectAndBind(socket: Socket, explicitProtector: ((Socket) -> Boolean)? = null): Boolean {
        val protector = explicitProtector ?: activeProtector
        if (protector != null && !protector.invoke(socket)) {
            return false
        }
        val net = underlyingNetwork
        if (net != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            runCatching { net.bindSocket(socket) }
        }
        return true
    }

    fun protectIfActive(socket: Socket): Boolean = protectAndBind(socket, null)
}
