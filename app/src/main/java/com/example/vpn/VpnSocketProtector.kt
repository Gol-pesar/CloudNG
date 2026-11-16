package com.example.vpn

import android.net.Network
import android.os.Build
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Global socket-protection hook registered while [Socks5VpnService] is active so any
 * outbound socket opened by CloudNG always allocates its native kernel FD before calling
 * VpnService.protect(), binds to the physical network when needed, and respects UID bypass.
 */
object VpnSocketProtector {
    @Volatile
    var activeProtector: ((Socket) -> Boolean)? = null

    @Volatile
    var underlyingNetwork: Network? = null

    @Volatile
    var selfUidBypassed: Boolean = false

    fun protectAndBind(
        socket: Socket,
        explicitProtector: ((Socket) -> Boolean)? = null,
        targetAddress: InetAddress? = null,
    ): Boolean {
        // Ensure the underlying Linux socket FD exists before VpnService.protect(socket) inspects it
        runCatching {
            socket.tcpNoDelay = true
            socket.reuseAddress = true
            if (!socket.isBound) {
                val bindAddr = when (targetAddress) {
                    is Inet4Address -> InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0))
                    is Inet6Address -> InetAddress.getByAddress(ByteArray(16))
                    else -> null
                }
                if (bindAddr != null) {
                    socket.bind(InetSocketAddress(bindAddr, 0))
                } else {
                    socket.bind(InetSocketAddress(0))
                }
            }
        }

        val protector = explicitProtector ?: activeProtector
        if (protector == null) {
            return true
        }

        val protectedByVpn = runCatching { protector.invoke(socket) }.getOrDefault(false)
        if (protectedByVpn) {
            return true
        }

        val net = underlyingNetwork
        val boundToPhysical = if (net != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            runCatching {
                net.bindSocket(socket)
                true
            }.getOrDefault(false)
        } else {
            false
        }

        // If VpnService.protect returned false (e.g., OEM ROM quirk or pre-establish window),
        // physical network binding or app UID self-bypass guarantees no TUN routing loop.
        return boundToPhysical || selfUidBypassed
    }

    fun protectIfActive(socket: Socket): Boolean = protectAndBind(socket, null, null)
}
