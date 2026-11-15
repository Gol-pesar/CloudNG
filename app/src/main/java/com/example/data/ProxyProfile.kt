package com.example.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.example.worker.WorkerDefaults

enum class ProfileType {
    WORKER_WS,
    STANDARD_SOCKS5,
}

enum class TunnelOperationMode {
    VPN_TUNNEL,
    LOCAL_SOCKS5,
}

@Entity(tableName = "proxy_profiles")
data class ProxyProfile(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val name: String,
    val profileType: ProfileType = ProfileType.STANDARD_SOCKS5,
    // Standard SOCKS5 fields
    val host: String = "",
    val port: Int = 1080,
    val username: String = "",
    val password: String = "",
    val useAuth: Boolean = false,
    val udpRelay: Boolean = true,
    // Cloudflare Worker WS Tunnel fields
    val uuid: String = "",
    val workerHost: String = "",
    val cleanIp: String = "",
    val subproto: String = WorkerDefaults.SUBPROTO,
    val localPort: Int = WorkerDefaults.LISTEN_PORT,
    // Diagnostics cache
    val lastLatencyMs: Long? = null,
    val lastExitIp: String? = null,
    val lastCheckedAt: Long? = null,
    val createdAt: Long = System.currentTimeMillis(),
) {
    val endpoint: String
        get() = when (profileType) {
            ProfileType.WORKER_WS -> {
                val target = cleanIp.ifBlank { workerHost }
                "$target → $workerHost"
            }
            ProfileType.STANDARD_SOCKS5 -> {
                if (host.contains(":") && !host.startsWith("[")) "[$host]:$port" else "$host:$port"
            }
        }
}
