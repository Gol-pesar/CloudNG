package com.example.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class TunnelStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR,
}

enum class LogLevel {
    INFO,
    SUCCESS,
    WARNING,
    ERROR,
}

data class TunnelLogEntry(
    val id: Long,
    val timestampMs: Long,
    val level: LogLevel,
    val tag: String,
    val message: String,
)

data class TrafficSample(
    val timestampMs: Long,
    val rxBytesPerSec: Long,
    val txBytesPerSec: Long,
)

data class VpnTelemetry(
    val status: TunnelStatus = TunnelStatus.DISCONNECTED,
    val activeProfileId: Long? = null,
    val activeProfileName: String? = null,
    val activeEndpoint: String? = null,
    val connectedSinceMs: Long? = null,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxBytesPerSec: Long = 0L,
    val txBytesPerSec: Long = 0L,
    val activeConnectionCount: Int = 0,
    val speedHistory: List<TrafficSample> = emptyList(),
    val logs: List<TunnelLogEntry> = emptyList(),
    val errorMessage: String? = null,
)

object VpnStateManager {
    private const val MAX_LOGS = 120
    private const val MAX_SAMPLES = 30

    private val _telemetry = MutableStateFlow(VpnTelemetry())
    val telemetry: StateFlow<VpnTelemetry> = _telemetry.asStateFlow()

    private val rxCounter = AtomicLong(0L)
    private val txCounter = AtomicLong(0L)
    private val activeConnections = AtomicInteger(0)
    private val logIdGen = AtomicLong(1L)

    private var lastSampleRx = 0L
    private var lastSampleTx = 0L

    fun onConnecting(profileId: Long, profileName: String, endpoint: String) {
        rxCounter.set(0L)
        txCounter.set(0L)
        activeConnections.set(0)
        lastSampleRx = 0L
        lastSampleTx = 0L
        _telemetry.update { current ->
            current.copy(
                status = TunnelStatus.CONNECTING,
                activeProfileId = profileId,
                activeProfileName = profileName,
                activeEndpoint = endpoint,
                connectedSinceMs = null,
                rxBytes = 0L,
                txBytes = 0L,
                rxBytesPerSec = 0L,
                txBytesPerSec = 0L,
                activeConnectionCount = 0,
                speedHistory = emptyList(),
                errorMessage = null,
            )
        }
        addLog(LogLevel.INFO, "VPN", "شروع اتصال به سرور $profileName ($endpoint)")
    }

    fun onConnected() {
        val now = System.currentTimeMillis()
        _telemetry.update {
            it.copy(
                status = TunnelStatus.CONNECTED,
                connectedSinceMs = now,
                errorMessage = null,
            )
        }
        addLog(LogLevel.SUCCESS, "SOCKS5", "تونل VPN با موفقیت برقرار شد.")
    }

    fun onDisconnected(reason: String? = null) {
        activeConnections.set(0)
        _telemetry.update {
            it.copy(
                status = TunnelStatus.DISCONNECTED,
                connectedSinceMs = null,
                rxBytesPerSec = 0L,
                txBytesPerSec = 0L,
                activeConnectionCount = 0,
                errorMessage = null,
            )
        }
        addLog(LogLevel.INFO, "VPN", reason ?: "اتصال تونل قطع شد.")
    }

    fun onError(message: String) {
        activeConnections.set(0)
        _telemetry.update {
            it.copy(
                status = TunnelStatus.ERROR,
                connectedSinceMs = null,
                rxBytesPerSec = 0L,
                txBytesPerSec = 0L,
                activeConnectionCount = 0,
                errorMessage = message,
            )
        }
        addLog(LogLevel.ERROR, "ERROR", message)
    }

    fun recordRx(bytes: Int) {
        if (bytes > 0) rxCounter.addAndGet(bytes.toLong())
    }

    fun recordTx(bytes: Int) {
        if (bytes > 0) txCounter.addAndGet(bytes.toLong())
    }

    fun incrementActiveConnections() {
        activeConnections.incrementAndGet()
    }

    fun decrementActiveConnections() {
        activeConnections.updateAndGet { if (it > 0) it - 1 else 0 }
    }

    fun sampleBandwidthTick() {
        val totalRx = rxCounter.get()
        val totalTx = txCounter.get()
        val deltaRx = (totalRx - lastSampleRx).coerceAtLeast(0L)
        val deltaTx = (totalTx - lastSampleTx).coerceAtLeast(0L)
        lastSampleRx = totalRx
        lastSampleTx = totalTx
        val now = System.currentTimeMillis()
        val sample = TrafficSample(now, deltaRx, deltaTx)
        val connCount = activeConnections.get()

        _telemetry.update { current ->
            val updatedHistory = (current.speedHistory + sample).takeLast(MAX_SAMPLES)
            current.copy(
                rxBytes = totalRx,
                txBytes = totalTx,
                rxBytesPerSec = deltaRx,
                txBytesPerSec = deltaTx,
                activeConnectionCount = connCount,
                speedHistory = updatedHistory,
            )
        }
    }

    fun addLog(level: LogLevel, tag: String, message: String) {
        val entry = TunnelLogEntry(
            id = logIdGen.getAndIncrement(),
            timestampMs = System.currentTimeMillis(),
            level = level,
            tag = tag,
            message = message,
        )
        _telemetry.update { current ->
            current.copy(logs = (listOf(entry) + current.logs).take(MAX_LOGS))
        }
    }

    fun clearLogs() {
        _telemetry.update { it.copy(logs = emptyList()) }
    }
}
