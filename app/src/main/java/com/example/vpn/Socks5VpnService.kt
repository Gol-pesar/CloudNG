package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.data.AppDatabase
import com.example.data.PerAppMode
import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.data.UserPreferences
import com.example.network.Socks5Client
import com.example.worker.LocalSocks5Server
import com.example.worker.WorkerWsClient
import com.example.worker.WorkerWsPool
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream

class Socks5VpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnelJob: Job? = null
    private var statsJob: Job? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetEngine: TunPacketEngine? = null
    private var localSocks5Server: LocalSocks5Server? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel("اتصال توسط کاربر قطع شد.")
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val profileId = intent.getLongExtra(EXTRA_PROFILE_ID, -1L)
                if (profileId > 0L) {
                    startTunnel(profileId)
                } else {
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopTunnel("دسترسی VPN توسط سیستم لغو شد.")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnelResources()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startTunnel(profileId: Long) {
        stopTunnelResources()
        ensureNotificationChannel()
        startForegroundCompat(buildNotification("در حال برقراری تونل…"))

        tunnelJob = serviceScope.launch {
            try {
                val db = AppDatabase.getInstance(applicationContext)
                val prefs = UserPreferences(applicationContext)
                val profile = db.proxyProfileDao().getById(profileId)
                if (profile == null) {
                    VpnStateManager.onError("پروفایل سرور انتخاب‌شده یافت نشد.")
                    stopSelf()
                    return@launch
                }
                val settings = prefs.settings.first()
                VpnStateManager.onConnecting(profile.id, profile.name, profile.endpoint)
                val vpnProtector: (java.net.Socket) -> Boolean = { sock -> protect(sock) }
                VpnSocketProtector.activeProtector = vpnProtector

                // Verify upstream handshake before bringing up TUN routes
                if (profile.profileType == ProfileType.WORKER_WS) {
                    val probeDns = if (settings.dnsServer == "1.1.1.1" || settings.dnsServer == "1.0.0.1") {
                        "8.8.8.8"
                    } else {
                        settings.dnsServer
                    }
                    WorkerWsClient.openTunnel(
                        uuid = profile.uuid,
                        workerHost = profile.workerHost,
                        cleanIp = profile.cleanIp,
                        subproto = profile.subproto,
                        targetHost = probeDns,
                        targetPort = 53,
                        socketProtector = vpnProtector,
                    ).close()
                } else {
                    Socks5Client.connect(
                        proxyHost = profile.host,
                        proxyPort = profile.port,
                        username = profile.username,
                        password = profile.password,
                        useAuth = profile.useAuth,
                        targetHost = settings.dnsServer,
                        targetPort = 53,
                        timeoutMs = 7000,
                        socketProtector = vpnProtector,
                    ).use { _ -> }
                }

                val pfd = establishVpnInterface(
                    profile = profile,
                    dnsServer = settings.dnsServer,
                    bypassLan = settings.bypassLan,
                    perAppMode = settings.perAppMode,
                    perAppPackages = settings.perAppPackages,
                )
                if (pfd == null) {
                    VpnStateManager.onError("ایجاد رابط TUN توسط سیستم‌عامل رد شد.")
                    stopSelf()
                    return@launch
                }
                vpnInterface = pfd

                val tunIn = FileInputStream(pfd.fileDescriptor)
                val tunOut = FileOutputStream(pfd.fileDescriptor)
                val engine = TunPacketEngine(
                    scope = serviceScope,
                    profile = profile,
                    dnsServer = settings.dnsServer,
                    remoteDnsOverTcp = settings.remoteDnsOverTcp,
                    tunOutput = tunOut,
                    protectSocket = vpnProtector,
                )
                packetEngine = engine

                // Also expose local 127.0.0.1:<localPort> SOCKS5 listener while VPN is active
                runCatching {
                    val srv = LocalSocks5Server(
                        profile = profile,
                        socketProtector = vpnProtector,
                    )
                    srv.start()
                    localSocks5Server = srv
                }

                if (profile.profileType == ProfileType.WORKER_WS) {
                    WorkerWsPool.startWarming(
                        workerHost = profile.workerHost,
                        cleanIp = profile.cleanIp,
                        subproto = profile.subproto,
                        socketProtector = vpnProtector,
                    )
                }

                VpnStateManager.onConnected()
                updateNotification("متصل به ${profile.name} (${profile.endpoint})")

                statsJob = serviceScope.launch {
                    while (isActive) {
                        delay(1000L)
                        VpnStateManager.sampleBandwidthTick()
                    }
                }

                val buffer = ByteArray(32767)
                while (isActive) {
                    val read = tunIn.read(buffer)
                    if (read > 0) {
                        engine.processPacket(buffer, read)
                    } else if (read < 0) {
                        break
                    }
                }
            } catch (t: Throwable) {
                VpnStateManager.onError(t.localizedMessage ?: "خطا در برقراری تونل")
            } finally {
                stopTunnelResources()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun establishVpnInterface(
        profile: ProxyProfile,
        dnsServer: String,
        bypassLan: Boolean,
        perAppMode: PerAppMode,
        perAppPackages: Set<String>,
    ): ParcelFileDescriptor? {
        val selfPkg = applicationContext.packageName
        val builder = Builder()
            .setSession("CloudNG - ${profile.name}")
            .setMtu(1500)
            .addAddress("10.8.0.2", 24)
            .addDnsServer(dnsServer)

        when (perAppMode) {
            PerAppMode.ALL_APPS -> {
                val selfBypassed = runCatching { builder.addDisallowedApplication(selfPkg) }.isSuccess
                if (!selfBypassed) {
                    runCatching { builder.addDisallowedApplication(packageName) }
                }
                VpnStateManager.addLog(LogLevel.INFO, "BYPASS", "خود برنامه ($selfPkg) از تونل Bypass شد.")
            }
            PerAppMode.BYPASS_SELECTED -> {
                runCatching { builder.addDisallowedApplication(selfPkg) }
                var extraCount = 0
                for (pkg in perAppPackages) {
                    val cleanPkg = pkg.trim()
                    if (cleanPkg.isNotEmpty() && cleanPkg != selfPkg) {
                        if (runCatching { builder.addDisallowedApplication(cleanPkg) }.isSuccess) {
                            extraCount++
                        }
                    }
                }
                VpnStateManager.addLog(
                    LogLevel.INFO,
                    "BYPASS",
                    "خود برنامه + $extraCount برنامه انتخاب‌شده Bypass شدند.",
                )
            }
            PerAppMode.PROXY_SELECTED -> {
                val allowedApps = perAppPackages
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && it != selfPkg }
                    .distinct()
                var addedCount = 0
                for (pkg in allowedApps) {
                    if (runCatching { builder.addAllowedApplication(pkg) }.isSuccess) {
                        addedCount++
                    }
                }
                if (addedCount == 0) {
                    // Never allow self package into TUN when no allowed apps succeeded
                    runCatching { builder.addDisallowedApplication(selfPkg) }
                    VpnStateManager.addLog(
                        LogLevel.WARNING,
                        "BYPASS",
                        "هیچ برنامه‌ای برای تونل انتخاب نشد؛ خود برنامه ($selfPkg) Bypass شد.",
                    )
                } else {
                    VpnStateManager.addLog(
                        LogLevel.INFO,
                        "PER-APP",
                        "فقط $addedCount برنامه از تونل عبور می‌کنند (خود برنامه Bypass است).",
                    )
                }
            }
        }

        if (bypassLan) {
            for (cidr in RouteCalculator.publicRoutesExcludingPrivate()) {
                builder.addRoute(cidr.address, cidr.prefix)
            }
        } else {
            builder.addRoute("0.0.0.0", 0)
        }

        return builder.establish()
    }

    private fun stopTunnel(reason: String) {
        stopTunnelResources()
        VpnStateManager.onDisconnected(reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopTunnelResources() {
        VpnSocketProtector.activeProtector = null
        statsJob?.cancel()
        statsJob = null
        tunnelJob?.cancel()
        tunnelJob = null
        WorkerWsPool.clear()
        localSocks5Server?.stop()
        localSocks5Server = null
        packetEngine?.closeAll()
        packetEngine = null
        runCatching { vpnInterface?.close() }
        vpnInterface = null
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.notif_channel_desc)
                setShowBadge(false)
            }
            manager?.createNotificationChannel(channel)
        }
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(contentText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification(contentText))
    }

    private fun buildNotification(contentText: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, Socks5VpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(contentText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.action_disconnect), stopIntent)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "socksguard_vpn_channel"
        private const val NOTIFICATION_ID = 4091

        const val ACTION_START = "com.example.vpn.ACTION_START"
        const val ACTION_STOP = "com.example.vpn.ACTION_STOP"
        const val EXTRA_PROFILE_ID = "extra_profile_id"

        fun start(context: Context, profileId: Long) {
            val intent = Intent(context, Socks5VpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PROFILE_ID, profileId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, Socks5VpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}

data class CidrBlock(val address: String, val prefix: Int)

object RouteCalculator {
    private data class Range(val start: Long, val end: Long)

    fun publicRoutesExcludingPrivate(): List<CidrBlock> {
        val excluded = listOf(
            cidrToRange("10.0.0.0", 8),
            cidrToRange("127.0.0.0", 8),
            cidrToRange("169.254.0.0", 16),
            cidrToRange("172.16.0.0", 12),
            cidrToRange("192.168.0.0", 16),
            cidrToRange("224.0.0.0", 4),
            cidrToRange("240.0.0.0", 4),
        )
        var allowed = listOf(Range(0x00000000L, 0xFFFFFFFFL))
        for (ex in excluded) {
            val next = mutableListOf<Range>()
            for (r in allowed) {
                if (ex.end < r.start || ex.start > r.end) {
                    next.add(r)
                } else {
                    if (ex.start > r.start) {
                        next.add(Range(r.start, ex.start - 1L))
                    }
                    if (ex.end < r.end) {
                        next.add(Range(ex.end + 1L, r.end))
                    }
                }
            }
            allowed = next
        }

        val blocks = mutableListOf<CidrBlock>()
        for (r in allowed) {
            decomposeRangeToCidrs(r.start, r.end, blocks)
        }
        return blocks
    }

    private fun cidrToRange(ip: String, prefix: Int): Range {
        val parts = ip.split(".").map { it.toLong() }
        val base = (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
        val size = 1L shl (32 - prefix)
        return Range(base, base + size - 1L)
    }

    private fun decomposeRangeToCidrs(startIn: Long, end: Long, out: MutableList<CidrBlock>) {
        var cur = startIn
        while (cur <= end) {
            var maxPrefix = 32
            while (maxPrefix > 0) {
                val mask = (1L shl (32 - (maxPrefix - 1))) - 1L
                if ((cur and mask) != 0L) break
                val nextEnd = cur + mask
                if (nextEnd > end) break
                maxPrefix--
            }
            val addr = "${(cur ushr 24) and 0xFF}.${(cur ushr 16) and 0xFF}.${(cur ushr 8) and 0xFF}.${cur and 0xFF}"
            out.add(CidrBlock(addr, maxPrefix))
            cur += (1L shl (32 - maxPrefix))
        }
    }
}
