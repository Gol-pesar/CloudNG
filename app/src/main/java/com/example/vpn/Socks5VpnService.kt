package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import kotlinx.coroutines.CancellationException
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
import java.io.InterruptedIOException
import java.util.concurrent.atomic.AtomicLong

class Socks5VpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessionCounter = AtomicLong(0L)
    @Volatile
    private var activeSessionId = 0L
    private var tunnelJob: Job? = null
    private var statsJob: Job? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetEngine: TunPacketEngine? = null
    private var localSocks5Server: LocalSocks5Server? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

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
        activeSessionId = sessionCounter.incrementAndGet()
        stopTunnelResources()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startTunnel(profileId: Long) {
        val mySessionId = sessionCounter.incrementAndGet()
        activeSessionId = mySessionId
        stopTunnelResources()
        ensureNotificationChannel()
        startForegroundCompat(buildNotification("در حال برقراری تونل…"))

        tunnelJob = serviceScope.launch {
            try {
                val db = AppDatabase.getInstance(applicationContext)
                val prefs = UserPreferences(applicationContext)
                val profile = db.proxyProfileDao().getById(profileId)
                if (profile == null) {
                    if (activeSessionId == mySessionId) {
                        VpnStateManager.onError("پروفایل سرور انتخاب‌شده یافت نشد.")
                        stopSelf()
                    }
                    return@launch
                }

                if (profile.profileType == ProfileType.WORKER_WS) {
                    if (profile.workerHost.isBlank() || profile.uuid.isBlank()) {
                        if (activeSessionId == mySessionId) {
                            VpnStateManager.onError("مشخصات سرور Worker (آدرس یا UUID) کامل نیست.")
                            stopSelf()
                        }
                        return@launch
                    }
                } else if (profile.host.isBlank() || profile.port !in 1..65535) {
                    if (activeSessionId == mySessionId) {
                        VpnStateManager.onError("آدرس یا پورت سرور SOCKS5 معتبر نیست.")
                        stopSelf()
                    }
                    return@launch
                }

                val settings = prefs.settings.first()
                VpnStateManager.onConnecting(profile.id, profile.name, profile.endpoint)

                val physicalNetwork = findUnderlyingPhysicalNetwork()
                val vpnProtector: (java.net.Socket) -> Boolean = { sock -> protect(sock) }
                VpnSocketProtector.activeProtector = vpnProtector
                VpnSocketProtector.underlyingNetwork = physicalNetwork
                registerUnderlyingNetworkCallback()

                val pfd = establishVpnInterface(
                    profile = profile,
                    dnsServer = settings.dnsServer,
                    bypassLan = settings.bypassLan,
                    perAppMode = settings.perAppMode,
                    perAppPackages = settings.perAppPackages,
                    underlyingNet = physicalNetwork,
                )
                if (pfd == null) {
                    if (activeSessionId == mySessionId) {
                        VpnStateManager.onError("ایجاد رابط TUN توسط سیستم‌عامل رد شد.")
                        stopSelf()
                    }
                    return@launch
                }
                if (activeSessionId != mySessionId || !isActive) {
                    runCatching { pfd.close() }
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

                // Non-blocking background verification so VPN startup never stalls or aborts on slow handshakes
                launch {
                    runCatching {
                        val t0 = System.nanoTime()
                        if (profile.profileType == ProfileType.WORKER_WS) {
                            WorkerWsClient.openTunnel(
                                uuid = profile.uuid,
                                workerHost = profile.workerHost,
                                cleanIp = profile.cleanIp,
                                subproto = profile.subproto,
                                targetHost = "8.8.8.8",
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
                                timeoutMs = 6000,
                                socketProtector = vpnProtector,
                            ).use { _ -> }
                        }
                        val ms = ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1L)
                        VpnStateManager.addLog(LogLevel.SUCCESS, "CORE", "مسیر بالادست آماده است (${ms}ms)")
                    }.onFailure { err ->
                        VpnStateManager.addLog(
                            LogLevel.WARNING,
                            "CORE",
                            "هشدار بررسی اولیه مسیر: ${err.localizedMessage ?: "ناموفق"}",
                        )
                    }
                }

                statsJob = serviceScope.launch {
                    while (isActive && activeSessionId == mySessionId) {
                        delay(1000L)
                        VpnStateManager.sampleBandwidthTick()
                    }
                }

                val buffer = ByteArray(32767)
                while (isActive && activeSessionId == mySessionId) {
                    val read = try {
                        tunIn.read(buffer)
                    } catch (_: InterruptedIOException) {
                        continue
                    }
                    if (read > 0) {
                        engine.processPacket(buffer, read)
                    } else if (read < 0) {
                        break
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (t: Throwable) {
                if (activeSessionId == mySessionId) {
                    VpnStateManager.onError(t.localizedMessage ?: "خطا در برقراری تونل")
                }
            } finally {
                if (activeSessionId == mySessionId) {
                    stopTunnelResources()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    private fun findUnderlyingPhysicalNetwork(): Network? {
        return runCatching {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return null
            val active = cm.activeNetwork
            if (active != null) {
                val caps = cm.getNetworkCapabilities(active)
                if (caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    return active
                }
            }
            @Suppress("DEPRECATION")
            cm.allNetworks.firstOrNull { net ->
                val caps = cm.getNetworkCapabilities(net)
                caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        }.getOrNull()
    }

    private fun registerUnderlyingNetworkCallback() {
        unregisterUnderlyingNetworkCallback()
        runCatching {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    updateUnderlyingPhysicalNetwork(network)
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        updateUnderlyingPhysicalNetwork(network)
                    }
                }

                override fun onLost(network: Network) {
                    if (VpnSocketProtector.underlyingNetwork == network) {
                        val fallback = findUnderlyingPhysicalNetwork()
                        updateUnderlyingPhysicalNetwork(fallback)
                    }
                }
            }
            cm.registerNetworkCallback(request, cb)
            networkCallback = cb
        }
    }

    private fun updateUnderlyingPhysicalNetwork(network: Network?) {
        VpnSocketProtector.underlyingNetwork = network
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1 && vpnInterface != null) {
            runCatching {
                setUnderlyingNetworks(if (network != null) arrayOf(network) else null)
            }
        }
    }

    private fun unregisterUnderlyingNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    private fun establishVpnInterface(
        profile: ProxyProfile,
        dnsServer: String,
        bypassLan: Boolean,
        perAppMode: PerAppMode,
        perAppPackages: Set<String>,
        underlyingNet: Network?,
    ): ParcelFileDescriptor? {
        val selfPkg = applicationContext.packageName
        val builder = Builder()
            .setSession("CloudNG - ${profile.name}")
            .setMtu(1400)
            .addAddress("10.8.0.2", 24)
            .addDnsServer(dnsServer)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1 && underlyingNet != null) {
            runCatching { builder.setUnderlyingNetworks(arrayOf(underlyingNet)) }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { builder.setMetered(false) }
        }

        when (perAppMode) {
            PerAppMode.ALL_APPS -> {
                val selfBypassed = runCatching { builder.addDisallowedApplication(selfPkg) }.isSuccess ||
                    runCatching { builder.addDisallowedApplication(packageName) }.isSuccess
                VpnSocketProtector.selfUidBypassed = selfBypassed
                VpnStateManager.addLog(LogLevel.INFO, "BYPASS", "خود برنامه ($selfPkg) از تونل Bypass شد.")
            }
            PerAppMode.BYPASS_SELECTED -> {
                val selfBypassed = runCatching { builder.addDisallowedApplication(selfPkg) }.isSuccess ||
                    runCatching { builder.addDisallowedApplication(packageName) }.isSuccess
                VpnSocketProtector.selfUidBypassed = selfBypassed
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
                    .filter { it.isNotEmpty() && it != selfPkg && it != packageName }
                    .distinct()
                var addedCount = 0
                for (pkg in allowedApps) {
                    if (runCatching { builder.addAllowedApplication(pkg) }.isSuccess) {
                        addedCount++
                    }
                }
                if (addedCount == 0) {
                    val selfBypassed = runCatching { builder.addDisallowedApplication(selfPkg) }.isSuccess ||
                        runCatching { builder.addDisallowedApplication(packageName) }.isSuccess
                    VpnSocketProtector.selfUidBypassed = selfBypassed
                    VpnStateManager.addLog(
                        LogLevel.WARNING,
                        "BYPASS",
                        "هیچ برنامه‌ای برای تونل انتخاب نشد؛ خود برنامه ($selfPkg) Bypass شد.",
                    )
                } else {
                    // Only allowlisted apps enter TUN, so CloudNG's own UID is inherently bypassed
                    VpnSocketProtector.selfUidBypassed = true
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

        // Capture global IPv6 inside TUN so carrier IPv6 cannot leak or stall Happy Eyeballs
        runCatching {
            builder.addAddress("fd00:10:8::2", 126)
            builder.addRoute("2000::", 3)
        }

        return builder.establish()
    }

    private fun stopTunnel(reason: String) {
        activeSessionId = sessionCounter.incrementAndGet()
        stopTunnelResources()
        VpnStateManager.onDisconnected(reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopTunnelResources() {
        unregisterUnderlyingNetworkCallback()
        VpnSocketProtector.activeProtector = null
        VpnSocketProtector.underlyingNetwork = null
        VpnSocketProtector.selfUidBypassed = false
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
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
            .setSmallIcon(R.drawable.ic_vpn_notification)
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
