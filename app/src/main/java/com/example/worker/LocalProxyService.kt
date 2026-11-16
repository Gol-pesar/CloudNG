package com.example.worker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.data.AppDatabase
import com.example.data.ProfileType
import com.example.vpn.LogLevel
import com.example.vpn.VpnStateManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground service running LocalSocks5Server on 127.0.0.1:<localPort>
 * without requiring system VPN permission when the user selects Local Proxy mode.
 */
class LocalProxyService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessionCounter = AtomicLong(0L)
    @Volatile
    private var activeSessionId = 0L
    private var proxyJob: Job? = null
    private var localServer: LocalSocks5Server? = null
    private var statsJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxy("پروکسی محلی متوقف شد.")
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val profileId = intent.getLongExtra(EXTRA_PROFILE_ID, -1L)
                if (profileId > 0L) {
                    startProxy(profileId)
                } else {
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopResources()
        scope.cancel()
        super.onDestroy()
    }

    private fun startProxy(profileId: Long) {
        val mySessionId = sessionCounter.incrementAndGet()
        activeSessionId = mySessionId
        stopResources()
        ensureChannel()
        startForegroundCompat(buildNotification("در حال راه‌اندازی پروکسی محلی…"))

        proxyJob = scope.launch {
            try {
                val profile = AppDatabase.getInstance(applicationContext)
                    .proxyProfileDao()
                    .getById(profileId)
                if (profile == null) {
                    if (activeSessionId == mySessionId) {
                        VpnStateManager.onError("پروفایل انتخاب‌شده یافت نشد.")
                        stopSelf()
                    }
                    return@launch
                }
                val endpointText = if (profile.profileType == ProfileType.WORKER_WS) {
                    "${WorkerDefaults.LISTEN_HOST}:${profile.localPort} → ${profile.workerHost}"
                } else {
                    "${WorkerDefaults.LISTEN_HOST}:${profile.localPort} → ${profile.endpoint}"
                }
                VpnStateManager.onConnecting(profile.id, profile.name, endpointText)

                val srv = LocalSocks5Server(profile = profile)
                srv.start()
                if (activeSessionId != mySessionId) {
                    srv.stop()
                    return@launch
                }
                localServer = srv

                VpnStateManager.onConnected()
                updateNotification("پروکسی محلی فعال: 127.0.0.1:${profile.localPort}")

                // Non-blocking background connectivity check
                if (profile.profileType == ProfileType.WORKER_WS) {
                    launch {
                        runCatching {
                            val t0 = System.nanoTime()
                            WorkerWsClient.openTunnel(
                                uuid = profile.uuid,
                                workerHost = profile.workerHost,
                                cleanIp = profile.cleanIp,
                                subproto = profile.subproto,
                                targetHost = "8.8.8.8",
                                targetPort = 53,
                            ).close()
                            val ms = ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1L)
                            VpnStateManager.addLog(LogLevel.SUCCESS, "WS", "اتصال Worker تأیید شد (${ms}ms)")
                        }.onFailure { err ->
                            VpnStateManager.addLog(
                                LogLevel.WARNING,
                                "WS",
                                "هشدار تست Worker: ${err.localizedMessage ?: "ناموفق"}",
                            )
                        }
                    }
                }

                statsJob = scope.launch {
                    while (isActive && activeSessionId == mySessionId) {
                        delay(1000L)
                        VpnStateManager.sampleBandwidthTick()
                    }
                }
            } catch (t: Throwable) {
                if (activeSessionId == mySessionId) {
                    VpnStateManager.onError(t.localizedMessage ?: "خطا در راه‌اندازی پروکسی محلی")
                    stopResources()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    private fun stopProxy(reason: String) {
        activeSessionId = sessionCounter.incrementAndGet()
        stopResources()
        VpnStateManager.onDisconnected(reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopResources() {
        statsJob?.cancel()
        statsJob = null
        proxyJob?.cancel()
        proxyJob = null
        WorkerWsPool.clear()
        localServer?.stop()
        localServer = null
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.notif_channel_desc)
                setShowBadge(false)
            }
            mgr?.createNotificationChannel(channel)
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

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            11,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            12,
            Intent(this, LocalProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.action_disconnect), stopIntent)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "socksguard_vpn_channel"
        private const val NOTIFICATION_ID = 4092

        const val ACTION_START = "com.example.worker.ACTION_START_LOCAL"
        const val ACTION_STOP = "com.example.worker.ACTION_STOP_LOCAL"
        const val EXTRA_PROFILE_ID = "extra_profile_id"

        fun start(context: Context, profileId: Long) {
            val intent = Intent(context, LocalProxyService::class.java).apply {
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
            val intent = Intent(context, LocalProxyService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
