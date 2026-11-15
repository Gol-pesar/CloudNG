package com.example.data

import com.example.ui.theme.ThemePreference
import com.example.worker.WorkerDefaults
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class ProxyRepository(
    private val dao: ProxyProfileDao,
    private val preferences: UserPreferences,
) {
    val profiles: Flow<List<ProxyProfile>> = dao.observeAll()
    val settings: Flow<AppSettings> = preferences.settings

    suspend fun ensureDefaultWorkerProfileSeeded() {
        val currentSettings = preferences.settings.first()
        if (currentSettings.seededDefaultWorker) return
        val existing = dao.observeAll().first()
        if (existing.isEmpty()) {
            val defaultProfile = ProxyProfile(
                name = "Cloudflare Worker WS",
                profileType = ProfileType.WORKER_WS,
                uuid = WorkerDefaults.UUID_STR,
                workerHost = WorkerDefaults.WORKER_HOST,
                cleanIp = WorkerDefaults.CLEAN_IP,
                subproto = WorkerDefaults.SUBPROTO,
                localPort = WorkerDefaults.LISTEN_PORT,
            )
            val id = dao.insert(defaultProfile)
            preferences.setActiveProfileId(id)
        }
        preferences.markDefaultWorkerSeeded()
    }

    suspend fun getProfileById(id: Long): ProxyProfile? = dao.getById(id)

    suspend fun saveProfile(profile: ProxyProfile): Long {
        return if (profile.id == 0L) {
            dao.insert(profile)
        } else {
            dao.update(profile)
            profile.id
        }
    }

    suspend fun deleteProfile(id: Long) {
        dao.deleteById(id)
    }

    suspend fun updateProbeResult(id: Long, latencyMs: Long?, exitIp: String?) {
        dao.updateProbeResult(
            id = id,
            latencyMs = latencyMs,
            exitIp = exitIp,
            checkedAt = System.currentTimeMillis(),
        )
    }

    suspend fun setActiveProfileId(id: Long?) = preferences.setActiveProfileId(id)

    suspend fun setOperationMode(mode: TunnelOperationMode) = preferences.setOperationMode(mode)

    suspend fun setDnsServer(dns: String) = preferences.setDnsServer(dns)

    suspend fun setBypassLan(enabled: Boolean) = preferences.setBypassLan(enabled)

    suspend fun setRemoteDnsOverTcp(enabled: Boolean) = preferences.setRemoteDnsOverTcp(enabled)

    suspend fun setThemePreference(theme: ThemePreference) =
        preferences.setThemePreference(theme)
}
