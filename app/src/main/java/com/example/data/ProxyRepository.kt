package com.example.data

import com.example.ui.theme.ThemePreference
import kotlinx.coroutines.flow.Flow

class ProxyRepository(
    private val dao: ProxyProfileDao,
    private val preferences: UserPreferences,
) {
    val profiles: Flow<List<ProxyProfile>> = dao.observeAll()
    val settings: Flow<AppSettings> = preferences.settings

    suspend fun getProfileById(id: Long): ProxyProfile? = dao.getById(id)

    suspend fun saveProfile(profile: ProxyProfile): Long {
        return if (profile.id == 0L) {
            dao.insert(profile)
        } else {
            dao.update(profile)
            profile.id
        }
    }

    suspend fun saveProfiles(newProfiles: List<ProxyProfile>): List<Long> {
        val insertedIds = mutableListOf<Long>()
        for (p in newProfiles) {
            insertedIds.add(dao.insert(p))
        }
        return insertedIds
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

    suspend fun setPerAppMode(mode: PerAppMode) = preferences.setPerAppMode(mode)

    suspend fun setPerAppPackages(packages: Set<String>) = preferences.setPerAppPackages(packages)

    suspend fun togglePerAppPackage(packageName: String) = preferences.togglePerAppPackage(packageName)
}
