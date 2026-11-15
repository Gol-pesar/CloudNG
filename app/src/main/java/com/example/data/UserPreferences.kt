package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.ui.theme.ThemePreference
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "socksguard_prefs")

data class AppSettings(
    val activeProfileId: Long? = null,
    val operationMode: TunnelOperationMode = TunnelOperationMode.VPN_TUNNEL,
    val dnsServer: String = "8.8.8.8",
    val bypassLan: Boolean = true,
    val remoteDnsOverTcp: Boolean = true,
    val themePreference: ThemePreference = ThemePreference.DARK,
    val seededDefaultWorker: Boolean = false,
)

class UserPreferences(private val context: Context) {
    private object Keys {
        val ACTIVE_PROFILE_ID = longPreferencesKey("active_profile_id")
        val OPERATION_MODE = stringPreferencesKey("operation_mode")
        val DNS_SERVER = stringPreferencesKey("dns_server")
        val BYPASS_LAN = booleanPreferencesKey("bypass_lan")
        val REMOTE_DNS_OVER_TCP = booleanPreferencesKey("remote_dns_over_tcp")
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val SEEDED_DEFAULT_WORKER = booleanPreferencesKey("seeded_default_worker")
    }

    val settings: Flow<AppSettings> = context.dataStore.data.map { prefs ->
        val activeId = prefs[Keys.ACTIVE_PROFILE_ID]?.takeIf { it > 0L }
        val modeStr = prefs[Keys.OPERATION_MODE] ?: TunnelOperationMode.VPN_TUNNEL.name
        val mode = runCatching { TunnelOperationMode.valueOf(modeStr) }.getOrDefault(TunnelOperationMode.VPN_TUNNEL)
        val themeStr = prefs[Keys.THEME_MODE] ?: ThemePreference.DARK.name
        val theme = runCatching { ThemePreference.valueOf(themeStr) }.getOrDefault(ThemePreference.DARK)
        AppSettings(
            activeProfileId = activeId,
            operationMode = mode,
            dnsServer = prefs[Keys.DNS_SERVER]?.takeIf { it.isNotBlank() } ?: "8.8.8.8",
            bypassLan = prefs[Keys.BYPASS_LAN] ?: true,
            remoteDnsOverTcp = prefs[Keys.REMOTE_DNS_OVER_TCP] ?: true,
            themePreference = theme,
            seededDefaultWorker = prefs[Keys.SEEDED_DEFAULT_WORKER] ?: false,
        )
    }

    suspend fun setActiveProfileId(id: Long?) {
        context.dataStore.edit { prefs ->
            if (id == null || id <= 0L) {
                prefs.remove(Keys.ACTIVE_PROFILE_ID)
            } else {
                prefs[Keys.ACTIVE_PROFILE_ID] = id
            }
        }
    }

    suspend fun setOperationMode(mode: TunnelOperationMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.OPERATION_MODE] = mode.name
        }
    }

    suspend fun setDnsServer(dns: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.DNS_SERVER] = dns.trim().ifEmpty { "8.8.8.8" }
        }
    }

    suspend fun setBypassLan(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.BYPASS_LAN] = enabled
        }
    }

    suspend fun setRemoteDnsOverTcp(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.REMOTE_DNS_OVER_TCP] = enabled
        }
    }

    suspend fun setThemePreference(theme: ThemePreference) {
        context.dataStore.edit { prefs ->
            prefs[Keys.THEME_MODE] = theme.name
        }
    }

    suspend fun markDefaultWorkerSeeded() {
        context.dataStore.edit { prefs ->
            prefs[Keys.SEEDED_DEFAULT_WORKER] = true
        }
    }
}
