package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.ui.theme.ThemePreference
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "cloudng_prefs")

enum class PerAppMode {
    ALL_APPS,
    BYPASS_SELECTED,
    PROXY_SELECTED,
}

data class AppSettings(
    val activeProfileId: Long? = null,
    val operationMode: TunnelOperationMode = TunnelOperationMode.VPN_TUNNEL,
    val dnsServer: String = "8.8.8.8",
    val bypassLan: Boolean = true,
    val remoteDnsOverTcp: Boolean = true,
    val themePreference: ThemePreference = ThemePreference.DARK,
    val perAppMode: PerAppMode = PerAppMode.ALL_APPS,
    val perAppPackages: Set<String> = emptySet(),
)

class UserPreferences(private val context: Context) {
    private object Keys {
        val ACTIVE_PROFILE_ID = longPreferencesKey("active_profile_id")
        val OPERATION_MODE = stringPreferencesKey("operation_mode")
        val DNS_SERVER = stringPreferencesKey("dns_server")
        val BYPASS_LAN = booleanPreferencesKey("bypass_lan")
        val REMOTE_DNS_OVER_TCP = booleanPreferencesKey("remote_dns_over_tcp")
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val PER_APP_MODE = stringPreferencesKey("per_app_mode")
        val PER_APP_PACKAGES = stringSetPreferencesKey("per_app_packages")
    }

    val settings: Flow<AppSettings> = context.dataStore.data.map { prefs ->
        val activeId = prefs[Keys.ACTIVE_PROFILE_ID]?.takeIf { it > 0L }
        val modeStr = prefs[Keys.OPERATION_MODE] ?: TunnelOperationMode.VPN_TUNNEL.name
        val mode = runCatching { TunnelOperationMode.valueOf(modeStr) }.getOrDefault(TunnelOperationMode.VPN_TUNNEL)
        val themeStr = prefs[Keys.THEME_MODE] ?: ThemePreference.DARK.name
        val theme = runCatching { ThemePreference.valueOf(themeStr) }.getOrDefault(ThemePreference.DARK)
        val perAppModeStr = prefs[Keys.PER_APP_MODE] ?: PerAppMode.ALL_APPS.name
        val perAppMode = runCatching { PerAppMode.valueOf(perAppModeStr) }.getOrDefault(PerAppMode.ALL_APPS)
        val perAppPackages = prefs[Keys.PER_APP_PACKAGES] ?: emptySet()
        AppSettings(
            activeProfileId = activeId,
            operationMode = mode,
            dnsServer = prefs[Keys.DNS_SERVER]?.takeIf { it.isNotBlank() } ?: "8.8.8.8",
            bypassLan = prefs[Keys.BYPASS_LAN] ?: true,
            remoteDnsOverTcp = prefs[Keys.REMOTE_DNS_OVER_TCP] ?: true,
            themePreference = theme,
            perAppMode = perAppMode,
            perAppPackages = perAppPackages,
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

    suspend fun setPerAppMode(mode: PerAppMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.PER_APP_MODE] = mode.name
        }
    }

    suspend fun setPerAppPackages(packages: Set<String>) {
        context.dataStore.edit { prefs ->
            prefs[Keys.PER_APP_PACKAGES] = packages
        }
    }

    suspend fun togglePerAppPackage(packageName: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.PER_APP_PACKAGES] ?: emptySet()
            prefs[Keys.PER_APP_PACKAGES] = if (current.contains(packageName)) {
                current - packageName
            } else {
                current + packageName
            }
        }
    }
}
