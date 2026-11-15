package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.AppDatabase
import com.example.data.AppSettings
import com.example.data.ProxyProfile
import com.example.data.ProxyRepository
import com.example.data.ProxyUriParser
import com.example.data.UserPreferences
import com.example.network.Socks5Diagnostics
import com.example.network.Socks5ProbeResult
import com.example.ui.theme.ThemePreference
import com.example.vpn.LogLevel
import com.example.vpn.VpnStateManager
import com.example.vpn.VpnTelemetry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class MainUiState(
    val profiles: List<ProxyProfile> = emptyList(),
    val selectedProfile: ProxyProfile? = null,
    val settings: AppSettings = AppSettings(),
    val telemetry: VpnTelemetry = VpnTelemetry(),
    val probingProfileIds: Set<Long> = emptySet(),
    val isTestingEndpoint: Boolean = false,
    val customEndpointProbe: Socks5ProbeResult? = null,
    val snackbarMessage: String? = null,
)

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = ProxyRepository(
        dao = AppDatabase.getInstance(application).proxyProfileDao(),
        preferences = UserPreferences(application),
    )

    private val probingIds = MutableStateFlow<Set<Long>>(emptySet())
    private val isTestingEndpoint = MutableStateFlow(false)
    private val customEndpointProbe = MutableStateFlow<Socks5ProbeResult?>(null)
    private val snackbarMessage = MutableStateFlow<String?>(null)

    init {
        viewModelScope.launch {
            repository.ensureDefaultWorkerProfileSeeded()
        }
    }

    private data class DiagnosticsUiState(
        val probingIds: Set<Long>,
        val isTestingEndpoint: Boolean,
        val customProbe: Socks5ProbeResult?,
        val snackbar: String?,
    )

    private val diagnosticsState = combine(
        probingIds,
        isTestingEndpoint,
        customEndpointProbe,
        snackbarMessage,
    ) { probing, testing, probeResult, message ->
        DiagnosticsUiState(probing, testing, probeResult, message)
    }

    val uiState: StateFlow<MainUiState> = combine(
        repository.profiles,
        repository.settings,
        VpnStateManager.telemetry,
        diagnosticsState,
    ) { profiles, settings, telemetry, diag ->
        val selected = profiles.firstOrNull { it.id == settings.activeProfileId }
            ?: profiles.firstOrNull()
        MainUiState(
            profiles = profiles,
            selectedProfile = selected,
            settings = settings,
            telemetry = telemetry,
            probingProfileIds = diag.probingIds,
            isTestingEndpoint = diag.isTestingEndpoint,
            customEndpointProbe = diag.customProbe,
            snackbarMessage = diag.snackbar,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = MainUiState(),
    )

    fun selectProfile(profileId: Long) {
        viewModelScope.launch {
            repository.setActiveProfileId(profileId)
        }
    }

    fun setOperationMode(mode: com.example.data.TunnelOperationMode) {
        viewModelScope.launch {
            repository.setOperationMode(mode)
        }
    }

    fun saveProfile(profile: ProxyProfile) {
        viewModelScope.launch {
            val savedId = repository.saveProfile(profile)
            if (uiState.value.settings.activeProfileId == null || profile.id == 0L) {
                repository.setActiveProfileId(savedId)
            }
            snackbarMessage.value = if (profile.id == 0L) {
                "سرور «${profile.name}» اضافه شد."
            } else {
                "پروفایل «${profile.name}» به‌روزرسانی شد."
            }
        }
    }

    fun deleteProfile(profile: ProxyProfile) {
        viewModelScope.launch {
            repository.deleteProfile(profile.id)
            if (uiState.value.settings.activeProfileId == profile.id) {
                val nextId = uiState.value.profiles.firstOrNull { it.id != profile.id }?.id
                repository.setActiveProfileId(nextId)
            }
            snackbarMessage.value = "سرور «${profile.name}» حذف شد."
        }
    }

    fun importFromUri(rawUri: String): Boolean {
        val parsed = ProxyUriParser.parse(rawUri)
        return parsed.fold(
            onSuccess = { profile ->
                saveProfile(profile)
                true
            },
            onFailure = { error ->
                snackbarMessage.value = error.localizedMessage ?: "فرمت لینک نامعتبر است."
                false
            },
        )
    }

    fun probeProfile(profile: ProxyProfile) {
        if (probingIds.value.contains(profile.id)) return
        viewModelScope.launch {
            probingIds.update { it + profile.id }
            val result = Socks5Diagnostics.probeProfile(profile)
            if (result.success) {
                repository.updateProbeResult(profile.id, result.latencyMs, result.exitIp)
                VpnStateManager.addLog(
                    LogLevel.SUCCESS,
                    "PING",
                    "${profile.name}: پینگ ${result.latencyMs}ms" +
                        (result.exitIp?.let { " | IP: $it" } ?: ""),
                )
                snackbarMessage.value = result.detail ?: "اتصال با موفقیت تأیید شد."
            } else {
                VpnStateManager.addLog(
                    LogLevel.ERROR,
                    "PING",
                    "${profile.name}: ${result.errorMessage ?: "ناموفق"}",
                )
                snackbarMessage.value = result.errorMessage ?: "تست اتصال ناموفق بود."
            }
            probingIds.update { it - profile.id }
        }
    }

    fun testCustomTarget(targetHost: String, targetPort: Int) {
        val profile = uiState.value.selectedProfile
        if (profile == null) {
            snackbarMessage.value = "ابتدا یک سرور SOCKS5 انتخاب یا اضافه کنید."
            return
        }
        val cleanHost = targetHost.trim()
        if (cleanHost.isEmpty() || targetPort !in 1..65535) {
            snackbarMessage.value = "آدرس مقصد یا شماره پورت معتبر نیست."
            return
        }
        viewModelScope.launch {
            isTestingEndpoint.value = true
            val result = Socks5Diagnostics.probeProfile(
                profile = profile,
                targetHost = cleanHost,
                targetPort = targetPort,
                fetchExitIp = false,
            )
            customEndpointProbe.value = result
            VpnStateManager.addLog(
                if (result.success) LogLevel.SUCCESS else LogLevel.ERROR,
                "TEST",
                if (result.success) {
                    "دسترسی به $cleanHost:$targetPort از طریق ${profile.name} (${result.latencyMs}ms)"
                } else {
                    "خطای دسترسی به $cleanHost:$targetPort — ${result.errorMessage}"
                },
            )
            isTestingEndpoint.value = false
        }
    }

    fun setDnsServer(dns: String) {
        viewModelScope.launch {
            repository.setDnsServer(dns)
            snackbarMessage.value = "سرور DNS به $dns تغییر یافت."
        }
    }

    fun setBypassLan(enabled: Boolean) {
        viewModelScope.launch {
            repository.setBypassLan(enabled)
        }
    }

    fun setRemoteDnsOverTcp(enabled: Boolean) {
        viewModelScope.launch {
            repository.setRemoteDnsOverTcp(enabled)
        }
    }

    fun setThemePreference(theme: ThemePreference) {
        viewModelScope.launch {
            repository.setThemePreference(theme)
        }
    }

    fun clearLogs() {
        VpnStateManager.clearLogs()
    }

    fun showMessage(msg: String) {
        snackbarMessage.value = msg
    }

    fun consumeMessage() {
        snackbarMessage.value = null
    }
}
