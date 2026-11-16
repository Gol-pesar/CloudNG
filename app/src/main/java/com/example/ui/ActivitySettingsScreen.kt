package com.example.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.PerAppMode
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.SignalAmber
import com.example.ui.theme.SignalEmerald
import com.example.ui.theme.SignalRose
import com.example.ui.theme.ThemePreference
import com.example.vpn.LogLevel

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ActivitySettingsScreen(
    uiState: MainUiState,
    onTestCustomTarget: (String, Int) -> Unit,
    onClearLogs: () -> Unit,
    onSetDnsServer: (String) -> Unit,
    onSetBypassLan: (Boolean) -> Unit,
    onSetRemoteDnsOverTcp: (Boolean) -> Unit,
    onSetThemePreference: (ThemePreference) -> Unit,
    onOpenPerAppProxy: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var selectedSection by remember { mutableIntStateOf(0) }
    var targetHost by remember { mutableStateOf("example.com") }
    var targetPortText by remember { mutableStateOf("80") }
    var customDnsText by remember(uiState.settings.dnsServer) { mutableStateOf(uiState.settings.dnsServer) }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        item {
            Column(
                modifier = Modifier
                    .widthIn(max = 640.dp)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    SegmentedButton(
                        selected = selectedSection == 0,
                        onClick = { selectedSection = 0 },
                        shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                        modifier = Modifier.testTag("tab_logs_diagnostics"),
                    ) {
                        Text("لاگ و تستر")
                    }
                    SegmentedButton(
                        selected = selectedSection == 1,
                        onClick = { selectedSection = 1 },
                        shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                        modifier = Modifier.testTag("tab_tunnel_settings"),
                    ) {
                        Text("تنظیمات تونل")
                    }
                }
            }
        }

        if (selectedSection == 0) {
            item {
                Surface(
                    shape = MaterialTheme.shapes.medium,
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.30f)),
                    modifier = Modifier
                        .widthIn(max = 640.dp)
                        .fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Icon(Icons.Filled.Terminal, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            Text("تست دسترسی از طریق SOCKS5", style = MaterialTheme.typography.titleMedium)
                        }
                        Text(
                            text = "برقراری اتصال واقعی از طریق سرور فعال به هر دامنه یا IP دلخواه",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                OutlinedTextField(
                                    value = targetHost,
                                    onValueChange = { targetHost = it },
                                    label = { Text("میزبان مقصد") },
                                    singleLine = true,
                                    modifier = Modifier
                                        .weight(0.68f)
                                        .testTag("diag_target_host_input"),
                                )
                                OutlinedTextField(
                                    value = targetPortText,
                                    onValueChange = { targetPortText = it.filter { c -> c.isDigit() }.take(5) },
                                    label = { Text("پورت") },
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                    modifier = Modifier
                                        .weight(0.32f)
                                        .testTag("diag_target_port_input"),
                                )
                            }
                        }

                        Button(
                            onClick = {
                                val port = targetPortText.toIntOrNull() ?: 80
                                onTestCustomTarget(targetHost, port)
                            },
                            enabled = !uiState.isTestingEndpoint,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp)
                                .testTag("diag_run_test_button"),
                        ) {
                            if (uiState.isTestingEndpoint) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                )
                                Spacer(Modifier.width(8.dp))
                                Text("در حال تست اتصال…")
                            } else {
                                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text("اجرای تست SOCKS5")
                            }
                        }

                        uiState.customEndpointProbe?.let { res ->
                            Surface(
                                shape = MaterialTheme.shapes.small,
                                color = if (res.success) {
                                    SignalEmerald.copy(alpha = 0.14f)
                                } else {
                                    SignalRose.copy(alpha = 0.14f)
                                },
                            ) {
                                Text(
                                    text = if (res.success) {
                                        "موفق • زمان پاسخ: ${res.latencyMs}ms"
                                    } else {
                                        "ناموفق • ${res.errorMessage ?: "خطای شبکه"}"
                                    },
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = if (res.success) SignalEmerald else SignalRose,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                )
                            }
                        }
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .widthIn(max = 640.dp)
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "گزارش رویدادها (${uiState.telemetry.logs.size})",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    TextButton(
                        onClick = onClearLogs,
                        enabled = uiState.telemetry.logs.isNotEmpty(),
                        modifier = Modifier.testTag("clear_logs_button"),
                    ) {
                        Icon(Icons.Filled.CleaningServices, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("پاک کردن")
                    }
                }
            }

            if (uiState.telemetry.logs.isEmpty()) {
                item {
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.28f)),
                        modifier = Modifier
                            .widthIn(max = 640.dp)
                            .fillMaxWidth(),
                    ) {
                        Text(
                            text = "هنوز رویدادی ثبت نشده است. با برقراری اتصال یا تست پینگ، گزارش‌ها اینجا نمایش داده می‌شوند.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(18.dp),
                        )
                    }
                }
            } else {
                items(uiState.telemetry.logs, key = { it.id }) { entry ->
                    val tagColor = when (entry.level) {
                        LogLevel.SUCCESS -> SignalEmerald
                        LogLevel.WARNING -> SignalAmber
                        LogLevel.ERROR -> SignalRose
                        LogLevel.INFO -> MaterialTheme.colorScheme.primary
                    }
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)),
                        modifier = Modifier
                            .widthIn(max = 640.dp)
                            .fillMaxWidth(),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = tagColor.copy(alpha = 0.16f),
                            ) {
                                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                    Text(
                                        text = entry.tag,
                                        fontFamily = JetBrainsMonoFontFamily,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp,
                                        color = tagColor,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
                                    )
                                }
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = entry.message,
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                    Text(
                                        text = Formatters.formatClockTime(entry.timestampMs),
                                        fontFamily = JetBrainsMonoFontFamily,
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } else {
            item {
                Column(
                    modifier = Modifier
                        .widthIn(max = 640.dp)
                        .fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    // DNS Configuration Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.30f)),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Icon(Icons.Filled.Dns, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                Text("سرور DNS تونل", style = MaterialTheme.typography.titleMedium)
                            }
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                listOf("8.8.8.8", "9.9.9.9", "1.1.1.1").forEach { preset ->
                                    FilterChip(
                                        selected = uiState.settings.dnsServer == preset,
                                        onClick = {
                                            customDnsText = preset
                                            onSetDnsServer(preset)
                                        },
                                        label = {
                                            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                                Text(preset, fontFamily = JetBrainsMonoFontFamily)
                                            }
                                        },
                                    )
                                }
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                    OutlinedTextField(
                                        value = customDnsText,
                                        onValueChange = { customDnsText = it },
                                        label = { Text("DNS دلخواه") },
                                        singleLine = true,
                                        modifier = Modifier
                                            .weight(1f)
                                            .testTag("custom_dns_input"),
                                    )
                                }
                                Button(
                                    onClick = { onSetDnsServer(customDnsText) },
                                    modifier = Modifier
                                        .height(52.dp)
                                        .testTag("apply_dns_button"),
                                ) {
                                    Text("اعمال")
                                }
                            }
                        }
                    }

                    // Routing Preferences Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.30f)),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(14.dp),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Icon(Icons.Filled.Lan, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                                Text("مسیریابی و پروتکل", style = MaterialTheme.typography.titleMedium)
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                                    Text("دور زدن شبکه محلی (Bypass LAN)", style = MaterialTheme.typography.titleSmall)
                                    Text(
                                        "آدرس‌های محلی 192.168.x.x و 10.x.x.x مستقیم عبور کنند",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Switch(
                                    checked = uiState.settings.bypassLan,
                                    onCheckedChange = onSetBypassLan,
                                    modifier = Modifier.testTag("bypass_lan_switch"),
                                )
                            }

                            androidx.compose.material3.HorizontalDivider(
                                thickness = 1.dp,
                                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.20f),
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                                    Text("DNS از داخل تونل (TCP)", style = MaterialTheme.typography.titleSmall)
                                    Text(
                                        "جلوگیری از نشت DNS هنگام استفاده از سرورهای SOCKS5",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Switch(
                                    checked = uiState.settings.remoteDnsOverTcp,
                                    onCheckedChange = onSetRemoteDnsOverTcp,
                                    modifier = Modifier.testTag("remote_dns_switch"),
                                )
                            }
                        }
                    }

                    // Per-App Proxy Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.30f)),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    Icon(Icons.Filled.Apps, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                    Text("پروکسی برنامه‌ها (Per-App Proxy)", style = MaterialTheme.typography.titleMedium)
                                }
                                FilledTonalButton(
                                    onClick = onOpenPerAppProxy,
                                    modifier = Modifier.testTag("open_per_app_proxy_button"),
                                ) {
                                    Text("تنظیم")
                                }
                            }
                            val perAppSummary = when (uiState.settings.perAppMode) {
                                PerAppMode.ALL_APPS -> "حالت فعلی: همه برنامه‌ها (به جز CloudNG)"
                                PerAppMode.BYPASS_SELECTED -> "حالت فعلی: دور زدن ${uiState.settings.perAppPackages.size} برنامه + خود CloudNG"
                                PerAppMode.PROXY_SELECTED -> "حالت فعلی: فقط ${uiState.settings.perAppPackages.size} برنامه انتخاب‌شده"
                            }
                            Text(
                                text = perAppSummary,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }

                    // Theme Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.30f)),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Icon(Icons.Filled.Palette, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                                Text("ظاهر برنامه", style = MaterialTheme.typography.titleMedium)
                            }
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                val options = listOf(
                                    ThemePreference.DARK to "تاریک",
                                    ThemePreference.LIGHT to "روشن",
                                    ThemePreference.SYSTEM to "هماهنگ با سیستم",
                                )
                                options.forEach { (pref, title) ->
                                    FilterChip(
                                        selected = uiState.settings.themePreference == pref,
                                        onClick = { onSetThemePreference(pref) },
                                        label = { Text(title) },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
