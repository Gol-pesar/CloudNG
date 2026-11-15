package com.example.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.R
import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.data.TunnelOperationMode
import com.example.ui.theme.SignalEmerald
import com.example.vpn.Socks5VpnService
import com.example.vpn.TunnelStatus
import com.example.worker.LocalProxyService

private data class NavTabItem(
    val route: String,
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String,
)

private val navTabs = listOf(
    NavTabItem(
        route = NavRoutes.ROUTE_CONNECT,
        labelRes = R.string.nav_connect,
        selectedIcon = Icons.Filled.Shield,
        unselectedIcon = Icons.Outlined.Shield,
        testTag = "nav_connect",
    ),
    NavTabItem(
        route = NavRoutes.ROUTE_SERVERS,
        labelRes = R.string.nav_servers,
        selectedIcon = Icons.Filled.Dns,
        unselectedIcon = Icons.Outlined.Dns,
        testTag = "nav_servers",
    ),
    NavTabItem(
        route = NavRoutes.ROUTE_ACTIVITY_SETTINGS,
        labelRes = R.string.nav_activity,
        selectedIcon = Icons.Filled.Tune,
        unselectedIcon = Icons.Outlined.Tune,
        testTag = "nav_activity_settings",
    ),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SocksGuardApp(
    uiState: MainUiState,
    viewModel: MainViewModel,
) {
    val context = LocalContext.current
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: NavRoutes.ROUTE_CONNECT
    val snackbarHostState = remember { SnackbarHostState() }

    var editingProfile by remember { mutableStateOf<ProxyProfile?>(null) }
    var showServerEditor by remember { mutableStateOf(false) }
    var showUriDialog by remember { mutableStateOf(false) }
    var showQrScanner by remember { mutableStateOf(false) }
    var qrExportProfile by remember { mutableStateOf<ProxyProfile?>(null) }
    var showPerAppSheet by remember { mutableStateOf(false) }
    var pendingProfileIdToStart by remember { mutableStateOf<Long?>(null) }

    LaunchedEffect(uiState.snackbarMessage) {
        val msg = uiState.snackbarMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        viewModel.consumeMessage()
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val profileId = pendingProfileIdToStart
        pendingProfileIdToStart = null
        if (result.resultCode == Activity.RESULT_OK && profileId != null) {
            Socks5VpnService.start(context, profileId)
        } else if (result.resultCode != Activity.RESULT_OK) {
            viewModel.showMessage("مجوز ایجاد اتصال VPN توسط کاربر تأیید نشد.")
        }
    }

    fun startSelectedMode(profileId: Long) {
        if (uiState.settings.operationMode == TunnelOperationMode.LOCAL_SOCKS5) {
            LocalProxyService.start(context, profileId)
        } else {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent == null) {
                Socks5VpnService.start(context, profileId)
            } else {
                pendingProfileIdToStart = profileId
                vpnPermissionLauncher.launch(prepareIntent)
            }
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { _ ->
        val profileId = pendingProfileIdToStart
        pendingProfileIdToStart = null
        if (profileId != null) {
            startSelectedMode(profileId)
        }
    }

    fun handleToggleConnection() {
        val status = uiState.telemetry.status
        if (status == TunnelStatus.CONNECTED || status == TunnelStatus.CONNECTING) {
            Socks5VpnService.stop(context)
            LocalProxyService.stop(context)
            return
        }
        val selected = uiState.selectedProfile
        if (selected == null) {
            editingProfile = null
            showServerEditor = true
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                pendingProfileIdToStart = selected.id
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        startSelectedMode(selected.id)
    }

    fun navigateToTab(route: String) {
        navController.navigate(route) {
            popUpTo(navController.graph.findStartDestination().id) {
                saveState = true
            }
            launchSingleTop = true
            restoreState = true
        }
    }

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val useRail = maxWidth >= 600.dp

            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing,
                snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
                topBar = {
                    CenterAlignedTopAppBar(
                        title = {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = stringResource(R.string.app_name),
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.Bold,
                                )
                                if (uiState.telemetry.status == TunnelStatus.CONNECTED) {
                                    Spacer(Modifier.width(8.dp))
                                    Surface(
                                        shape = MaterialTheme.shapes.small,
                                        color = SignalEmerald.copy(alpha = 0.16f),
                                    ) {
                                        val badgeLabel = if (uiState.selectedProfile?.profileType == ProfileType.WORKER_WS) {
                                            "WS"
                                        } else {
                                            "SOCKS5"
                                        }
                                        Text(
                                            text = badgeLabel,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = SignalEmerald,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                        )
                                    }
                                }
                            }
                        },
                        colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                            containerColor = MaterialTheme.colorScheme.background,
                        ),
                    )
                },
                bottomBar = {
                    if (!useRail) {
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.surface,
                        ) {
                            navTabs.forEach { tab ->
                                val selected = currentRoute == tab.route
                                NavigationBarItem(
                                    selected = selected,
                                    onClick = { navigateToTab(tab.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                            contentDescription = stringResource(tab.labelRes),
                                        )
                                    },
                                    label = { Text(stringResource(tab.labelRes)) },
                                    modifier = Modifier.testTag(tab.testTag),
                                )
                            }
                        }
                    }
                },
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                ) {
                    if (useRail) {
                        NavigationRail(
                            containerColor = MaterialTheme.colorScheme.surface,
                            modifier = Modifier.fillMaxHeight(),
                        ) {
                            navTabs.forEach { tab ->
                                val selected = currentRoute == tab.route
                                NavigationRailItem(
                                    selected = selected,
                                    onClick = { navigateToTab(tab.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                            contentDescription = stringResource(tab.labelRes),
                                        )
                                    },
                                    label = { Text(stringResource(tab.labelRes)) },
                                    modifier = Modifier.testTag(tab.testTag),
                                )
                            }
                        }
                    }

                    Box(modifier = Modifier.weight(1f).fillMaxSize()) {
                        NavHost(
                            navController = navController,
                            startDestination = NavRoutes.ROUTE_CONNECT,
                        ) {
                            composable(NavRoutes.ROUTE_CONNECT) {
                                ConnectScreen(
                                    uiState = uiState,
                                    onToggleConnection = ::handleToggleConnection,
                                    onChangeOperationMode = viewModel::setOperationMode,
                                    onOpenServersTab = { navigateToTab(NavRoutes.ROUTE_SERVERS) },
                                    onOpenAddServer = {
                                        editingProfile = null
                                        showServerEditor = true
                                    },
                                    onOpenPerAppProxy = { showPerAppSheet = true },
                                    onProbeSelected = viewModel::probeProfile,
                                    onShowMessage = viewModel::showMessage,
                                )
                            }
                            composable(NavRoutes.ROUTE_SERVERS) {
                                ServersScreen(
                                    uiState = uiState,
                                    onSelectProfile = { id ->
                                        viewModel.selectProfile(id)
                                        if (uiState.telemetry.status == TunnelStatus.CONNECTED) {
                                            startSelectedMode(id)
                                        }
                                    },
                                    onAddProfile = {
                                        editingProfile = null
                                        showServerEditor = true
                                    },
                                    onEditProfile = { profile ->
                                        editingProfile = profile
                                        showServerEditor = true
                                    },
                                    onDeleteProfile = viewModel::deleteProfile,
                                    onProbeProfile = viewModel::probeProfile,
                                    onImportUriClick = { showUriDialog = true },
                                    onScanQrClick = { showQrScanner = true },
                                    onShowQrClick = { profile -> qrExportProfile = profile },
                                    onCopiedMessage = viewModel::showMessage,
                                )
                            }
                            composable(NavRoutes.ROUTE_ACTIVITY_SETTINGS) {
                                ActivitySettingsScreen(
                                    uiState = uiState,
                                    onTestCustomTarget = viewModel::testCustomTarget,
                                    onClearLogs = viewModel::clearLogs,
                                    onSetDnsServer = viewModel::setDnsServer,
                                    onSetBypassLan = viewModel::setBypassLan,
                                    onSetRemoteDnsOverTcp = viewModel::setRemoteDnsOverTcp,
                                    onSetThemePreference = viewModel::setThemePreference,
                                    onOpenPerAppProxy = { showPerAppSheet = true },
                                )
                            }
                        }
                    }
                }
            }

            if (showServerEditor) {
                ServerEditorSheet(
                    initialProfile = editingProfile,
                    onDismiss = { showServerEditor = false },
                    onSave = { profile ->
                        viewModel.saveProfile(profile)
                        showServerEditor = false
                    },
                )
            }

            if (showUriDialog) {
                UriImportDialog(
                    onDismiss = { showUriDialog = false },
                    onImport = { raw ->
                        if (viewModel.importFromUri(raw)) {
                            showUriDialog = false
                        }
                    },
                )
            }

            if (showQrScanner) {
                QrScannerDialog(
                    onQrDecoded = { decoded ->
                        showQrScanner = false
                        viewModel.importFromUri(decoded)
                    },
                    onErrorMessage = viewModel::showMessage,
                    onDismiss = { showQrScanner = false },
                )
            }

            qrExportProfile?.let { profileToExport ->
                QrExportDialog(
                    profile = profileToExport,
                    onCopiedMessage = viewModel::showMessage,
                    onDismiss = { qrExportProfile = null },
                )
            }

            if (showPerAppSheet) {
                PerAppProxySheet(
                    currentMode = uiState.settings.perAppMode,
                    selectedPackages = uiState.settings.perAppPackages,
                    onChangeMode = viewModel::setPerAppMode,
                    onTogglePackage = viewModel::togglePerAppPackage,
                    onClearSelection = { viewModel.setPerAppPackages(emptySet()) },
                    onDismiss = { showPerAppSheet = false },
                )
            }
        }
    }
}
