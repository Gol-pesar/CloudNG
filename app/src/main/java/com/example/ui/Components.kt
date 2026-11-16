package com.example.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.data.ProfileType
import com.example.data.ProxyProfile
import com.example.data.ProxyUriParser
import com.example.data.TunnelOperationMode
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.SignalAmber
import com.example.ui.theme.SignalEmerald
import com.example.ui.theme.SignalRose
import com.example.vpn.TrafficSample
import com.example.vpn.TunnelStatus
import com.example.vpn.VpnTelemetry
import com.example.worker.WorkerDefaults
import kotlinx.coroutines.delay

@Composable
fun ConnectionHeroCard(
    telemetry: VpnTelemetry,
    selectedProfile: ProxyProfile?,
    operationMode: TunnelOperationMode,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val status = telemetry.status
    val statusColor by animateColorAsState(
        targetValue = when (status) {
            TunnelStatus.CONNECTED -> SignalEmerald
            TunnelStatus.CONNECTING -> SignalAmber
            TunnelStatus.ERROR -> SignalRose
            TunnelStatus.DISCONNECTED -> MaterialTheme.colorScheme.primary
        },
        animationSpec = tween(350),
        label = "status_color",
    )

    val buttonScale by animateFloatAsState(
        targetValue = if (status == TunnelStatus.CONNECTING) 0.94f else 1f,
        animationSpec = spring(),
        label = "power_scale",
    )

    val infiniteTransition = rememberInfiniteTransition(label = "radar_pulse")
    val pulseProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "pulse",
    )

    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status, telemetry.connectedSinceMs) {
        while (status == TunnelStatus.CONNECTED && telemetry.connectedSinceMs != null) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    val statusText = when (status) {
        TunnelStatus.DISCONNECTED -> stringResource(R.string.status_disconnected)
        TunnelStatus.CONNECTING -> stringResource(R.string.status_connecting)
        TunnelStatus.CONNECTED -> if (operationMode == TunnelOperationMode.LOCAL_SOCKS5) {
            "پروکسی محلی فعال است"
        } else {
            stringResource(R.string.status_connected)
        }
        TunnelStatus.ERROR -> telemetry.errorMessage ?: stringResource(R.string.status_error)
    }

    val hairlineBorder = if (status == TunnelStatus.DISCONNECTED) {
        MaterialTheme.colorScheme.outline.copy(alpha = 0.34f)
    } else {
        statusColor.copy(alpha = 0.42f)
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
        border = BorderStroke(1.dp, hairlineBorder),
    ) {
        Box(modifier = Modifier.fillMaxWidth()) {
            Image(
                painter = painterResource(id = R.drawable.img_tunnel_hero_bg),
                contentDescription = stringResource(R.string.cd_hero_background),
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .matchParentSize()
                    .alpha(if (status == TunnelStatus.CONNECTED) 0.24f else 0.14f),
            )

            Box(
                modifier = Modifier
                    .matchParentSize()
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(
                                MaterialTheme.colorScheme.surface.copy(alpha = 0.72f),
                                statusColor.copy(alpha = if (status == TunnelStatus.CONNECTED) 0.08f else 0.03f),
                                MaterialTheme.colorScheme.surface.copy(alpha = 0.96f),
                            ),
                        ),
                    ),
            )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 22.dp, vertical = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Surface(
                    shape = CircleShape,
                    color = statusColor.copy(alpha = 0.12f),
                    border = BorderStroke(1.dp, statusColor.copy(alpha = 0.36f)),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(statusColor),
                        )
                        Text(
                            text = statusText,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = statusColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier.size(164.dp),
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val center = Offset(size.width / 2f, size.height / 2f)
                        val maxRadius = size.minDimension / 2f
                        // Subtle fixed precision orbital ring
                        drawCircle(
                            color = statusColor.copy(alpha = if (status == TunnelStatus.CONNECTED) 0.26f else 0.14f),
                            radius = maxRadius * 0.80f,
                            center = center,
                            style = Stroke(width = 1.dp.toPx()),
                        )
                        if (status == TunnelStatus.CONNECTED || status == TunnelStatus.CONNECTING) {
                            val r1 = (maxRadius * 0.66f) + (maxRadius * 0.34f * pulseProgress)
                            val alpha1 = (1f - pulseProgress) * 0.45f
                            drawCircle(
                                color = statusColor.copy(alpha = alpha1),
                                radius = r1,
                                center = center,
                                style = Stroke(width = 2.dp.toPx()),
                            )
                            val secondPhase = (pulseProgress + 0.5f) % 1f
                            val r2 = (maxRadius * 0.66f) + (maxRadius * 0.34f * secondPhase)
                            val alpha2 = (1f - secondPhase) * 0.32f
                            drawCircle(
                                color = statusColor.copy(alpha = alpha2),
                                radius = r2,
                                center = center,
                                style = Stroke(width = 1.5.dp.toPx()),
                            )
                        } else {
                            drawCircle(
                                color = statusColor.copy(alpha = 0.08f),
                                radius = maxRadius * 0.94f,
                                center = center,
                                style = Stroke(width = 1.dp.toPx()),
                            )
                        }
                    }

                    Surface(
                        modifier = Modifier
                            .size(108.dp)
                            .scale(buttonScale)
                            .clip(CircleShape)
                            .clickable(onClick = onToggleConnection)
                            .testTag("power_toggle_button"),
                        shape = CircleShape,
                        color = if (status == TunnelStatus.CONNECTED) {
                            statusColor
                        } else {
                            MaterialTheme.colorScheme.surfaceVariant
                        },
                        border = BorderStroke(
                            width = 2.dp,
                            color = if (status == TunnelStatus.CONNECTED) {
                                Color.White.copy(alpha = 0.35f)
                            } else {
                                statusColor.copy(alpha = 0.85f)
                            },
                        ),
                        shadowElevation = if (status == TunnelStatus.CONNECTED) 12.dp else 4.dp,
                    ) {
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier
                                .fillMaxSize()
                                .background(
                                    Brush.verticalGradient(
                                        colors = if (status == TunnelStatus.CONNECTED) {
                                            listOf(Color.White.copy(alpha = 0.16f), Color.Transparent)
                                        } else {
                                            listOf(
                                                MaterialTheme.colorScheme.primary.copy(alpha = 0.06f),
                                                Color.Transparent,
                                            )
                                        },
                                    ),
                                ),
                        ) {
                            if (status == TunnelStatus.CONNECTING) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(36.dp),
                                    color = statusColor,
                                    strokeWidth = 2.5.dp,
                                )
                            } else {
                                Icon(
                                    imageVector = Icons.Filled.PowerSettingsNew,
                                    contentDescription = stringResource(R.string.cd_power_button),
                                    tint = if (status == TunnelStatus.CONNECTED) {
                                        MaterialTheme.colorScheme.onPrimary
                                    } else {
                                        statusColor
                                    },
                                    modifier = Modifier.size(42.dp),
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = when (status) {
                        TunnelStatus.CONNECTED -> stringResource(R.string.action_disconnect)
                        TunnelStatus.CONNECTING -> stringResource(R.string.status_connecting)
                        else -> stringResource(R.string.action_connect)
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )

                Spacer(modifier = Modifier.height(6.dp))

                if (status == TunnelStatus.CONNECTED && telemetry.connectedSinceMs != null) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        Text(
                            text = Formatters.formatDuration(telemetry.connectedSinceMs, nowMs),
                            fontFamily = JetBrainsMonoFontFamily,
                            fontWeight = FontWeight.Bold,
                            fontSize = 22.sp,
                            letterSpacing = 1.sp,
                            color = statusColor,
                        )
                        if (selectedProfile != null) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Surface(
                                shape = MaterialTheme.shapes.small,
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
                                border = BorderStroke(
                                    1.dp,
                                    MaterialTheme.colorScheme.outline.copy(alpha = 0.25f),
                                ),
                            ) {
                                Text(
                                    text = "SOCKS5 • 127.0.0.1:${selectedProfile.localPort}",
                                    fontFamily = JetBrainsMonoFontFamily,
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                                )
                            }
                        }
                    }
                } else if (selectedProfile != null) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        val prefix = if (selectedProfile.profileType == ProfileType.WORKER_WS) {
                            "Worker WS"
                        } else {
                            "SOCKS5"
                        }
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                            border = BorderStroke(
                                1.dp,
                                MaterialTheme.colorScheme.outline.copy(alpha = 0.22f),
                            ),
                        ) {
                            Text(
                                text = "$prefix • ${selectedProfile.endpoint}",
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            )
                        }
                    }
                } else {
                    Text(
                        text = "برای شروع یک سرور اضافه کنید",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
fun TelemetrySparkline(
    samples: List<TrafficSample>,
    modifier: Modifier = Modifier,
) {
    val rxColor = MaterialTheme.colorScheme.primary
    val txColor = MaterialTheme.colorScheme.secondary
    val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)

    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        if (w <= 0f || h <= 0f) return@Canvas

        for (i in 1..3) {
            val y = h * (i / 4f)
            drawLine(
                color = gridColor,
                start = Offset(0f, y),
                end = Offset(w, y),
                strokeWidth = 1.dp.toPx(),
            )
        }

        if (samples.size < 2) return@Canvas

        val maxRate = samples.maxOf { maxOf(it.rxBytesPerSec, it.txBytesPerSec) }.coerceAtLeast(1024L)
        val stepX = w / (samples.size - 1).coerceAtLeast(1)

        val rxPoints = samples.mapIndexed { idx, sample ->
            val x = idx * stepX
            val y = h - ((sample.rxBytesPerSec.toFloat() / maxRate.toFloat()) * (h * 0.84f)) - (h * 0.06f)
            Offset(x, y)
        }
        val txPoints = samples.mapIndexed { idx, sample ->
            val x = idx * stepX
            val y = h - ((sample.txBytesPerSec.toFloat() / maxRate.toFloat()) * (h * 0.84f)) - (h * 0.06f)
            Offset(x, y)
        }

        fun buildSmoothPath(points: List<Offset>, closeToBottom: Boolean): Path {
            val path = Path()
            if (points.isEmpty()) return path
            if (closeToBottom) {
                path.moveTo(points.first().x, h)
                path.lineTo(points.first().x, points.first().y)
            } else {
                path.moveTo(points.first().x, points.first().y)
            }
            for (i in 0 until points.size - 1) {
                val p0 = points[i]
                val p1 = points[i + 1]
                val ctrlX = (p0.x + p1.x) / 2f
                path.cubicTo(ctrlX, p0.y, ctrlX, p1.y, p1.x, p1.y)
            }
            if (closeToBottom) {
                path.lineTo(points.last().x, h)
                path.close()
            }
            return path
        }

        val rxLine = buildSmoothPath(rxPoints, closeToBottom = false)
        val rxFill = buildSmoothPath(rxPoints, closeToBottom = true)
        val txLine = buildSmoothPath(txPoints, closeToBottom = false)

        drawPath(
            path = rxFill,
            brush = Brush.verticalGradient(
                colors = listOf(rxColor.copy(alpha = 0.22f), Color.Transparent),
            ),
        )
        drawPath(
            path = txLine,
            color = txColor.copy(alpha = 0.82f),
            style = Stroke(width = 1.75.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round),
        )
        drawPath(
            path = rxLine,
            color = rxColor,
            style = Stroke(width = 2.25.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerEditorSheet(
    initialProfile: ProxyProfile?,
    onDismiss: () -> Unit,
    onSave: (ProxyProfile) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val clipboard = LocalClipboardManager.current

    var profileType by remember(initialProfile) {
        mutableStateOf(initialProfile?.profileType ?: ProfileType.WORKER_WS)
    }
    var name by remember(initialProfile) { mutableStateOf(initialProfile?.name ?: "") }

    // Standard SOCKS5 fields
    var host by remember(initialProfile) { mutableStateOf(initialProfile?.host ?: "") }
    var portText by remember(initialProfile) { mutableStateOf((initialProfile?.port ?: 1080).toString()) }
    var useAuth by remember(initialProfile) { mutableStateOf(initialProfile?.useAuth ?: false) }
    var username by remember(initialProfile) { mutableStateOf(initialProfile?.username ?: "") }
    var password by remember(initialProfile) { mutableStateOf(initialProfile?.password ?: "") }
    var udpRelay by remember(initialProfile) { mutableStateOf(initialProfile?.udpRelay ?: true) }
    var showPassword by remember { mutableStateOf(false) }

    // Worker WS fields
    var uuid by remember(initialProfile) { mutableStateOf(initialProfile?.uuid ?: "") }
    var workerHost by remember(initialProfile) { mutableStateOf(initialProfile?.workerHost ?: "") }
    var cleanIp by remember(initialProfile) { mutableStateOf(initialProfile?.cleanIp ?: "") }
    var subproto by remember(initialProfile) { mutableStateOf(initialProfile?.subproto ?: WorkerDefaults.SUBPROTO) }
    var localPortText by remember(initialProfile) {
        mutableStateOf((initialProfile?.localPort ?: WorkerDefaults.LISTEN_PORT).toString())
    }

    var errorText by remember { mutableStateOf<String?>(null) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = if (initialProfile == null) "افزودن سرور" else "ویرایش سرور",
                    style = MaterialTheme.typography.headlineSmall,
                )
                TextButton(
                    onClick = {
                        val clip = clipboard.getText()?.text.orEmpty()
                        ProxyUriParser.parse(clip).onSuccess { parsed ->
                            profileType = parsed.profileType
                            name = parsed.name
                            if (parsed.profileType == ProfileType.WORKER_WS) {
                                uuid = parsed.uuid
                                workerHost = parsed.workerHost
                                cleanIp = parsed.cleanIp
                                subproto = parsed.subproto
                                localPortText = parsed.localPort.toString()
                            } else {
                                host = parsed.host
                                portText = parsed.port.toString()
                                useAuth = parsed.useAuth
                                username = parsed.username
                                password = parsed.password
                            }
                            errorText = null
                        }.onFailure { err ->
                            errorText = err.localizedMessage ?: "لینک معتبری در حافظه یافت نشد."
                        }
                    },
                    modifier = Modifier.testTag("paste_from_clipboard_button"),
                ) {
                    Icon(Icons.Filled.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("جای‌گذاری لینک")
                }
            }

            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = profileType == ProfileType.WORKER_WS,
                    onClick = {
                        profileType = ProfileType.WORKER_WS
                        errorText = null
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                    modifier = Modifier.testTag("type_worker_ws_tab"),
                ) {
                    Text("Worker WebSocket")
                }
                SegmentedButton(
                    selected = profileType == ProfileType.STANDARD_SOCKS5,
                    onClick = {
                        profileType = ProfileType.STANDARD_SOCKS5
                        errorText = null
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                    modifier = Modifier.testTag("type_standard_socks5_tab"),
                ) {
                    Text("SOCKS5 مستقیم")
                }
            }

            if (errorText != null) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.errorContainer,
                ) {
                    Text(
                        text = errorText!!,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                    )
                }
            }

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("نام پروفایل (اختیاری)") },
                placeholder = { Text("مثلاً: Cloudflare Worker") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("server_name_input"),
            )

            if (profileType == ProfileType.WORKER_WS) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        value = workerHost,
                        onValueChange = {
                            workerHost = it
                            errorText = null
                        },
                        label = { Text("Worker Host (دامنه ورکر)") },
                        placeholder = { Text("example.workers.dev") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("worker_host_input"),
                    )

                    OutlinedTextField(
                        value = uuid,
                        onValueChange = {
                            uuid = it
                            errorText = null
                        },
                        label = { Text("UUID") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("worker_uuid_input"),
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        OutlinedTextField(
                            value = cleanIp,
                            onValueChange = { cleanIp = it },
                            label = { Text("Clean IP (آی‌پی تمیز)") },
                            placeholder = { Text("172.67.x.x") },
                            singleLine = true,
                            modifier = Modifier
                                .weight(0.62f)
                                .testTag("worker_clean_ip_input"),
                        )
                        OutlinedTextField(
                            value = localPortText,
                            onValueChange = { localPortText = it.filter { c -> c.isDigit() }.take(5) },
                            label = { Text("پورت محلی") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier
                                .weight(0.38f)
                                .testTag("worker_local_port_input"),
                        )
                    }

                    OutlinedTextField(
                        value = subproto,
                        onValueChange = { subproto = it },
                        label = { Text("Subprotocol (Sec-WebSocket-Protocol)") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("worker_subproto_input"),
                    )
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        OutlinedTextField(
                            value = host,
                            onValueChange = {
                                host = it
                                errorText = null
                            },
                            label = { Text("آدرس سرور (IP / Host)") },
                            placeholder = { Text("185.x.x.x") },
                            singleLine = true,
                            modifier = Modifier
                                .weight(0.68f)
                                .testTag("server_host_input"),
                        )
                        OutlinedTextField(
                            value = portText,
                            onValueChange = { input ->
                                portText = input.filter { it.isDigit() }.take(5)
                                errorText = null
                            },
                            label = { Text("پورت") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier
                                .weight(0.32f)
                                .testTag("server_port_input"),
                        )
                    }
                }

                Surface(
                    shape = MaterialTheme.shapes.medium,
                    color = MaterialTheme.colorScheme.surfaceVariant,
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Lock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                            )
                            Column {
                                Text("احراز هویت (نام کاربری / رمز)", style = MaterialTheme.typography.titleSmall)
                                Text(
                                    "مطابق استاندارد RFC 1929",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Switch(
                            checked = useAuth,
                            onCheckedChange = { useAuth = it },
                            modifier = Modifier.testTag("server_auth_switch"),
                        )
                    }
                }

                if (useAuth) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        OutlinedTextField(
                            value = username,
                            onValueChange = { username = it },
                            label = { Text("نام کاربری (Username)") },
                            singleLine = true,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("server_username_input"),
                        )
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = { Text("رمز عبور (Password)") },
                            singleLine = true,
                            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                            trailingIcon = {
                                IconButton(onClick = { showPassword = !showPassword }) {
                                    Icon(
                                        imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = "نمایش یا مخفی کردن رمز",
                                    )
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("server_password_input"),
                        )
                    }
                }

                Surface(
                    shape = MaterialTheme.shapes.medium,
                    color = MaterialTheme.colorScheme.surfaceVariant,
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Bolt,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.tertiary,
                            )
                            Column {
                                Text("پشتیبانی UDP / DNS", style = MaterialTheme.typography.titleSmall)
                                Text(
                                    "ارسال درخواست‌های DNS از داخل تونل",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Switch(
                            checked = udpRelay,
                            onCheckedChange = { udpRelay = it },
                            modifier = Modifier.testTag("server_udp_switch"),
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .weight(1f)
                        .height(50.dp)
                        .testTag("cancel_server_button"),
                ) {
                    Text(stringResource(R.string.action_cancel))
                }
                Button(
                    onClick = {
                        if (profileType == ProfileType.WORKER_WS) {
                            val cleanWorker = workerHost.trim()
                                .removePrefix("https://")
                                .removePrefix("wss://")
                                .trimEnd('/')
                            val cleanUuid = uuid.trim()
                            val lPort = localPortText.trim().toIntOrNull()
                            when {
                                cleanWorker.isEmpty() -> errorText = "آدرس Worker Host را وارد کنید."
                                cleanUuid.isEmpty() -> errorText = "مقدار UUID را وارد کنید."
                                lPort == null || lPort !in 1024..65535 -> errorText = "پورت محلی باید بین ۱۰۲۴ تا ۶۵۵۳۵ باشد."
                                else -> {
                                    val resolvedName = name.trim().ifEmpty { cleanWorker }
                                    onSave(
                                        ProxyProfile(
                                            id = initialProfile?.id ?: 0L,
                                            name = resolvedName,
                                            profileType = ProfileType.WORKER_WS,
                                            uuid = cleanUuid,
                                            workerHost = cleanWorker,
                                            cleanIp = cleanIp.trim(),
                                            subproto = subproto.trim().ifEmpty { WorkerDefaults.SUBPROTO },
                                            localPort = lPort,
                                            lastLatencyMs = initialProfile?.lastLatencyMs,
                                            lastExitIp = initialProfile?.lastExitIp,
                                            lastCheckedAt = initialProfile?.lastCheckedAt,
                                            createdAt = initialProfile?.createdAt ?: System.currentTimeMillis(),
                                        ),
                                    )
                                }
                            }
                        } else {
                            val cleanHost = host.trim()
                            val port = portText.trim().toIntOrNull()
                            when {
                                cleanHost.isEmpty() -> errorText = "لطفاً آدرس سرور یا IP را وارد کنید."
                                port == null || port !in 1..65535 -> errorText = "پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد."
                                useAuth && username.trim().isEmpty() -> errorText = "نام کاربری را وارد کنید."
                                else -> {
                                    val resolvedName = name.trim().ifEmpty { "$cleanHost:$port" }
                                    onSave(
                                        ProxyProfile(
                                            id = initialProfile?.id ?: 0L,
                                            name = resolvedName,
                                            profileType = ProfileType.STANDARD_SOCKS5,
                                            host = cleanHost,
                                            port = port,
                                            username = if (useAuth) username.trim() else "",
                                            password = if (useAuth) password else "",
                                            useAuth = useAuth,
                                            udpRelay = udpRelay,
                                            localPort = initialProfile?.localPort ?: WorkerDefaults.LISTEN_PORT,
                                            lastLatencyMs = initialProfile?.lastLatencyMs,
                                            lastExitIp = initialProfile?.lastExitIp,
                                            lastCheckedAt = initialProfile?.lastCheckedAt,
                                            createdAt = initialProfile?.createdAt ?: System.currentTimeMillis(),
                                        ),
                                    )
                                }
                            }
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .height(50.dp)
                        .testTag("save_server_button"),
                ) {
                    Text(stringResource(R.string.action_save))
                }
            }
        }
    }
}

@Composable
fun UriImportDialog(
    onDismiss: () -> Unit,
    onImport: (String) -> Unit,
) {
    var uriText by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("ورود کانفیگ از کلیپ‌بورد / لینک") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "فرمت استاندارد CloudNG:\namir://UUID@worker.dev?type=ws&cleanIp=...\namir://user:pass@host:1080?type=socks5\nپشتیبانی از ورود چند کانفیگ همزمان (هر خط یک لینک)",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        value = uriText,
                        onValueChange = { uriText = it },
                        label = { Text("لینک amir:// یا مشخصات سرور") },
                        minLines = 3,
                        maxLines = 5,
                        trailingIcon = {
                            IconButton(
                                onClick = {
                                    clipboard.getText()?.text?.let { uriText = it }
                                },
                            ) {
                                Icon(Icons.Filled.ContentPaste, contentDescription = "جای‌گذاری")
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("uri_import_input"),
                    )
                }
                OutlinedButton(
                    onClick = {
                        val clip = clipboard.getText()?.text.orEmpty()
                        if (clip.isNotBlank()) {
                            onImport(clip)
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("paste_and_import_clipboard_button"),
                ) {
                    Icon(Icons.Filled.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("خواندن مستقیم از کلیپ‌بورد و افزودن")
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onImport(uriText) },
                modifier = Modifier.testTag("confirm_uri_import_button"),
            ) {
                Text("افزودن")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}
