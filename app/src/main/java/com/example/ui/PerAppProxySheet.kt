package com.example.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.PerAppMode
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.SignalEmerald
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledAppEntry(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
    val iconBitmap: ImageBitmap?,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PerAppProxySheet(
    currentMode: PerAppMode,
    selectedPackages: Set<String>,
    onChangeMode: (PerAppMode) -> Unit,
    onTogglePackage: (String) -> Unit,
    onClearSelection: () -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var searchQuery by remember { mutableStateOf("") }
    var installedApps by remember { mutableStateOf<List<InstalledAppEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        isLoading = true
        installedApps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val selfPkg = context.packageName
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
            val resolved = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
            val seen = HashSet<String>()
            val list = ArrayList<InstalledAppEntry>(resolved.size)
            for (ri in resolved) {
                val pkg = ri.activityInfo?.packageName ?: continue
                if (pkg == selfPkg || !seen.add(pkg)) continue
                val appInfo = ri.activityInfo.applicationInfo
                val isSys = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val label = runCatching { ri.loadLabel(pm).toString() }.getOrDefault(pkg)
                val icon = runCatching { drawableToImageBitmap(ri.loadIcon(pm)) }.getOrNull()
                list.add(
                    InstalledAppEntry(
                        packageName = pkg,
                        label = label,
                        isSystemApp = isSys,
                        iconBitmap = icon,
                    ),
                )
            }
            list.sortedWith(
                compareBy<InstalledAppEntry> { !selectedPackages.contains(it.packageName) }
                    .thenBy { it.isSystemApp }
                    .thenBy { it.label.lowercase() },
            )
        }
        isLoading = false
    }

    val filteredApps = remember(installedApps, searchQuery) {
        val q = searchQuery.trim().lowercase()
        if (q.isEmpty()) {
            installedApps
        } else {
            installedApps.filter {
                it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 20.dp)
                .padding(bottom = 18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
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
                    Text("پروکسی تفکیکی برنامه‌ها (Per-App)", style = MaterialTheme.typography.titleLarge)
                }
                if (currentMode != PerAppMode.ALL_APPS && selectedPackages.isNotEmpty()) {
                    TextButton(onClick = onClearSelection) {
                        Text("پاک کردن (${selectedPackages.size})")
                    }
                }
            }

            // Always-bypassed self-protection notice
            Surface(
                shape = MaterialTheme.shapes.small,
                color = SignalEmerald.copy(alpha = 0.14f),
                border = BorderStroke(1.dp, SignalEmerald.copy(alpha = 0.35f)),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        imageVector = Icons.Filled.VerifiedUser,
                        contentDescription = null,
                        tint = SignalEmerald,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = "خود برنامه CloudNG همیشه به صورت خودکار Bypass می‌شود و وارد تونل نمی‌گردد.",
                        style = MaterialTheme.typography.bodySmall,
                        color = SignalEmerald,
                    )
                }
            }

            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = currentMode == PerAppMode.ALL_APPS,
                    onClick = { onChangeMode(PerAppMode.ALL_APPS) },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3),
                    modifier = Modifier.testTag("per_app_all"),
                ) {
                    Text("همه برنامه‌ها", maxLines = 1, fontSize = 11.sp)
                }
                SegmentedButton(
                    selected = currentMode == PerAppMode.BYPASS_SELECTED,
                    onClick = { onChangeMode(PerAppMode.BYPASS_SELECTED) },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3),
                    modifier = Modifier.testTag("per_app_bypass"),
                ) {
                    Text("Bypass انتخابی", maxLines = 1, fontSize = 11.sp)
                }
                SegmentedButton(
                    selected = currentMode == PerAppMode.PROXY_SELECTED,
                    onClick = { onChangeMode(PerAppMode.PROXY_SELECTED) },
                    shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3),
                    modifier = Modifier.testTag("per_app_proxy_only"),
                ) {
                    Text("فقط انتخابی", maxLines = 1, fontSize = 11.sp)
                }
            }

            Text(
                text = when (currentMode) {
                    PerAppMode.ALL_APPS -> "ترافیک تمام برنامه‌ها (به جز CloudNG) از تونل عبور می‌کند."
                    PerAppMode.BYPASS_SELECTED -> "برنامه‌های تیک‌خورده مستقیم (بدون فیلترشکن) متصل می‌شوند."
                    PerAppMode.PROXY_SELECTED -> "فقط برنامه‌های تیک‌خورده از تونل عبور می‌کنند و بقیه مستقیم هستند."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (currentMode != PerAppMode.ALL_APPS) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("جستجوی نام برنامه یا پکیج…") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Filled.Close, contentDescription = "پاک کردن جستجو")
                            }
                        }
                    },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("per_app_search_input"),
                )

                if (isLoading) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(240.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 200.dp, max = 380.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        items(filteredApps, key = { it.packageName }) { app ->
                            val checked = selectedPackages.contains(app.packageName)
                            Surface(
                                onClick = { onTogglePackage(app.packageName) },
                                shape = MaterialTheme.shapes.small,
                                color = if (checked) {
                                    MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.28f)
                                } else {
                                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
                                },
                                border = BorderStroke(
                                    1.dp,
                                    if (checked) {
                                        MaterialTheme.colorScheme.primary.copy(alpha = 0.6f)
                                    } else {
                                        MaterialTheme.colorScheme.outline.copy(alpha = 0.2f)
                                    },
                                ),
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    if (app.iconBitmap != null) {
                                        Image(
                                            bitmap = app.iconBitmap,
                                            contentDescription = null,
                                            modifier = Modifier
                                                .size(34.dp)
                                                .clip(RoundedCornerShape(8.dp)),
                                        )
                                    } else {
                                        Icon(
                                            Icons.Filled.Apps,
                                            contentDescription = null,
                                            modifier = Modifier.size(34.dp),
                                        )
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = app.label,
                                            style = MaterialTheme.typography.titleSmall,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                            Text(
                                                text = app.packageName,
                                                fontFamily = JetBrainsMonoFontFamily,
                                                fontSize = 11.sp,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis,
                                            )
                                        }
                                    }
                                    Checkbox(
                                        checked = checked,
                                        onCheckedChange = { onTogglePackage(app.packageName) },
                                    )
                                }
                            }
                        }
                    }
                }
            } else {
                Spacer(modifier = Modifier.height(6.dp))
            }
        }
    }
}

private fun drawableToImageBitmap(drawable: Drawable): ImageBitmap {
    if (drawable is BitmapDrawable && drawable.bitmap != null) {
        return drawable.bitmap.asImageBitmap()
    }
    val w = drawable.intrinsicWidth.coerceIn(48, 96)
    val h = drawable.intrinsicHeight.coerceIn(48, 96)
    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bmp)
    drawable.setBounds(0, 0, canvas.width, canvas.height)
    drawable.draw(canvas)
    return bmp.asImageBitmap()
}
