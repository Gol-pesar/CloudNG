package com.example.ui

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Formatters {
    fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format(Locale.US, "%.2f MB", mb)
        val gb = mb / 1024.0
        return String.format(Locale.US, "%.2f GB", gb)
    }

    fun formatSpeed(bytesPerSec: Long): String = "${formatBytes(bytesPerSec)}/s"

    fun formatDuration(connectedSinceMs: Long?, nowMs: Long): String {
        if (connectedSinceMs == null) return "00:00:00"
        val elapsedSec = ((nowMs - connectedSinceMs) / 1000L).coerceAtLeast(0L)
        val hrs = elapsedSec / 3600L
        val mins = (elapsedSec % 3600L) / 60L
        val secs = elapsedSec % 60L
        return String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    }

    fun formatClockTime(timestampMs: Long): String {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.US)
        return sdf.format(Date(timestampMs))
    }
}
