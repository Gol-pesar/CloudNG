package com.example.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface ProxyProfileDao {
    @Query("SELECT * FROM proxy_profiles ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<ProxyProfile>>

    @Query("SELECT * FROM proxy_profiles WHERE id = :id LIMIT 1")
    suspend fun getById(id: Long): ProxyProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(profile: ProxyProfile): Long

    @Update
    suspend fun update(profile: ProxyProfile)

    @Query("DELETE FROM proxy_profiles WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query(
        "UPDATE proxy_profiles SET lastLatencyMs = :latencyMs, lastExitIp = :exitIp, lastCheckedAt = :checkedAt WHERE id = :id"
    )
    suspend fun updateProbeResult(
        id: Long,
        latencyMs: Long?,
        exitIp: String?,
        checkedAt: Long,
    )
}
