package com.example.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

class ProfileTypeConverters {
    @TypeConverter
    fun fromProfileType(value: ProfileType): String = value.name

    @TypeConverter
    fun toProfileType(value: String): ProfileType =
        runCatching { ProfileType.valueOf(value) }.getOrDefault(ProfileType.STANDARD_SOCKS5)
}

@Database(entities = [ProxyProfile::class], version = 2, exportSchema = false)
@TypeConverters(ProfileTypeConverters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun proxyProfileDao(): ProxyProfileDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "cloudng.db",
                )
                    .fallbackToDestructiveMigration(true)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
