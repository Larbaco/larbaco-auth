/*
 * Copyright (C) 2025 Larbaco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package com.larbaco.larbaco_auth;

import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.config.ModConfigEvent;
import net.neoforged.neoforge.common.ModConfigSpec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID, bus = EventBusSubscriber.Bus.MOD)
public class Config {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    // Security Settings
    public static final ModConfigSpec.IntValue MAX_LOGIN_ATTEMPTS = BUILDER
            .comment("Maximum allowed failed login attempts before account lockout")
            .defineInRange("maxLoginAttempts", 3, 1, 10);

    public static final ModConfigSpec.IntValue SESSION_DURATION = BUILDER
            .comment("Session duration in minutes")
            .defineInRange("sessionDuration", 30, 5, 1440);

    public static final ModConfigSpec.BooleanValue REQUIRE_MIXED_CASE = BUILDER
            .comment("Require passwords to have mixed case letters")
            .define("requireMixedCase", true);

    public static final ModConfigSpec.BooleanValue REQUIRE_SPECIAL_CHAR = BUILDER
            .comment("Require passwords to contain special characters")
            .define("requireSpecialChar", true);

    // Advanced Security Settings
    public static final ModConfigSpec.IntValue LOCKOUT_DURATION = BUILDER
            .comment("Account lockout duration in minutes after max failed attempts")
            .defineInRange("lockoutDuration", 15, 1, 1440);

    public static final ModConfigSpec.IntValue PASSWORD_MIN_LENGTH = BUILDER
            .comment("Minimum password length")
            .defineInRange("passwordMinLength", 6, 4, 64);

    public static final ModConfigSpec.BooleanValue REQUIRE_NUMBERS = BUILDER
            .comment("Require passwords to contain at least one number")
            .define("requireNumbers", false);

    // Performance Settings
    public static final ModConfigSpec.IntValue MAX_CONCURRENT_SESSIONS = BUILDER
            .comment("Maximum number of concurrent authentication sessions")
            .defineInRange("maxConcurrentSessions", 100, 10, 1000);

    public static final ModConfigSpec.IntValue DATABASE_POOL_SIZE = BUILDER
            .comment("Database connection pool size")
            .defineInRange("databasePoolSize", 5, 1, 20);

    // Logging Settings
    public static final ModConfigSpec.BooleanValue ENABLE_DETAILED_LOGGING = BUILDER
            .comment("Enable detailed authentication logging")
            .define("enableDetailedLogging", true);

    public static final ModConfigSpec.IntValue LOG_RETENTION_DAYS = BUILDER
            .comment("Number of days to retain authentication logs")
            .defineInRange("logRetentionDays", 30, 1, 365);

    // Monitoring Settings
    public static final ModConfigSpec.BooleanValue ENABLE_MONITORING = BUILDER
            .comment("Enable real-time system monitoring")
            .define("enableMonitoring", false);

    public static final ModConfigSpec.IntValue HEALTH_CHECK_INTERVAL = BUILDER
            .comment("Health check interval in minutes")
            .defineInRange("healthCheckInterval", 5, 1, 60);

    static final ModConfigSpec SPEC = BUILDER.build();

    // Runtime values
    public static int maxLoginAttempts;
    public static int sessionDuration;
    public static boolean requireMixedCase;
    public static boolean requireSpecialChar;
    public static int lockoutDuration;
    public static int passwordMinLength;
    public static boolean requireNumbers;
    public static int maxConcurrentSessions;
    public static int databasePoolSize;
    public static boolean enableDetailedLogging;
    public static int logRetentionDays;
    public static boolean enableMonitoring;
    public static int healthCheckInterval;

    private static Path configPath;
    private static long lastReloadTime = 0;

    @SubscribeEvent
    static void onLoad(final ModConfigEvent event) {
        try {
            loadConfigValues();
            configPath = event.getConfig().getFullPath();
            lastReloadTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Configuration loaded successfully");

            if (enableDetailedLogging) {
                AuthLogger.logSystemEvent("CONFIG_LOADED", getConfigSummary());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error loading configuration: {}", e.getMessage(), e);
        }
    }

    private static void loadConfigValues() {
        maxLoginAttempts = MAX_LOGIN_ATTEMPTS.get();
        sessionDuration = SESSION_DURATION.get();
        requireMixedCase = REQUIRE_MIXED_CASE.get();
        requireSpecialChar = REQUIRE_SPECIAL_CHAR.get();
        lockoutDuration = LOCKOUT_DURATION.get();
        passwordMinLength = PASSWORD_MIN_LENGTH.get();
        requireNumbers = REQUIRE_NUMBERS.get();
        maxConcurrentSessions = MAX_CONCURRENT_SESSIONS.get();
        databasePoolSize = DATABASE_POOL_SIZE.get();
        enableDetailedLogging = ENABLE_DETAILED_LOGGING.get();
        logRetentionDays = LOG_RETENTION_DAYS.get();
        enableMonitoring = ENABLE_MONITORING.get();
        healthCheckInterval = HEALTH_CHECK_INTERVAL.get();
    }

    public static void reload() {
        try {
            // In NeoForge, config values are automatically reloaded from the file
            // We just need to refresh our cached values
            loadConfigValues();
            lastReloadTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Configuration reloaded successfully");

            if (enableDetailedLogging) {
                AuthLogger.logSystemEvent("CONFIG_RELOADED", getConfigSummary());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error reloading configuration: {}", e.getMessage(), e);
            throw new RuntimeException("Configuration reload failed", e);
        }
    }

    public static boolean validate() {
        try {
            List<String> issues = new ArrayList<>();

            if (maxLoginAttempts < 1 || maxLoginAttempts > 10) {
                issues.add("maxLoginAttempts must be between 1 and 10");
            }

            if (sessionDuration < 5 || sessionDuration > 1440) {
                issues.add("sessionDuration must be between 5 and 1440 minutes");
            }

            if (lockoutDuration < 1 || lockoutDuration > 1440) {
                issues.add("lockoutDuration must be between 1 and 1440 minutes");
            }

            if (passwordMinLength < 4 || passwordMinLength > 64) {
                issues.add("passwordMinLength must be between 4 and 64 characters");
            }

            if (maxConcurrentSessions < 10 || maxConcurrentSessions > 1000) {
                issues.add("maxConcurrentSessions must be between 10 and 1000");
            }

            if (databasePoolSize < 1 || databasePoolSize > 20) {
                issues.add("databasePoolSize must be between 1 and 20");
            }

            if (logRetentionDays < 1 || logRetentionDays > 365) {
                issues.add("logRetentionDays must be between 1 and 365");
            }

            if (healthCheckInterval < 1 || healthCheckInterval > 60) {
                issues.add("healthCheckInterval must be between 1 and 60 minutes");
            }

            if (!issues.isEmpty()) {
                LarbacoAuthMain.LOGGER.error("Configuration validation failed:");
                for (String issue : issues) {
                    LarbacoAuthMain.LOGGER.error("  - {}", issue);
                }
                return false;
            }

            return true;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error validating configuration: {}", e.getMessage(), e);
            return false;
        }
    }

    public static String getConfigPath() {
        return configPath != null ? configPath.toString() : "Unknown";
    }

    public static long getLastReloadTime() {
        return lastReloadTime;
    }

    public static String getConfigSummary() {
        return String.format(
                "Security: maxAttempts=%d, sessionDuration=%d, lockoutDuration=%d, " +
                        "passwordMinLength=%d, requireMixedCase=%s, requireSpecialChar=%s, requireNumbers=%s; " +
                        "Performance: maxSessions=%d, dbPoolSize=%d; " +
                        "Monitoring: detailedLogging=%s, logRetention=%d days, monitoring=%s, healthInterval=%d min",
                maxLoginAttempts, sessionDuration, lockoutDuration, passwordMinLength,
                requireMixedCase, requireSpecialChar, requireNumbers,
                maxConcurrentSessions, databasePoolSize,
                enableDetailedLogging, logRetentionDays, enableMonitoring, healthCheckInterval
        );
    }

    public static boolean isMonitoringEnabled() {
        return enableMonitoring;
    }

    public static boolean isDetailedLoggingEnabled() {
        return enableDetailedLogging;
    }

    public static String getPasswordRequirementsString() {
        StringBuilder requirements = new StringBuilder();
        requirements.append("at least ").append(passwordMinLength).append(" characters");

        if (requireMixedCase) {
            requirements.append(", mixed case letters");
        }

        if (requireNumbers) {
            requirements.append(", at least one number");
        }

        if (requireSpecialChar) {
            requirements.append(", at least one special character (!@#$%^&*()_+-=[]{}|;':\"\\,.<>?/)");
        }

        return requirements.toString();
    }

    public static boolean validatePassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            return false;
        }

        if (password.length() < passwordMinLength) {
            return false;
        }

        if (requireMixedCase) {
            boolean hasUpper = !password.equals(password.toLowerCase());
            boolean hasLower = !password.equals(password.toUpperCase());
            if (!(hasUpper && hasLower)) {
                return false;
            }
        }

        if (requireNumbers) {
            if (!password.matches(".*\\d.*")) {
                return false;
            }
        }

        if (requireSpecialChar) {
            if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) {
                return false;
            }
        }

        return true;
    }

    public static void createDefaultConfig(Path configFile) {
        try {
            if (!Files.exists(configFile.getParent())) {
                Files.createDirectories(configFile.getParent());
            }

            String defaultConfig = """
                    # LarbacoAuth Configuration File
                    # 
                    # Security Settings
                    maxLoginAttempts = 3
                    sessionDuration = 30
                    requireMixedCase = true
                    requireSpecialChar = true
                    lockoutDuration = 15
                    passwordMinLength = 6
                    requireNumbers = false
                    
                    # Performance Settings
                    maxConcurrentSessions = 100
                    databasePoolSize = 5
                    
                    # Logging Settings
                    enableDetailedLogging = true
                    logRetentionDays = 30
                    
                    # Monitoring Settings
                    enableMonitoring = false
                    healthCheckInterval = 5
                    """;

            Files.writeString(configFile, defaultConfig);
            LarbacoAuthMain.LOGGER.info("Created default configuration file: {}", configFile);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Failed to create default configuration: {}", e.getMessage(), e);
        }
    }
}