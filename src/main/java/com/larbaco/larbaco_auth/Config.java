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
import java.util.ArrayList;
import java.util.List;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID, bus = EventBusSubscriber.Bus.MOD)
public class Config {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    // Special values to indicate "use preset value"
    private static final String USE_PRESET_STRING = "USE_PRESET_VALUE";
    private static final int USE_PRESET_INT = -1;

    // Preset selection
    public static final ModConfigSpec.ConfigValue<String> PRESET = BUILDER
            .comment("Configuration preset to use",
                    "Available: balanced, high_security, mobile_friendly, lan_party, public_server",
                    "Use 'custom' to specify all values manually")
            .define("preset", "balanced");

    // Security Settings
    public static final ModConfigSpec.IntValue MAX_LOGIN_ATTEMPTS = BUILDER
            .comment("Maximum allowed failed login attempts before account lockout",
                    "Set to -1 to use preset value")
            .defineInRange("maxLoginAttempts", USE_PRESET_INT, -1, 10);

    public static final ModConfigSpec.IntValue SESSION_DURATION = BUILDER
            .comment("Session duration in minutes", "Set to -1 to use preset value")
            .defineInRange("sessionDuration", USE_PRESET_INT, -1, 1440);

    public static final ModConfigSpec.ConfigValue<String> REQUIRE_MIXED_CASE = BUILDER
            .comment("Require passwords to have mixed case letters",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("requireMixedCase", USE_PRESET_STRING);

    public static final ModConfigSpec.ConfigValue<String> REQUIRE_SPECIAL_CHAR = BUILDER
            .comment("Require passwords to contain special characters",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("requireSpecialChar", USE_PRESET_STRING);

    public static final ModConfigSpec.IntValue LOCKOUT_DURATION = BUILDER
            .comment("Account lockout duration in minutes after max failed attempts",
                    "Set to -1 to use preset value")
            .defineInRange("lockoutDuration", USE_PRESET_INT, -1, 1440);

    public static final ModConfigSpec.IntValue PASSWORD_MIN_LENGTH = BUILDER
            .comment("Minimum password length", "Set to -1 to use preset value")
            .defineInRange("passwordMinLength", USE_PRESET_INT, -1, 64);

    public static final ModConfigSpec.ConfigValue<String> REQUIRE_NUMBERS = BUILDER
            .comment("Require passwords to contain at least one number",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("requireNumbers", USE_PRESET_STRING);

    // Session Security Settings
    public static final ModConfigSpec.ConfigValue<String> ENABLE_SESSION_IP_VALIDATION = BUILDER
            .comment("Enable IP validation for sessions (prevents session hijacking)",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("enableSessionIPValidation", USE_PRESET_STRING);

    public static final ModConfigSpec.IntValue IP_FAILURE_THRESHOLD = BUILDER
            .comment("Number of IP validation failures before temporarily blocking IP",
                    "Set to -1 to use preset value")
            .defineInRange("ipFailureThreshold", USE_PRESET_INT, -1, 50);

    public static final ModConfigSpec.IntValue IP_BLOCK_DURATION = BUILDER
            .comment("Duration in minutes to block suspicious IPs", "Set to -1 to use preset value")
            .defineInRange("ipBlockDuration", USE_PRESET_INT, -1, 1440);

    public static final ModConfigSpec.ConfigValue<String> ALLOW_SUBNET_CHANGES = BUILDER
            .comment("Allow IP changes within the same subnet (recommended for mobile users)",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("allowSubnetChanges", USE_PRESET_STRING);

    // Performance Settings
    public static final ModConfigSpec.IntValue MAX_CONCURRENT_SESSIONS = BUILDER
            .comment("Maximum number of concurrent authentication sessions",
                    "Set to -1 to use preset value")
            .defineInRange("maxConcurrentSessions", USE_PRESET_INT, -1, 1000);

    public static final ModConfigSpec.IntValue DATABASE_POOL_SIZE = BUILDER
            .comment("Database connection pool size", "Set to -1 to use preset value")
            .defineInRange("databasePoolSize", USE_PRESET_INT, -1, 20);

    // Logging Settings
    public static final ModConfigSpec.ConfigValue<String> ENABLE_DETAILED_LOGGING = BUILDER
            .comment("Enable detailed authentication logging",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("enableDetailedLogging", USE_PRESET_STRING);

    public static final ModConfigSpec.IntValue LOG_RETENTION_DAYS = BUILDER
            .comment("Number of days to retain authentication logs", "Set to -1 to use preset value")
            .defineInRange("logRetentionDays", USE_PRESET_INT, -1, 365);

    // Monitoring Settings
    public static final ModConfigSpec.ConfigValue<String> ENABLE_MONITORING = BUILDER
            .comment("Enable real-time system monitoring",
                    "Set to 'USE_PRESET_VALUE' to use preset value, 'true' or 'false' to override")
            .define("enableMonitoring", USE_PRESET_STRING);

    public static final ModConfigSpec.IntValue HEALTH_CHECK_INTERVAL = BUILDER
            .comment("Health check interval in minutes", "Set to -1 to use preset value")
            .defineInRange("healthCheckInterval", USE_PRESET_INT, -1, 60);

    static final ModConfigSpec SPEC = BUILDER.build();

    // Current configuration data
    private static ConfigData currentConfig;
    private static String currentPreset = "balanced";

    // Runtime values for easy access
    public static int maxLoginAttempts;
    public static int sessionDuration;
    public static boolean requireMixedCase;
    public static boolean requireSpecialChar;
    public static int lockoutDuration;
    public static int passwordMinLength;
    public static boolean requireNumbers;
    public static boolean enableSessionIPValidation;
    public static int ipFailureThreshold;
    public static int ipBlockDuration;
    public static boolean allowSubnetChanges;
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
            loadConfiguration();
            configPath = event.getConfig().getFullPath();
            lastReloadTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Configuration loaded successfully using preset: {}", currentPreset);

            if (enableDetailedLogging) {
                AuthLogger.logSystemEvent("CONFIG_LOADED", getConfigSummary());
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error loading configuration: {}", e.getMessage(), e);
        }
    }

    private static void loadConfiguration() {
        try {
            currentPreset = PRESET.get();
            if (currentPreset == null || currentPreset.isEmpty()) {
                currentPreset = "balanced";
            }

            currentConfig = ConfigLoader.loadPreset(currentPreset);
            applyUserOverrides();
            extractRuntimeValues();

            if (!enableSessionIPValidation) {
                LarbacoAuthMain.LOGGER.warn("⚠️  IP validation is DISABLED - sessions are vulnerable to hijacking!");
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load configuration: {}", e.getMessage(), e);
            throw new RuntimeException("Configuration loading failed", e);
        }
    }

    private static void applyUserOverrides() {
        // Security overrides
        if (MAX_LOGIN_ATTEMPTS.get() != USE_PRESET_INT) {
            currentConfig.getSecurity().put("maxLoginAttempts", MAX_LOGIN_ATTEMPTS.get());
        }
        if (SESSION_DURATION.get() != USE_PRESET_INT) {
            currentConfig.getSecurity().put("sessionDuration", SESSION_DURATION.get());
        }
        if (LOCKOUT_DURATION.get() != USE_PRESET_INT) {
            currentConfig.getSecurity().put("lockoutDuration", LOCKOUT_DURATION.get());
        }
        if (PASSWORD_MIN_LENGTH.get() != USE_PRESET_INT) {
            currentConfig.getSecurity().put("passwordMinLength", PASSWORD_MIN_LENGTH.get());
        }

        applyBooleanOverride(REQUIRE_MIXED_CASE.get(), "security", "requireMixedCase");
        applyBooleanOverride(REQUIRE_SPECIAL_CHAR.get(), "security", "requireSpecialChar");
        applyBooleanOverride(REQUIRE_NUMBERS.get(), "security", "requireNumbers");

        // Session security overrides
        applyBooleanOverride(ENABLE_SESSION_IP_VALIDATION.get(), "sessionSecurity", "enableSessionIPValidation");

        if (IP_FAILURE_THRESHOLD.get() != USE_PRESET_INT) {
            currentConfig.getSessionSecurity().put("ipFailureThreshold", IP_FAILURE_THRESHOLD.get());
        }
        if (IP_BLOCK_DURATION.get() != USE_PRESET_INT) {
            currentConfig.getSessionSecurity().put("ipBlockDuration", IP_BLOCK_DURATION.get());
        }

        applyBooleanOverride(ALLOW_SUBNET_CHANGES.get(), "sessionSecurity", "allowSubnetChanges");

        // Performance overrides
        if (MAX_CONCURRENT_SESSIONS.get() != USE_PRESET_INT) {
            currentConfig.getPerformance().put("maxConcurrentSessions", MAX_CONCURRENT_SESSIONS.get());
        }
        if (DATABASE_POOL_SIZE.get() != USE_PRESET_INT) {
            currentConfig.getPerformance().put("databasePoolSize", DATABASE_POOL_SIZE.get());
        }

        // Logging overrides
        applyBooleanOverride(ENABLE_DETAILED_LOGGING.get(), "logging", "enableDetailedLogging");

        if (LOG_RETENTION_DAYS.get() != USE_PRESET_INT) {
            currentConfig.getLogging().put("logRetentionDays", LOG_RETENTION_DAYS.get());
        }

        // Monitoring overrides
        applyBooleanOverride(ENABLE_MONITORING.get(), "monitoring", "enableMonitoring");

        if (HEALTH_CHECK_INTERVAL.get() != USE_PRESET_INT) {
            currentConfig.getMonitoring().put("healthCheckInterval", HEALTH_CHECK_INTERVAL.get());
        }
    }

    // Helper method to apply boolean overrides from string values
    private static void applyBooleanOverride(String stringValue, String section, String key) {
        if (!USE_PRESET_STRING.equals(stringValue)) {
            boolean boolValue = parseBooleanSafely(stringValue, true);
            currentConfig.getSectionMap(section).put(key, boolValue);
        }
    }

    // Safely parse boolean from string with fallback
    private static boolean parseBooleanSafely(String value, boolean fallback) {
        if (value == null) return fallback;

        String lower = value.toLowerCase().trim();
        if ("true".equals(lower) || "yes".equals(lower) || "1".equals(lower)) {
            return true;
        } else if ("false".equals(lower) || "no".equals(lower) || "0".equals(lower)) {
            return false;
        }

        LarbacoAuthMain.LOGGER.warn("Invalid boolean value '{}', using fallback: {}", value, fallback);
        return fallback;
    }

    private static void extractRuntimeValues() {
        maxLoginAttempts = currentConfig.getInt("security", "maxLoginAttempts", 3);
        sessionDuration = currentConfig.getInt("security", "sessionDuration", 30);
        lockoutDuration = currentConfig.getInt("security", "lockoutDuration", 15);
        passwordMinLength = currentConfig.getInt("security", "passwordMinLength", 6);
        requireMixedCase = currentConfig.getBoolean("security", "requireMixedCase", true);
        requireSpecialChar = currentConfig.getBoolean("security", "requireSpecialChar", true);
        requireNumbers = currentConfig.getBoolean("security", "requireNumbers", false);

        enableSessionIPValidation = currentConfig.getBoolean("sessionSecurity", "enableSessionIPValidation", true);
        ipFailureThreshold = currentConfig.getInt("sessionSecurity", "ipFailureThreshold", 10);
        ipBlockDuration = currentConfig.getInt("sessionSecurity", "ipBlockDuration", 60);
        allowSubnetChanges = currentConfig.getBoolean("sessionSecurity", "allowSubnetChanges", true);

        maxConcurrentSessions = currentConfig.getInt("performance", "maxConcurrentSessions", 100);
        databasePoolSize = currentConfig.getInt("performance", "databasePoolSize", 5);

        enableDetailedLogging = currentConfig.getBoolean("logging", "enableDetailedLogging", true);
        logRetentionDays = currentConfig.getInt("logging", "logRetentionDays", 30);

        enableMonitoring = currentConfig.getBoolean("monitoring", "enableMonitoring", false);
        healthCheckInterval = currentConfig.getInt("monitoring", "healthCheckInterval", 5);
    }

    public static void reload() {
        try {
            ConfigLoader.reload();
            loadConfiguration();
            lastReloadTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Configuration reloaded successfully using preset: {}", currentPreset);

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
            var validation = ConfigLoader.validateConfiguration(currentConfig);

            if (!validation.isValid()) {
                LarbacoAuthMain.LOGGER.error("Configuration validation failed:");
                for (String issue : validation.getIssues()) {
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

    public static String getCurrentPreset() {
        return currentPreset;
    }

    public static List<String> getAvailablePresets() {
        try {
            return ConfigLoader.getAvailablePresets();
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error getting available presets: {}", e.getMessage());
            return List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server");
        }
    }

    public static String getConfigSummary() {
        return String.format(
                "Preset: %s; Security: maxAttempts=%d, sessionDuration=%d, lockoutDuration=%d, " +
                        "passwordMinLength=%d, requireMixedCase=%s, requireSpecialChar=%s, requireNumbers=%s; " +
                        "Session: ipValidation=%s, ipFailureThreshold=%d, ipBlockDuration=%d, allowSubnetChanges=%s; " +
                        "Performance: maxSessions=%d, dbPoolSize=%d; " +
                        "Monitoring: detailedLogging=%s, logRetention=%d days, monitoring=%s, healthInterval=%d min",
                currentPreset, maxLoginAttempts, sessionDuration, lockoutDuration, passwordMinLength,
                requireMixedCase, requireSpecialChar, requireNumbers,
                enableSessionIPValidation, ipFailureThreshold, ipBlockDuration, allowSubnetChanges,
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

    // Get IP security configuration for use by AuthSessionManager
    public static IPSecurityConfig getIPSecurityConfig() {
        return new IPSecurityConfig(
                enableSessionIPValidation,
                ipFailureThreshold,
                ipBlockDuration * 60000L, // Convert minutes to milliseconds
                allowSubnetChanges
        );
    }

    public record IPSecurityConfig(
            boolean enabled,
            int failureThreshold,
            long blockDurationMs,
            boolean allowSubnetChanges
    ) {}

    public static void createDefaultConfig(Path configFile) {
        try {
            if (!Files.exists(configFile.getParent())) {
                Files.createDirectories(configFile.getParent());
            }

            String defaultConfig = String.format("""
                    # LarbacoAuth Configuration File
                    # 
                    # Choose a preset that matches your server's needs:
                    # - balanced:       Recommended for most servers (default)
                    # - high_security:  Maximum security for sensitive servers
                    # - mobile_friendly: Optimized for mobile players
                    # - lan_party:      Relaxed for trusted local networks only
                    # - public_server:  Large public servers with diverse players
                    # - custom:         Specify all values manually
                    
                    preset = "%s"
                    
                    # Override specific preset values:
                    # For integers: set to -1 to use preset value
                    # For booleans: set to "USE_PRESET_VALUE" to use preset, or "true"/"false" to override
                    
                    # Security Settings
                    maxLoginAttempts = -1
                    sessionDuration = -1
                    lockoutDuration = -1
                    passwordMinLength = -1
                    requireMixedCase = "USE_PRESET_VALUE"
                    requireSpecialChar = "USE_PRESET_VALUE"
                    requireNumbers = "USE_PRESET_VALUE"
                    
                    # Session Security Settings
                    enableSessionIPValidation = "USE_PRESET_VALUE"
                    ipFailureThreshold = -1
                    ipBlockDuration = -1
                    allowSubnetChanges = "USE_PRESET_VALUE"
                    
                    # Performance Settings
                    maxConcurrentSessions = -1
                    databasePoolSize = -1
                    
                    # Logging Settings
                    enableDetailedLogging = "USE_PRESET_VALUE"
                    logRetentionDays = -1
                    
                    # Monitoring Settings
                    enableMonitoring = "USE_PRESET_VALUE"
                    healthCheckInterval = -1
                    """, currentPreset);

            Files.writeString(configFile, defaultConfig);
            LarbacoAuthMain.LOGGER.info("Created default configuration file: {}", configFile);
        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Failed to create default configuration: {}", e.getMessage(), e);
        }
    }

    public static boolean switchPreset(String newPreset) {
        try {
            List<String> available = getAvailablePresets();
            if (!available.contains(newPreset)) {
                LarbacoAuthMain.LOGGER.error("Unknown preset: {}. Available: {}", newPreset, available);
                return false;
            }

            LarbacoAuthMain.LOGGER.info("Switching from preset '{}' to '{}'", currentPreset, newPreset);
            LarbacoAuthMain.LOGGER.info("To switch presets, edit your config file and change: preset = \"{}\"", newPreset);
            LarbacoAuthMain.LOGGER.info("Then run: /authman reload");

            return true;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error switching preset: {}", e.getMessage(), e);
            return false;
        }
    }

    public static ConfigData getCurrentConfigData() {
        return currentConfig;
    }

    public static <T> T getConfigValue(String section, String key, T defaultValue, Class<T> type) {
        try {
            Object value = currentConfig.getSectionMap(section).get(key);
            if (value != null && type.isInstance(value)) {
                return type.cast(value);
            }
            return defaultValue;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.warn("Error getting config value {}.{}: {}", section, key, e.getMessage());
            return defaultValue;
        }
    }

    public static boolean isUsingDefaults() {
        return "balanced".equals(currentPreset) &&
                MAX_LOGIN_ATTEMPTS.get() == USE_PRESET_INT &&
                SESSION_DURATION.get() == USE_PRESET_INT &&
                USE_PRESET_STRING.equals(ENABLE_SESSION_IP_VALIDATION.get());
    }

    public static String getRecommendedPreset(int playerCount, boolean hasMobileUsers, boolean isPublic) {
        if (playerCount < 10) {
            return hasMobileUsers ? "mobile_friendly" : "balanced";
        } else if (playerCount > 100) {
            return "public_server";
        } else if (!isPublic) {
            return "high_security";
        } else {
            return hasMobileUsers ? "mobile_friendly" : "balanced";
        }
    }

    @Deprecated
    public static boolean getBoolean(String s, boolean b) {
        LarbacoAuthMain.LOGGER.warn("Deprecated method getBoolean() called - update your code");
        return b;
    }
}