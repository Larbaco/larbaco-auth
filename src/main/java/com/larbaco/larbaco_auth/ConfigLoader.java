package com.larbaco.larbaco_auth;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads and manages configuration presets without external dependencies
 * Handles preset inheritance, validation, and merging of configuration values
 * Uses built-in Java collections instead of YAML to avoid dependency issues
 */
public class ConfigLoader {
    private static ConfigData defaults;
    private static final Map<String, ConfigData> presetCache = new HashMap<>();

    // Initialize the loader with built-in presets
    static {
        try {
            loadDefaults();
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to initialize configuration loader: {}", e.getMessage(), e);
            defaults = createFallbackDefaults();
        }
    }

    /**
     * Load configuration defaults from built-in preset definitions
     */
    private static void loadDefaults() {
        try {
            defaults = createBuiltInDefaults();
            LarbacoAuthMain.LOGGER.info("Loaded configuration defaults version: {}", defaults.getVersion());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load defaults: {}", e.getMessage(), e);
            throw new RuntimeException("Cannot load configuration defaults", e);
        }
    }

    /**
     * Load a specific preset by name
     */
    public static ConfigData loadPreset(String presetName) {
        if (presetName == null || presetName.isEmpty()) {
            presetName = defaults.getDefaultPreset();
        }

        // Check cache first
        ConfigData cached = presetCache.get(presetName);
        if (cached != null) {
            return cached;
        }

        try {
            ConfigData preset = createBuiltInPreset(presetName);
            ConfigData merged = defaults.mergeWith(preset);

            // Validate the merged configuration
            ValidationResult validation = validateConfiguration(merged);
            if (!validation.isValid()) {
                LarbacoAuthMain.LOGGER.warn("Preset '{}' has validation issues: {}",
                        presetName, validation.getIssues());
                merged = fixInvalidValues(merged, validation);
            }

            // Cache the result
            presetCache.put(presetName, merged);

            LarbacoAuthMain.LOGGER.info("Loaded preset '{}' successfully", presetName);
            return merged;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load preset '{}': {}", presetName, e.getMessage(), e);
            LarbacoAuthMain.LOGGER.warn("Falling back to defaults");
            return defaults;
        }
    }

    /**
     * Create built-in preset configuration
     */
    private static ConfigData createBuiltInPreset(String presetName) {
        return switch (presetName.toLowerCase()) {
            case "balanced" -> createBalancedPreset();
            case "high_security" -> createHighSecurityPreset();
            case "mobile_friendly" -> createMobileFriendlyPreset();
            case "lan_party" -> createLanPartyPreset();
            case "public_server" -> createPublicServerPreset();
            default -> {
                LarbacoAuthMain.LOGGER.warn("Unknown preset '{}', using balanced", presetName);
                yield createBalancedPreset();
            }
        };
    }

    /**
     * Create balanced preset (recommended default)
     */
    private static ConfigData createBalancedPreset() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 3);
        security.put("sessionDuration", 30);
        security.put("lockoutDuration", 15);
        security.put("passwordMinLength", 6);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", true);
        security.put("requireNumbers", false);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 10);
        sessionSecurity.put("ipBlockDuration", 60);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 100);
        performance.put("databasePoolSize", 5);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 30);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", false);
        monitoring.put("healthCheckInterval", 5);

        return new ConfigData("1.0.0", "balanced",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Create high security preset
     */
    private static ConfigData createHighSecurityPreset() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 2);
        security.put("sessionDuration", 15);
        security.put("lockoutDuration", 30);
        security.put("passwordMinLength", 8);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", true);
        security.put("requireNumbers", true);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 5);
        sessionSecurity.put("ipBlockDuration", 180);
        sessionSecurity.put("allowSubnetChanges", false);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 50);
        performance.put("databasePoolSize", 3);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 90);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", true);
        monitoring.put("healthCheckInterval", 2);

        return new ConfigData("1.0.0", "high_security",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Create mobile friendly preset
     */
    private static ConfigData createMobileFriendlyPreset() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 5);
        security.put("sessionDuration", 60);
        security.put("lockoutDuration", 10);
        security.put("passwordMinLength", 6);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", false);
        security.put("requireNumbers", false);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 20);
        sessionSecurity.put("ipBlockDuration", 30);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 150);
        performance.put("databasePoolSize", 7);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 21);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", false);
        monitoring.put("healthCheckInterval", 10);

        return new ConfigData("1.0.0", "mobile_friendly",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Create LAN party preset
     */
    private static ConfigData createLanPartyPreset() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 10);
        security.put("sessionDuration", 120);
        security.put("lockoutDuration", 5);
        security.put("passwordMinLength", 4);
        security.put("requireMixedCase", false);
        security.put("requireSpecialChar", false);
        security.put("requireNumbers", false);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", false);
        sessionSecurity.put("ipFailureThreshold", 50);
        sessionSecurity.put("ipBlockDuration", 10);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 50);
        performance.put("databasePoolSize", 3);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", false);
        logging.put("logRetentionDays", 7);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", false);
        monitoring.put("healthCheckInterval", 15);

        return new ConfigData("1.0.0", "lan_party",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Create public server preset
     */
    private static ConfigData createPublicServerPreset() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 3);
        security.put("sessionDuration", 45);
        security.put("lockoutDuration", 20);
        security.put("passwordMinLength", 7);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", true);
        security.put("requireNumbers", true);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 8);
        sessionSecurity.put("ipBlockDuration", 120);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 500);
        performance.put("databasePoolSize", 10);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 60);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", true);
        monitoring.put("healthCheckInterval", 3);

        return new ConfigData("1.0.0", "public_server",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Validate configuration against rules
     */
    public static ValidationResult validateConfiguration(ConfigData config) {
        ValidationResult result = new ValidationResult();

        // Validate security settings
        validateRange(config.getSecurity(), "maxLoginAttempts", 1, 10, result);
        validateRange(config.getSecurity(), "sessionDuration", 5, 1440, result);
        validateRange(config.getSecurity(), "lockoutDuration", 1, 1440, result);
        validateRange(config.getSecurity(), "passwordMinLength", 4, 64, result);

        // Validate session security settings
        validateRange(config.getSessionSecurity(), "ipFailureThreshold", 3, 50, result);
        validateRange(config.getSessionSecurity(), "ipBlockDuration", 5, 1440, result);

        // Validate performance settings
        validateRange(config.getPerformance(), "maxConcurrentSessions", 10, 1000, result);
        validateRange(config.getPerformance(), "databasePoolSize", 1, 20, result);

        // Validate logging settings
        validateRange(config.getLogging(), "logRetentionDays", 1, 365, result);

        // Validate monitoring settings
        validateRange(config.getMonitoring(), "healthCheckInterval", 1, 60, result);

        return result;
    }

    /**
     * Validate a numeric range
     */
    private static void validateRange(Map<String, Object> section, String key, int min, int max, ValidationResult result) {
        if (section == null) return;

        Object value = section.get(key);
        if (value instanceof Number numValue) {
            int intValue = numValue.intValue();
            if (intValue < min || intValue > max) {
                result.addIssue(key + " must be between " + min + " and " + max + ", got " + intValue);
            }
        }
    }

    /**
     * Fix invalid configuration values by replacing with defaults
     */
    private static ConfigData fixInvalidValues(ConfigData config, ValidationResult validation) {
        for (String issue : validation.getIssues()) {
            LarbacoAuthMain.LOGGER.warn("Configuration issue (using default): {}", issue);
        }
        return config;
    }

    /**
     * Get available presets
     */
    public static List<String> getAvailablePresets() {
        return List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server");
    }

    /**
     * Get defaults
     */
    public static ConfigData getDefaults() {
        return defaults;
    }

    /**
     * Clear preset cache (for reloading)
     */
    public static void clearCache() {
        presetCache.clear();
        LarbacoAuthMain.LOGGER.debug("Configuration preset cache cleared");
    }

    /**
     * Reload configuration system
     */
    public static void reload() {
        try {
            clearCache();
            loadDefaults();
            LarbacoAuthMain.LOGGER.info("Configuration system reloaded successfully");
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to reload configuration system: {}", e.getMessage(), e);
        }
    }

    /**
     * Create built-in defaults configuration
     */
    private static ConfigData createBuiltInDefaults() {
        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 3);
        security.put("sessionDuration", 30);
        security.put("lockoutDuration", 15);
        security.put("passwordMinLength", 6);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", true);
        security.put("requireNumbers", false);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 10);
        sessionSecurity.put("ipBlockDuration", 60);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 100);
        performance.put("databasePoolSize", 5);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 30);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", false);
        monitoring.put("healthCheckInterval", 5);

        return new ConfigData("1.0.0", "balanced",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }

    /**
     * Create fallback defaults if initialization fails
     */
    private static ConfigData createFallbackDefaults() {
        LarbacoAuthMain.LOGGER.warn("Using hardcoded fallback configuration");

        Map<String, Object> security = new HashMap<>();
        security.put("maxLoginAttempts", 3);
        security.put("sessionDuration", 30);
        security.put("lockoutDuration", 15);
        security.put("passwordMinLength", 6);
        security.put("requireMixedCase", true);
        security.put("requireSpecialChar", true);
        security.put("requireNumbers", false);

        Map<String, Object> sessionSecurity = new HashMap<>();
        sessionSecurity.put("enableSessionIPValidation", true);
        sessionSecurity.put("ipFailureThreshold", 10);
        sessionSecurity.put("ipBlockDuration", 60);
        sessionSecurity.put("allowSubnetChanges", true);

        Map<String, Object> performance = new HashMap<>();
        performance.put("maxConcurrentSessions", 100);
        performance.put("databasePoolSize", 5);

        Map<String, Object> logging = new HashMap<>();
        logging.put("enableDetailedLogging", true);
        logging.put("logRetentionDays", 30);

        Map<String, Object> monitoring = new HashMap<>();
        monitoring.put("enableMonitoring", false);
        monitoring.put("healthCheckInterval", 5);

        return new ConfigData("1.0.0-fallback", "balanced",
                List.of("balanced", "high_security", "mobile_friendly", "lan_party", "public_server"),
                security, sessionSecurity, performance, logging, monitoring, new HashMap<>());
    }
}

/**
 * Holds configuration data and provides merging capabilities
 */
class ConfigData {
    private final String version;
    private final String defaultPreset;
    private final List<String> availablePresets;
    private final Map<String, Object> security;
    private final Map<String, Object> sessionSecurity;
    private final Map<String, Object> performance;
    private final Map<String, Object> logging;
    private final Map<String, Object> monitoring;
    private final Map<String, Object> validation;

    public ConfigData(String version, String defaultPreset, List<String> availablePresets,
                      Map<String, Object> security, Map<String, Object> sessionSecurity,
                      Map<String, Object> performance, Map<String, Object> logging,
                      Map<String, Object> monitoring, Map<String, Object> validation) {
        this.version = version;
        this.defaultPreset = defaultPreset;
        this.availablePresets = availablePresets;
        this.security = security != null ? security : new HashMap<>();
        this.sessionSecurity = sessionSecurity != null ? sessionSecurity : new HashMap<>();
        this.performance = performance != null ? performance : new HashMap<>();
        this.logging = logging != null ? logging : new HashMap<>();
        this.monitoring = monitoring != null ? monitoring : new HashMap<>();
        this.validation = validation != null ? validation : new HashMap<>();
    }

    /**
     * Merge this config with another (other takes precedence)
     */
    public ConfigData mergeWith(ConfigData other) {
        return new ConfigData(
                other.version != null ? other.version : this.version,
                other.defaultPreset != null ? other.defaultPreset : this.defaultPreset,
                other.availablePresets != null ? other.availablePresets : this.availablePresets,
                mergeMaps(this.security, other.security),
                mergeMaps(this.sessionSecurity, other.sessionSecurity),
                mergeMaps(this.performance, other.performance),
                mergeMaps(this.logging, other.logging),
                mergeMaps(this.monitoring, other.monitoring),
                mergeMaps(this.validation, other.validation)
        );
    }

    private Map<String, Object> mergeMaps(Map<String, Object> base, Map<String, Object> override) {
        Map<String, Object> result = new HashMap<>(base);
        if (override != null) {
            result.putAll(override);
        }
        return result;
    }

    // Getters
    public String getVersion() { return version; }
    public String getDefaultPreset() { return defaultPreset; }
    public List<String> getAvailablePresets() { return availablePresets; }
    public Map<String, Object> getSecurity() { return security; }
    public Map<String, Object> getSessionSecurity() { return sessionSecurity; }
    public Map<String, Object> getPerformance() { return performance; }
    public Map<String, Object> getLogging() { return logging; }
    public Map<String, Object> getMonitoring() { return monitoring; }
    public Map<String, Object> getValidation() { return validation; }

    // Convenience getters for specific values
    public int getInt(String section, String key, int defaultValue) {
        Map<String, Object> sectionMap = getSectionMap(section);
        Object value = sectionMap.get(key);
        return value instanceof Number ? ((Number) value).intValue() : defaultValue;
    }

    public boolean getBoolean(String section, String key, boolean defaultValue) {
        Map<String, Object> sectionMap = getSectionMap(section);
        Object value = sectionMap.get(key);
        return value instanceof Boolean ? (Boolean) value : defaultValue;
    }

    Map<String, Object> getSectionMap(String section) {
        return switch (section) {
            case "security" -> security;
            case "sessionSecurity" -> sessionSecurity;
            case "performance" -> performance;
            case "logging" -> logging;
            case "monitoring" -> monitoring;
            default -> new HashMap<>();
        };
    }
}

/**
 * Validation result container
 */
class ValidationResult {
    private final List<String> issues = new java.util.ArrayList<>();

    public void addIssue(String issue) {
        issues.add(issue);
    }

    public boolean isValid() {
        return issues.isEmpty();
    }

    public List<String> getIssues() {
        return new java.util.ArrayList<>(issues);
    }
}