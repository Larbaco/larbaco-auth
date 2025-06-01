package com.larbaco.larbaco_auth.monitoring;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.commands.RegisterCommand;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.storage.DataManager;

import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.RuntimeMXBean;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class SystemMonitor {
    private static final String REPORTS_DIR = "config/larbaco_auth/reports";
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    // Performance tracking
    private static final AtomicLong totalAuthTime = new AtomicLong(0);
    private static final AtomicInteger authOperationCount = new AtomicInteger(0);
    private static final AtomicInteger sessionsCreated = new AtomicInteger(0);
    private static final AtomicInteger sessionsExpired = new AtomicInteger(0);
    private static final AtomicInteger totalLoginAttempts = new AtomicInteger(0);
    private static final AtomicInteger failedLoginAttempts = new AtomicInteger(0);
    private static final AtomicLong databaseOperations = new AtomicLong(0);

    // System health tracking
    private static final Map<String, Boolean> componentHealth = new ConcurrentHashMap<>();
    private static final Map<String, String> lastErrors = new ConcurrentHashMap<>();
    private static final Map<String, Long> lastHealthCheck = new ConcurrentHashMap<>();

    // Real-time monitoring
    private static volatile boolean realTimeMonitoring = false;
    private static ScheduledExecutorService monitoringService;

    private static final long startupTime = System.currentTimeMillis();

    static {
        componentHealth.put("Authentication", true);
        componentHealth.put("Database", true);
        componentHealth.put("SessionManager", true);
        componentHealth.put("Configuration", true);
        componentHealth.put("Logging", true);

        try {
            Files.createDirectories(Paths.get(REPORTS_DIR));
        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Failed to create reports directory: {}", e.getMessage());
        }
    }

    public static void recordAuthOperation(long durationMs) {
        totalAuthTime.addAndGet(durationMs);
        authOperationCount.incrementAndGet();
    }

    public static void recordLoginAttempt(boolean success) {
        totalLoginAttempts.incrementAndGet();
        if (!success) {
            failedLoginAttempts.incrementAndGet();
        }
    }

    public static void recordSessionCreated() {
        sessionsCreated.incrementAndGet();
    }

    public static void recordSessionExpired() {
        sessionsExpired.incrementAndGet();
    }

    public static void recordDatabaseOperation() {
        databaseOperations.incrementAndGet();
    }

    public static void updateComponentHealth(String component, boolean healthy, String error) {
        componentHealth.put(component, healthy);
        lastHealthCheck.put(component, System.currentTimeMillis());

        if (!healthy && error != null) {
            lastErrors.put(component, error);
            LarbacoAuthMain.LOGGER.warn("Component {} marked as unhealthy: {}", component, error);
        } else if (healthy) {
            lastErrors.remove(component);
        }
    }

    public static SystemStatistics getSystemStatistics() {
        try {
            int registeredPlayers = RegisterCommand.getRegisteredPlayerCount();
            int authenticatedPlayers = LarbacoAuthMain.getAuthenticatedPlayerCount();

            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            double successRate = totalLoginAttempts.get() > 0 ?
                    ((double) (totalLoginAttempts.get() - failedLoginAttempts.get()) / totalLoginAttempts.get()) * 100 : 0.0;

            String sessionStats = AuthSessionManager.getSessionStats();
            String[] parts = sessionStats.split(", ");
            int activeSessions = 0;
            int pendingOperations = 0;

            try {
                if (parts.length >= 2) {
                    activeSessions = Integer.parseInt(parts[0].split(": ")[1]);
                    pendingOperations = Integer.parseInt(parts[1].split(": ")[1]);
                }
            } catch (NumberFormatException e) {
                LarbacoAuthMain.LOGGER.debug("Error parsing session stats: {}", e.getMessage());
            }

            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            double memoryUsageMB = memoryBean.getHeapMemoryUsage().getUsed() / (1024.0 * 1024.0);

            long uptimeMs = System.currentTimeMillis() - startupTime;
            String uptime = formatDuration(Duration.ofMillis(uptimeMs));

            return new SystemStatistics(
                    registeredPlayers,
                    authenticatedPlayers,
                    totalLoginAttempts.get(),
                    failedLoginAttempts.get(),
                    successRate,
                    activeSessions,
                    pendingOperations,
                    sessionsCreated.get(),
                    sessionsExpired.get(),
                    avgAuthTime,
                    databaseOperations.get(),
                    memoryUsageMB,
                    uptime
            );

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error gathering system statistics: {}", e.getMessage(), e);
            return new SystemStatistics(0, 0, 0, 0, 0.0, 0, 0, 0, 0, 0.0, 0, 0.0, "Unknown");
        }
    }

    public static HealthCheckResult performHealthCheck() {
        List<String> warnings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        Map<String, Boolean> currentHealth = new HashMap<>(componentHealth);

        checkAuthenticationHealth(warnings, errors);
        checkDatabaseHealth(warnings, errors);
        checkSessionHealth(warnings, errors);
        checkConfigurationHealth(warnings, errors);
        checkPerformanceHealth(warnings, errors);

        boolean isHealthy = errors.isEmpty() &&
                componentHealth.values().stream().allMatch(Boolean::booleanValue);

        String performanceStatus = determinePerformanceStatus();

        return new HealthCheckResult(
                isHealthy,
                currentHealth,
                warnings,
                errors,
                performanceStatus
        );
    }

    public static boolean startRealTimeMonitoring() {
        if (realTimeMonitoring) {
            return false;
        }

        realTimeMonitoring = true;
        monitoringService = Executors.newScheduledThreadPool(2);

        monitoringService.scheduleAtFixedRate(() -> {
            try {
                HealthCheckResult health = performHealthCheck();
                if (!health.isHealthy()) {
                    LarbacoAuthMain.LOGGER.warn("Health check failed: {} errors, {} warnings",
                            health.errors().size(), health.warnings().size());
                }
            } catch (Exception e) {
                LarbacoAuthMain.LOGGER.error("Error during scheduled health check: {}", e.getMessage());
            }
        }, 0, 5, TimeUnit.MINUTES);

        monitoringService.scheduleAtFixedRate(() -> {
            try {
                logPerformanceMetrics();
            } catch (Exception e) {
                LarbacoAuthMain.LOGGER.error("Error during performance monitoring: {}", e.getMessage());
            }
        }, 1, 1, TimeUnit.MINUTES);

        AuthLogger.logSystemEvent("MONITORING_START", "Real-time monitoring enabled");
        return true;
    }

    public static boolean stopRealTimeMonitoring() {
        if (!realTimeMonitoring) {
            return false;
        }

        realTimeMonitoring = false;

        if (monitoringService != null) {
            monitoringService.shutdown();
            try {
                if (!monitoringService.awaitTermination(10, TimeUnit.SECONDS)) {
                    monitoringService.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                monitoringService.shutdownNow();
            }
        }

        AuthLogger.logSystemEvent("MONITORING_STOP", "Real-time monitoring disabled");
        return true;
    }

    public static String generateDetailedReport() throws IOException {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String reportFileName = String.format("system_report_%s.json", timestamp);
        Path reportPath = Paths.get(REPORTS_DIR, reportFileName);

        MonitoringReport report = new MonitoringReport(
                timestamp,
                getSystemStatistics(),
                performHealthCheck(),
                AuthLogger.getEventStatistics(),
                AuthLogger.getSecurityAlerts(),
                getConfigurationSnapshot(),
                getSystemInfo()
        );

        try (FileWriter writer = new FileWriter(reportPath.toFile())) {
            gson.toJson(report, writer);
        }

        LarbacoAuthMain.LOGGER.info("Generated detailed monitoring report: {}", reportPath);
        return reportPath.toString();
    }

    public static void resetStatistics() {
        totalAuthTime.set(0);
        authOperationCount.set(0);
        sessionsCreated.set(0);
        sessionsExpired.set(0);
        totalLoginAttempts.set(0);
        failedLoginAttempts.set(0);
        databaseOperations.set(0);

        AuthLogger.logSystemEvent("STATS_RESET", "System statistics reset");
    }

    // Private helper methods

    private static void checkAuthenticationHealth(List<String> warnings, List<String> errors) {
        try {
            if (!LarbacoAuthMain.isInitialized()) {
                errors.add("Authentication system not properly initialized");
                updateComponentHealth("Authentication", false, "Not initialized");
                return;
            }

            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            if (avgAuthTime > 1000) {
                warnings.add(String.format("High authentication latency: %.2fms average", avgAuthTime));
            }

            if (totalLoginAttempts.get() > 10) {
                double failureRate = (double) failedLoginAttempts.get() / totalLoginAttempts.get();
                if (failureRate > 0.5) {
                    warnings.add(String.format("High login failure rate: %.1f%%", failureRate * 100));
                }
            }

            updateComponentHealth("Authentication", true, null);

        } catch (Exception e) {
            errors.add("Error checking authentication health: " + e.getMessage());
            updateComponentHealth("Authentication", false, e.getMessage());
        }
    }

    private static void checkDatabaseHealth(List<String> warnings, List<String> errors) {
        try {
            int playerCount = RegisterCommand.getRegisteredPlayerCount();

            long dbSize = DataManager.getDatabaseSize();
            if (dbSize > 100 * 1024 * 1024) { // 100MB
                warnings.add(String.format("Large database size: %.2f MB", dbSize / (1024.0 * 1024.0)));
            }

            updateComponentHealth("Database", true, null);

        } catch (Exception e) {
            errors.add("Database connectivity error: " + e.getMessage());
            updateComponentHealth("Database", false, e.getMessage());
        }
    }

    private static void checkSessionHealth(List<String> warnings, List<String> errors) {
        try {
            String sessionStats = AuthSessionManager.getSessionStats();

            if (sessionStats.contains("Active sessions:")) {
                String[] parts = sessionStats.split(", ");
                try {
                    int activeSessions = Integer.parseInt(parts[0].split(": ")[1]);
                    int pendingOps = Integer.parseInt(parts[1].split(": ")[1]);

                    if (activeSessions > 100) {
                        warnings.add(String.format("High number of active sessions: %d", activeSessions));
                    }

                    if (pendingOps > 50) {
                        warnings.add(String.format("High number of pending operations: %d", pendingOps));
                    }

                } catch (NumberFormatException e) {
                    warnings.add("Unable to parse session statistics");
                }
            }

            updateComponentHealth("SessionManager", true, null);

        } catch (Exception e) {
            errors.add("Session manager error: " + e.getMessage());
            updateComponentHealth("SessionManager", false, e.getMessage());
        }
    }

    private static void checkConfigurationHealth(List<String> warnings, List<String> errors) {
        try {
            if (Config.maxLoginAttempts < 1 || Config.maxLoginAttempts > 20) {
                warnings.add("Unusual max login attempts setting: " + Config.maxLoginAttempts);
            }

            if (Config.sessionDuration < 5 || Config.sessionDuration > 1440) {
                warnings.add("Unusual session duration setting: " + Config.sessionDuration + " minutes");
            }

            boolean configValid = Config.validate();
            if (!configValid) {
                errors.add("Configuration validation failed");
                updateComponentHealth("Configuration", false, "Validation failed");
                return;
            }

            updateComponentHealth("Configuration", true, null);

        } catch (Exception e) {
            errors.add("Configuration check error: " + e.getMessage());
            updateComponentHealth("Configuration", false, e.getMessage());
        }
    }

    private static void checkPerformanceHealth(List<String> warnings, List<String> errors) {
        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            long usedMemory = memoryBean.getHeapMemoryUsage().getUsed();
            long maxMemory = memoryBean.getHeapMemoryUsage().getMax();

            double memoryUsagePercent = (double) usedMemory / maxMemory * 100;

            if (memoryUsagePercent > 80) {
                warnings.add(String.format("High memory usage: %.1f%%", memoryUsagePercent));
            }

            RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
            long uptime = runtimeBean.getUptime();

            if (uptime < 60000) {
                warnings.add("System recently restarted");
            }

        } catch (Exception e) {
            warnings.add("Performance check error: " + e.getMessage());
        }
    }

    private static String determinePerformanceStatus() {
        try {
            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            long usedMemory = memoryBean.getHeapMemoryUsage().getUsed();
            long maxMemory = memoryBean.getHeapMemoryUsage().getMax();
            double memoryUsagePercent = (double) usedMemory / maxMemory * 100;

            if (avgAuthTime > 2000 || memoryUsagePercent > 90) {
                return "POOR";
            } else if (avgAuthTime > 500 || memoryUsagePercent > 70) {
                return "FAIR";
            } else {
                return "GOOD";
            }

        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private static void logPerformanceMetrics() {
        SystemStatistics stats = getSystemStatistics();

        if (stats.averageAuthTime() > 1000) {
            LarbacoAuthMain.LOGGER.warn("High authentication latency detected: {:.2f}ms", stats.averageAuthTime());
        }

        if (stats.memoryUsageMB() > 100) {
            LarbacoAuthMain.LOGGER.info("Memory usage: {:.1f}MB", stats.memoryUsageMB());
        }

        if (System.currentTimeMillis() % (10 * 60 * 1000) < 60000) {
            LarbacoAuthMain.LOGGER.info("Auth stats - Total attempts: {}, Success rate: {:.1f}%, Active sessions: {}",
                    stats.totalLoginAttempts(), stats.successRate(), stats.activeSessions());
        }
    }

    private static Map<String, Object> getConfigurationSnapshot() {
        Map<String, Object> config = new HashMap<>();
        config.put("maxLoginAttempts", Config.maxLoginAttempts);
        config.put("sessionDuration", Config.sessionDuration);
        config.put("requireMixedCase", Config.requireMixedCase);
        config.put("requireSpecialChar", Config.requireSpecialChar);
        return config;
    }

    private static Map<String, String> getSystemInfo() {
        Map<String, String> info = new HashMap<>();

        try {
            info.put("modVersion", LarbacoAuthMain.getVersion());
            info.put("minecraftVersion", LarbacoAuthMain.getMinecraftVersion());
            info.put("neoforgeVersion", LarbacoAuthMain.getNeoForgeVersion());
            info.put("javaVersion", System.getProperty("java.version"));
            info.put("osName", System.getProperty("os.name"));
            info.put("osVersion", System.getProperty("os.version"));
            info.put("language", LarbacoAuthMain.getCurrentLanguage());
            info.put("uptime", formatDuration(Duration.ofMillis(System.currentTimeMillis() - startupTime)));
        } catch (Exception e) {
            info.put("error", "Failed to gather system info: " + e.getMessage());
        }

        return info;
    }

    private static String formatDuration(Duration duration) {
        long days = duration.toDays();
        long hours = duration.toHours() % 24;
        long minutes = duration.toMinutes() % 60;

        if (days > 0) {
            return String.format("%dd %02dh %02dm", days, hours, minutes);
        } else if (hours > 0) {
            return String.format("%dh %02dm", hours, minutes);
        } else {
            return String.format("%dm", minutes);
        }
    }

    public record SystemStatistics(
            int registeredPlayers,
            int authenticatedPlayers,
            int totalLoginAttempts,
            int failedLoginAttempts,
            double successRate,
            int activeSessions,
            int pendingOperations,
            int sessionsCreated,
            int sessionsExpired,
            double averageAuthTime,
            long databaseOperations,
            double memoryUsageMB,
            String uptime
    ) {}

    public record HealthCheckResult(
            boolean isHealthy,
            Map<String, Boolean> componentStatus,
            List<String> warnings,
            List<String> errors,
            String performanceStatus
    ) {}

    public record MonitoringReport(
            String timestamp,
            SystemStatistics statistics,
            HealthCheckResult healthCheck,
            Map<String, Integer> eventStatistics,
            List<AuthLogger.SecurityAlert> securityAlerts,
            Map<String, Object> configuration,
            Map<String, String> systemInfo
    ) {}
}