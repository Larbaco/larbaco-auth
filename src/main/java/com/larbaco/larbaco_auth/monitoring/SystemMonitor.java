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

package com.larbaco.larbaco_auth.monitoring;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.commands.RegisterCommand;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.storage.DataManager;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Enhanced system monitor with improved performance, reliability, and integration.
 * Maintains full backward compatibility while adding advanced monitoring capabilities.
 */
public class SystemMonitor {
    // ==================== CONSTANTS ====================
    private static final String REPORTS_DIR = "config/larbaco_auth/reports";
    private static final String METRICS_DIR = "config/larbaco_auth/metrics";
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
    private static final DateTimeFormatter READABLE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Enhanced monitoring intervals
    private static final long HEALTH_CHECK_INTERVAL = 5; // minutes
    private static final long METRICS_COLLECTION_INTERVAL = 1; // minute
    private static final long CLEANUP_INTERVAL = 30; // minutes
    private static final int MAX_METRIC_HISTORY = 1440; // 24 hours of minute-by-minute data

    // ==================== SERIALIZATION ====================
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    // ==================== PERFORMANCE TRACKING (BACKWARD COMPATIBILITY) ====================
    private static final AtomicLong totalAuthTime = new AtomicLong(0);
    private static final AtomicInteger authOperationCount = new AtomicInteger(0);
    private static final AtomicInteger sessionsCreated = new AtomicInteger(0);
    private static final AtomicInteger sessionsExpired = new AtomicInteger(0);
    private static final AtomicInteger totalLoginAttempts = new AtomicInteger(0);
    private static final AtomicInteger failedLoginAttempts = new AtomicInteger(0);
    private static final AtomicLong databaseOperations = new AtomicLong(0);

    // ==================== ENHANCED METRICS ====================
    private static final AtomicLong passwordChanges = new AtomicLong(0);
    private static final AtomicLong adminActions = new AtomicLong(0);
    private static final AtomicLong systemEvents = new AtomicLong(0);
    private static final AtomicLong networkErrors = new AtomicLong(0);
    private static final AtomicLong configReloads = new AtomicLong(0);

    // Performance metrics history
    private static final Queue<MetricSnapshot> metricsHistory = new ConcurrentLinkedQueue<>();
    private static final Map<String, Queue<Long>> performanceHistory = new ConcurrentHashMap<>();

    // ==================== SYSTEM HEALTH TRACKING (BACKWARD COMPATIBILITY) ====================
    private static final Map<String, Boolean> componentHealth = new ConcurrentHashMap<>();
    private static final Map<String, String> lastErrors = new ConcurrentHashMap<>();
    private static final Map<String, Long> lastHealthCheck = new ConcurrentHashMap<>();

    // ==================== ENHANCED HEALTH TRACKING ====================
    private static final Map<String, AtomicLong> componentErrorCounts = new ConcurrentHashMap<>();
    private static final Map<String, Long> componentResponseTimes = new ConcurrentHashMap<>();
    private static final Map<String, String> componentVersions = new ConcurrentHashMap<>();

    // ==================== MONITORING STATE ====================
    private static final AtomicBoolean realTimeMonitoring = new AtomicBoolean(false);
    private static final AtomicBoolean shutdownInProgress = new AtomicBoolean(false);
    private static volatile ScheduledExecutorService monitoringService;
    private static volatile ScheduledExecutorService metricsService;

    private static final long startupTime = System.currentTimeMillis();
    private static final AtomicLong lastFullHealthCheck = new AtomicLong(0);
    private static final AtomicInteger healthCheckCount = new AtomicInteger(0);

    // ==================== INITIALIZATION ====================

    static {
        try {
            initializeComponents();
            createDirectoryStructure();
            initializeComponentVersions();
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to initialize SystemMonitor static components: {}", e.getMessage());
        }
    }

    private static void initializeComponents() {
        // Initialize component health tracking
        componentHealth.put("Authentication", true);
        componentHealth.put("Database", true);
        componentHealth.put("SessionManager", true);
        componentHealth.put("Configuration", true);
        componentHealth.put("Logging", true);
        componentHealth.put("NetworkIO", true);
        componentHealth.put("MemoryManagement", true);

        // Initialize error counters
        componentHealth.keySet().forEach(component ->
                componentErrorCounts.put(component, new AtomicLong(0)));

        // Initialize performance tracking
        performanceHistory.put("authTime", new ConcurrentLinkedQueue<>());
        performanceHistory.put("memoryUsage", new ConcurrentLinkedQueue<>());
        performanceHistory.put("sessionCount", new ConcurrentLinkedQueue<>());
        performanceHistory.put("dbOperations", new ConcurrentLinkedQueue<>());
    }

    private static void createDirectoryStructure() {
        try {
            Files.createDirectories(Paths.get(REPORTS_DIR));
            Files.createDirectories(Paths.get(METRICS_DIR));
        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Failed to create monitoring directories: {}", e.getMessage());
        }
    }

    private static void initializeComponentVersions() {
        try {
            componentVersions.put("LarbacoAuth", LarbacoAuthMain.getVersion());
            componentVersions.put("Minecraft", LarbacoAuthMain.getMinecraftVersion());
            componentVersions.put("NeoForge", LarbacoAuthMain.getNeoForgeVersion());
            componentVersions.put("Java", System.getProperty("java.version"));
            componentVersions.put("OS", System.getProperty("os.name") + " " + System.getProperty("os.version"));
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Could not initialize all component versions: {}", e.getMessage());
        }
    }

    // ==================== ORIGINAL METHODS (FULL BACKWARD COMPATIBILITY) ====================

    public static void recordAuthOperation(long durationMs) {
        totalAuthTime.addAndGet(durationMs);
        authOperationCount.incrementAndGet();

        // Enhanced: Record performance history
        recordPerformanceMetric("authTime", durationMs);

        // Enhanced: Update component response time
        componentResponseTimes.put("Authentication", durationMs);
    }

    public static void recordLoginAttempt(boolean success) {
        totalLoginAttempts.incrementAndGet();
        if (!success) {
            failedLoginAttempts.incrementAndGet();
            incrementComponentError("Authentication");
        }
    }

    public static void recordSessionCreated() {
        sessionsCreated.incrementAndGet();
        recordPerformanceMetric("sessionCount", getCurrentSessionCount());
    }

    public static void recordSessionExpired() {
        sessionsExpired.incrementAndGet();
    }

    public static void recordDatabaseOperation() {
        databaseOperations.incrementAndGet();
        recordPerformanceMetric("dbOperations", databaseOperations.get());
    }

    public static void updateComponentHealth(String component, boolean healthy, String error) {
        if (shutdownInProgress.get()) {
            return;
        }

        try {
            componentHealth.put(component, healthy);
            lastHealthCheck.put(component, System.currentTimeMillis());

            if (!healthy && error != null) {
                lastErrors.put(component, error);
                incrementComponentError(component);
                LarbacoAuthMain.LOGGER.warn("Component {} marked as unhealthy: {}", component, error);

                // Only log to AuthLogger for non-authentication components to avoid duplication
                if (!"Authentication".equals(component) && !"Logging".equals(component)) {
                    AuthLogger.logSystemEvent("COMPONENT_UNHEALTHY",
                            String.format("Component %s failed: %s", component, error));
                }
            } else if (healthy) {
                lastErrors.remove(component);
                LarbacoAuthMain.LOGGER.debug("Component {} restored to healthy state", component);
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error updating component health for {}: {}", component, e.getMessage());
        }
    }

    public static SystemStatistics getSystemStatistics() {
        try {
            long startTime = System.nanoTime();

            int registeredPlayers = getRegisteredPlayerCountSafe();
            int authenticatedPlayers = LarbacoAuthMain.getAuthenticatedPlayerCount();

            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            double successRate = totalLoginAttempts.get() > 0 ?
                    ((double) (totalLoginAttempts.get() - failedLoginAttempts.get()) / totalLoginAttempts.get()) * 100 : 100.0;

            SessionInfo sessionInfo = getSessionInfoSafe();
            MemoryInfo memoryInfo = getMemoryInfoSafe();

            long uptimeMs = System.currentTimeMillis() - startupTime;
            String uptime = formatDuration(Duration.ofMillis(uptimeMs));

            // Record performance for this operation
            long duration = (System.nanoTime() - startTime) / 1_000_000;
            componentResponseTimes.put("SystemStatistics", duration);

            return new SystemStatistics(
                    registeredPlayers,
                    authenticatedPlayers,
                    totalLoginAttempts.get(),
                    failedLoginAttempts.get(),
                    successRate,
                    sessionInfo.activeSessions(),
                    sessionInfo.pendingOperations(),
                    sessionsCreated.get(),
                    sessionsExpired.get(),
                    avgAuthTime,
                    databaseOperations.get(),
                    memoryInfo.usageMB(),
                    uptime
            );

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error gathering system statistics: {}", e.getMessage(), e);
            updateComponentHealth("SystemStatistics", false, e.getMessage());
            return createFallbackStatistics();
        }
    }

    public static HealthCheckResult performHealthCheck() {
        if (shutdownInProgress.get()) {
            return new HealthCheckResult(false, Collections.emptyMap(),
                    List.of("System shutdown in progress"), Collections.emptyList(), "SHUTDOWN");
        }

        long startTime = System.nanoTime();
        healthCheckCount.incrementAndGet();

        List<String> warnings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        Map<String, Boolean> currentHealth = new HashMap<>(componentHealth);

        try {
            checkAuthenticationHealthEnhanced(warnings, errors);
            checkDatabaseHealthEnhanced(warnings, errors);
            checkSessionHealthEnhanced(warnings, errors);
            checkConfigurationHealthEnhanced(warnings, errors);
            checkPerformanceHealthEnhanced(warnings, errors);
            checkMemoryHealthEnhanced(warnings, errors);
            checkNetworkHealthEnhanced(warnings, errors);

        } catch (Exception e) {
            errors.add("Health check system failure: " + e.getMessage());
            LarbacoAuthMain.LOGGER.error("Critical health check error: {}", e.getMessage(), e);
            updateComponentHealth("HealthCheck", false, e.getMessage());
        }

        boolean isHealthy = errors.isEmpty() &&
                componentHealth.values().stream().allMatch(Boolean::booleanValue);

        String performanceStatus = determinePerformanceStatusEnhanced();

        // Record health check performance
        long duration = (System.nanoTime() - startTime) / 1_000_000;
        componentResponseTimes.put("HealthCheck", duration);
        lastFullHealthCheck.set(System.currentTimeMillis());

        return new HealthCheckResult(
                isHealthy,
                currentHealth,
                warnings,
                errors,
                performanceStatus
        );
    }

    public static boolean startRealTimeMonitoring() {
        if (realTimeMonitoring.getAndSet(true)) {
            LarbacoAuthMain.LOGGER.info("Real-time monitoring already running");
            return false;
        }

        try {
            initializeMonitoringServices();
            scheduleMonitoringTasks();
            scheduleMetricsCollection();

            AuthLogger.logSystemEvent("MONITORING_START", "Enhanced real-time monitoring enabled");
            LarbacoAuthMain.LOGGER.info("Enhanced real-time monitoring started successfully");
            return true;

        } catch (Exception e) {
            realTimeMonitoring.set(false);
            LarbacoAuthMain.LOGGER.error("Failed to start enhanced real-time monitoring: {}", e.getMessage(), e);
            updateComponentHealth("Monitoring", false, "Failed to start: " + e.getMessage());
            return false;
        }
    }

    public static boolean stopRealTimeMonitoring() {
        if (!realTimeMonitoring.getAndSet(false)) {
            LarbacoAuthMain.LOGGER.info("Real-time monitoring was not running");
            return false;
        }

        try {
            shutdownMonitoringServices();
            AuthLogger.logSystemEvent("MONITORING_STOP", "Enhanced real-time monitoring disabled");
            LarbacoAuthMain.LOGGER.info("Enhanced real-time monitoring stopped successfully");
            return true;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error stopping enhanced real-time monitoring: {}", e.getMessage(), e);
            return false;
        }
    }

    public static String generateDetailedReport() throws IOException {
        if (shutdownInProgress.get()) {
            throw new IllegalStateException("Cannot generate report during shutdown");
        }

        long startTime = System.nanoTime();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String reportFileName = String.format("system_report_%s.json", timestamp);
        Path reportPath = Paths.get(REPORTS_DIR, reportFileName);

        try {
            EnhancedMonitoringReport report = new EnhancedMonitoringReport(
                    timestamp,
                    getSystemStatistics(),
                    performHealthCheck(),
                    AuthLogger.getEventStatistics(),
                    AuthLogger.getSecurityAlerts(),
                    getConfigurationSnapshot(),
                    getEnhancedSystemInfo(),
                    getPerformanceMetrics(),
                    getComponentHealthDetails(),
                    getMetricsHistorySummary()
            );

            try (BufferedWriter writer = Files.newBufferedWriter(reportPath, StandardCharsets.UTF_8)) {
                gson.toJson(report, writer);
            }

            long duration = (System.nanoTime() - startTime) / 1_000_000;
            LarbacoAuthMain.LOGGER.info("Enhanced monitoring report generated in {}ms: {}", duration, reportPath);

            // Record performance
            componentResponseTimes.put("ReportGeneration", duration);

            return reportPath.toString();

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error generating enhanced monitoring report: {}", e.getMessage(), e);
            updateComponentHealth("ReportGeneration", false, e.getMessage());
            throw new IOException("Failed to generate enhanced report", e);
        }
    }

    public static void resetStatistics() {
        if (shutdownInProgress.get()) {
            return;
        }

        try {
            // Reset original counters
            totalAuthTime.set(0);
            authOperationCount.set(0);
            sessionsCreated.set(0);
            sessionsExpired.set(0);
            totalLoginAttempts.set(0);
            failedLoginAttempts.set(0);
            databaseOperations.set(0);

            // Reset enhanced counters
            passwordChanges.set(0);
            adminActions.set(0);
            systemEvents.set(0);
            networkErrors.set(0);
            configReloads.set(0);

            // Reset error counters
            componentErrorCounts.values().forEach(counter -> counter.set(0));

            // Clear performance history
            performanceHistory.values().forEach(Queue::clear);
            metricsHistory.clear();

            // Reset health check counter
            healthCheckCount.set(0);

            AuthLogger.logSystemEvent("STATS_RESET", "Enhanced system statistics reset");
            LarbacoAuthMain.LOGGER.info("Enhanced system statistics reset completed");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error resetting enhanced statistics: {}", e.getMessage());
        }
    }

    public static void shutdown() {
        if (shutdownInProgress.getAndSet(true)) {
            return;
        }

        try {
            LarbacoAuthMain.LOGGER.info("Enhanced SystemMonitor shutdown initiated...");

            // Stop monitoring services
            stopRealTimeMonitoring();

            // Generate final report if monitoring was active
            try {
                if (realTimeMonitoring.get()) {
                    String finalReport = generateDetailedReport();
                    LarbacoAuthMain.LOGGER.info("Final monitoring report saved: {}", finalReport);
                }
            } catch (Exception e) {
                LarbacoAuthMain.LOGGER.warn("Could not generate final monitoring report: {}", e.getMessage());
            }

            // Cleanup data structures
            clearDataStructures();

            LarbacoAuthMain.LOGGER.info("Enhanced SystemMonitor shutdown completed successfully");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during enhanced SystemMonitor shutdown: {}", e.getMessage(), e);
        }
    }

    // ==================== ENHANCED HELPER METHODS ====================

    private static void recordPerformanceMetric(String metricName, long value) {
        Queue<Long> history = performanceHistory.get(metricName);
        if (history != null) {
            history.offer(value);

            // Keep only recent history
            while (history.size() > MAX_METRIC_HISTORY) {
                history.poll();
            }
        }
    }

    private static void incrementComponentError(String component) {
        AtomicLong errorCount = componentErrorCounts.get(component);
        if (errorCount != null) {
            errorCount.incrementAndGet();
        }
    }

    private static int getRegisteredPlayerCountSafe() {
        try {
            return RegisterCommand.getRegisteredPlayerCount();
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error getting registered player count: {}", e.getMessage());
            updateComponentHealth("Database", false, "Cannot access player count");
            return 0;
        }
    }

    private static SessionInfo getSessionInfoSafe() {
        try {
            String sessionStats = AuthSessionManager.getSessionStats();
            return parseSessionStats(sessionStats);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error getting session info: {}", e.getMessage());
            updateComponentHealth("SessionManager", false, "Cannot access session stats");
            return new SessionInfo(0, 0);
        }
    }

    private static SessionInfo parseSessionStats(String sessionStats) {
        try {
            if (sessionStats.contains("Active sessions:")) {
                String[] parts = sessionStats.split(", ");
                int activeSessions = Integer.parseInt(parts[0].split(": ")[1]);
                int pendingOps = parts.length > 1 ?
                        Integer.parseInt(parts[1].split(": ")[1]) : 0;
                return new SessionInfo(activeSessions, pendingOps);
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error parsing session stats: {}", e.getMessage());
        }
        return new SessionInfo(0, 0);
    }

    private static MemoryInfo getMemoryInfoSafe() {
        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            long usedMemory = memoryBean.getHeapMemoryUsage().getUsed();
            long maxMemory = memoryBean.getHeapMemoryUsage().getMax();
            double usageMB = usedMemory / (1024.0 * 1024.0);
            double usagePercent = maxMemory > 0 ? (double) usedMemory / maxMemory * 100 : 0;

            recordPerformanceMetric("memoryUsage", (long) usageMB);

            return new MemoryInfo(usageMB, usagePercent, usedMemory, maxMemory);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error getting memory info: {}", e.getMessage());
            updateComponentHealth("MemoryManagement", false, "Cannot access memory stats");
            return new MemoryInfo(0, 0, 0, 0);
        }
    }

    private static int getCurrentSessionCount() {
        try {
            return LarbacoAuthMain.getAuthenticatedPlayerCount();
        } catch (Exception e) {
            return 0;
        }
    }

    private static SystemStatistics createFallbackStatistics() {
        return new SystemStatistics(0, 0, 0, 0, 0.0, 0, 0, 0, 0, 0.0, 0, 0.0, "Unknown");
    }

    // ==================== ENHANCED HEALTH CHECK METHODS ====================

    private static void checkAuthenticationHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            if (!LarbacoAuthMain.isInitialized()) {
                errors.add("Authentication system not properly initialized");
                updateComponentHealth("Authentication", false, "Not initialized");
                return;
            }

            // Check authentication performance
            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            if (avgAuthTime > 2000) {
                errors.add(String.format("Critical authentication latency: %.2fms average", avgAuthTime));
                updateComponentHealth("Authentication", false, "High latency");
            } else if (avgAuthTime > 1000) {
                warnings.add(String.format("High authentication latency: %.2fms average", avgAuthTime));
            }

            // Check failure rate
            if (totalLoginAttempts.get() > 10) {
                double failureRate = (double) failedLoginAttempts.get() / totalLoginAttempts.get();
                if (failureRate > 0.7) {
                    errors.add(String.format("Critical login failure rate: %.1f%%", failureRate * 100));
                } else if (failureRate > 0.5) {
                    warnings.add(String.format("High login failure rate: %.1f%%", failureRate * 100));
                }
            }

            // Check error count
            AtomicLong errorCount = componentErrorCounts.get("Authentication");
            if (errorCount != null && errorCount.get() > 50) {
                warnings.add(String.format("High authentication error count: %d", errorCount.get()));
            }

            updateComponentHealth("Authentication", true, null);

        } catch (Exception e) {
            errors.add("Error checking authentication health: " + e.getMessage());
            updateComponentHealth("Authentication", false, e.getMessage());
        }
    }

    private static void checkDatabaseHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            // Test database connectivity
            int playerCount = getRegisteredPlayerCountSafe();
            long dbSize = DataManager.getDatabaseSize();

            // Check database size
            if (dbSize > 500 * 1024 * 1024) { // 500MB
                errors.add(String.format("Critical database size: %.2f MB", dbSize / (1024.0 * 1024.0)));
            } else if (dbSize > 100 * 1024 * 1024) { // 100MB
                warnings.add(String.format("Large database size: %.2f MB", dbSize / (1024.0 * 1024.0)));
            }

            // Check operation count
            if (databaseOperations.get() > 10000) {
                warnings.add(String.format("High database operation count: %d", databaseOperations.get()));
            }

            updateComponentHealth("Database", true, null);

        } catch (Exception e) {
            errors.add("Database connectivity error: " + e.getMessage());
            updateComponentHealth("Database", false, e.getMessage());
        }
    }

    private static void checkSessionHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            if (!AuthSessionManager.isHealthy()) {
                errors.add("Session manager is unhealthy");
                updateComponentHealth("SessionManager", false, "Session manager unhealthy");
                return;
            }

            SessionInfo sessionInfo = getSessionInfoSafe();

            if (sessionInfo.activeSessions() > 200) {
                errors.add(String.format("Critical number of active sessions: %d", sessionInfo.activeSessions()));
            } else if (sessionInfo.activeSessions() > 100) {
                warnings.add(String.format("High number of active sessions: %d", sessionInfo.activeSessions()));
            }

            if (sessionInfo.pendingOperations() > 100) {
                errors.add(String.format("Critical number of pending operations: %d", sessionInfo.pendingOperations()));
            } else if (sessionInfo.pendingOperations() > 50) {
                warnings.add(String.format("High number of pending operations: %d", sessionInfo.pendingOperations()));
            }

            updateComponentHealth("SessionManager", true, null);

        } catch (Exception e) {
            errors.add("Session manager error: " + e.getMessage());
            updateComponentHealth("SessionManager", false, e.getMessage());
        }
    }

    private static void checkConfigurationHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            boolean configValid = Config.validate();
            if (!configValid) {
                errors.add("Configuration validation failed");
                updateComponentHealth("Configuration", false, "Validation failed");
                return;
            }

            // Check for unusual settings
            if (Config.maxLoginAttempts < 1 || Config.maxLoginAttempts > 20) {
                warnings.add("Unusual max login attempts setting: " + Config.maxLoginAttempts);
            }

            if (Config.sessionDuration < 5 || Config.sessionDuration > 1440) {
                warnings.add("Unusual session duration setting: " + Config.sessionDuration + " minutes");
            }

            if (Config.passwordMinLength < 4) {
                warnings.add("Very low minimum password length: " + Config.passwordMinLength);
            }

            updateComponentHealth("Configuration", true, null);

        } catch (Exception e) {
            errors.add("Configuration check error: " + e.getMessage());
            updateComponentHealth("Configuration", false, e.getMessage());
        }
    }

    private static void checkPerformanceHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            MemoryInfo memoryInfo = getMemoryInfoSafe();

            if (memoryInfo.usagePercent() > 95) {
                errors.add(String.format("Critical memory usage: %.1f%%", memoryInfo.usagePercent()));
            } else if (memoryInfo.usagePercent() > 80) {
                warnings.add(String.format("High memory usage: %.1f%%", memoryInfo.usagePercent()));
            }

            // Check uptime
            RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
            long uptime = runtimeBean.getUptime();

            if (uptime < 60000) {
                warnings.add("System recently restarted");
            }

            // Check thread count
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            int threadCount = threadBean.getThreadCount();

            if (threadCount > 100) {
                warnings.add(String.format("High thread count: %d", threadCount));
            }

        } catch (Exception e) {
            warnings.add("Performance check error: " + e.getMessage());
        }
    }

    private static void checkMemoryHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            // Check garbage collection
            List<GarbageCollectorMXBean> gcBeans = ManagementFactory.getGarbageCollectorMXBeans();
            for (GarbageCollectorMXBean gcBean : gcBeans) {
                long collectionCount = gcBean.getCollectionCount();
                long collectionTime = gcBean.getCollectionTime();

                if (collectionCount > 1000) {
                    warnings.add(String.format("High GC count for %s: %d collections",
                            gcBean.getName(), collectionCount));
                }

                if (collectionTime > 10000) { // 10 seconds
                    warnings.add(String.format("High GC time for %s: %d ms",
                            gcBean.getName(), collectionTime));
                }
            }

            // Check memory pools
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            if (memoryBean.getHeapMemoryUsage().getUsed() > memoryBean.getHeapMemoryUsage().getMax() * 0.9) {
                errors.add("Heap memory critically low");
            }

            updateComponentHealth("MemoryManagement", true, null);

        } catch (Exception e) {
            warnings.add("Memory health check error: " + e.getMessage());
            updateComponentHealth("MemoryManagement", false, e.getMessage());
        }
    }

    private static void checkNetworkHealthEnhanced(List<String> warnings, List<String> errors) {
        try {
            // Check network error count
            if (networkErrors.get() > 100) {
                errors.add(String.format("High network error count: %d", networkErrors.get()));
            } else if (networkErrors.get() > 50) {
                warnings.add(String.format("Elevated network error count: %d", networkErrors.get()));
            }

            // Check connected players vs capacity
            int authenticatedPlayers = LarbacoAuthMain.getAuthenticatedPlayerCount();
            if (authenticatedPlayers > Config.maxConcurrentSessions * 0.9) {
                warnings.add(String.format("Near session capacity: %d/%d",
                        authenticatedPlayers, Config.maxConcurrentSessions));
            }

            updateComponentHealth("NetworkIO", true, null);

        } catch (Exception e) {
            warnings.add("Network health check error: " + e.getMessage());
            updateComponentHealth("NetworkIO", false, e.getMessage());
        }
    }

    private static String determinePerformanceStatusEnhanced() {
        try {
            double avgAuthTime = authOperationCount.get() > 0 ?
                    (double) totalAuthTime.get() / authOperationCount.get() : 0.0;

            MemoryInfo memoryInfo = getMemoryInfoSafe();

            // Check recent performance trends
            boolean performanceDegrading = isPerformanceDegrading();

            if (avgAuthTime > 3000 || memoryInfo.usagePercent() > 95 || performanceDegrading) {
                return "CRITICAL";
            } else if (avgAuthTime > 2000 || memoryInfo.usagePercent() > 90) {
                return "POOR";
            } else if (avgAuthTime > 500 || memoryInfo.usagePercent() > 70) {
                return "FAIR";
            } else {
                return "EXCELLENT";
            }

        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private static boolean isPerformanceDegrading() {
        try {
            Queue<Long> authTimeHistory = performanceHistory.get("authTime");
            if (authTimeHistory == null || authTimeHistory.size() < 10) {
                return false;
            }

            List<Long> recentTimes = authTimeHistory.stream()
                    .skip(Math.max(0, authTimeHistory.size() - 10))
                    .collect(Collectors.toList());

            if (recentTimes.size() < 10) {
                return false;
            }

            // Check if recent times are consistently higher than earlier times
            double firstHalf = recentTimes.subList(0, 5).stream().mapToLong(Long::longValue).average().orElse(0);
            double secondHalf = recentTimes.subList(5, 10).stream().mapToLong(Long::longValue).average().orElse(0);

            return secondHalf > firstHalf * 1.5; // 50% increase is concerning

        } catch (Exception e) {
            return false;
        }
    }

    // ==================== ENHANCED MONITORING SERVICES ====================

    private static void initializeMonitoringServices() {
        monitoringService = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "LarbacoAuth-Monitor");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, ex) -> {
                LarbacoAuthMain.LOGGER.error("Uncaught exception in monitoring thread: {}", ex.getMessage(), ex);
                updateComponentHealth("Monitoring", false, "Thread exception: " + ex.getMessage());
            });
            return t;
        });

        metricsService = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "LarbacoAuth-Metrics");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, ex) -> {
                LarbacoAuthMain.LOGGER.error("Uncaught exception in metrics thread: {}", ex.getMessage(), ex);
            });
            return t;
        });
    }

    private static void scheduleMonitoringTasks() {
        // Health check task
        monitoringService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    HealthCheckResult health = performHealthCheck();
                    if (!health.isHealthy()) {
                        LarbacoAuthMain.LOGGER.warn("Health check failed: {} errors, {} warnings",
                                health.errors().size(), health.warnings().size());

                        // Log critical errors to AuthLogger only if not already logged
                        for (String error : health.errors()) {
                            if (error.contains("Authentication") || error.contains("Database") ||
                                    error.contains("Session") || error.contains("Configuration")) {
                                // These are already logged by their respective components
                                continue;
                            }
                            AuthLogger.logSystemEvent("HEALTH_CHECK_ERROR", error);
                        }
                    }
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during scheduled health check: {}", e.getMessage());
                    updateComponentHealth("HealthCheck", false, e.getMessage());
                }
            }
        }, 0, HEALTH_CHECK_INTERVAL, TimeUnit.MINUTES);

        // Performance monitoring task
        monitoringService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    logPerformanceMetricsEnhanced();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during performance monitoring: {}", e.getMessage());
                }
            }
        }, 1, METRICS_COLLECTION_INTERVAL, TimeUnit.MINUTES);

        // Cleanup task
        monitoringService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    performCleanupTasks();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during cleanup tasks: {}", e.getMessage());
                }
            }
        }, CLEANUP_INTERVAL, CLEANUP_INTERVAL, TimeUnit.MINUTES);
    }

    private static void scheduleMetricsCollection() {
        // Only schedule metrics collection if monitoring is enabled
        if (!Config.enableMonitoring) {
            LarbacoAuthMain.LOGGER.debug("Detailed metrics collection disabled by configuration");
            return;
        }

        metricsService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get() && Config.enableMonitoring) { // Double-check in case config changes
                try {
                    collectMetricsSnapshot();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error collecting metrics snapshot: {}", e.getMessage());
                }
            }
        }, 0, 1, TimeUnit.MINUTES);
    }

    private static void logPerformanceMetricsEnhanced() {
        try {
            SystemStatistics stats = getSystemStatistics();
            MemoryInfo memoryInfo = getMemoryInfoSafe();

            // Log performance warnings (but avoid duplicating auth performance logs)
            if (stats.averageAuthTime() > 2000) { // Higher threshold to avoid duplication
                LarbacoAuthMain.LOGGER.warn("Critical authentication latency detected: {:.2f}ms", stats.averageAuthTime());
            }

            if (memoryInfo.usagePercent() > 85) { // Higher threshold
                LarbacoAuthMain.LOGGER.warn("Critical memory usage: {:.1f}% ({:.1f}MB)",
                        memoryInfo.usagePercent(), memoryInfo.usageMB());
            }

            // Periodic info logging (every 10 minutes) - reduced frequency
            if (System.currentTimeMillis() % (10 * 60 * 1000) < 60000) {
                LarbacoAuthMain.LOGGER.info("System health summary - Auth: {:.1f}ms avg, Memory: {:.1f}MB, Sessions: {}, Uptime: {}",
                        stats.averageAuthTime(), memoryInfo.usageMB(), stats.activeSessions(), stats.uptime());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging enhanced performance metrics: {}", e.getMessage());
        }
    }

    private static void collectMetricsSnapshot() {
        // Only collect detailed metrics if monitoring is enabled
        if (!Config.enableMonitoring) {
            return;
        }

        try {
            MemoryInfo memoryInfo = getMemoryInfoSafe();
            SessionInfo sessionInfo = getSessionInfoSafe();
            double cpuUsage = getCurrentCpuUsage();

            MetricSnapshot snapshot = new MetricSnapshot(
                    System.currentTimeMillis(),
                    memoryInfo.usageMB(),
                    memoryInfo.usagePercent(),
                    sessionInfo.activeSessions(),
                    authOperationCount.get(),
                    totalLoginAttempts.get(),
                    failedLoginAttempts.get(),
                    databaseOperations.get(),
                    cpuUsage >= 0 ? cpuUsage : 0.0 // Use 0 if CPU monitoring failed
            );

            metricsHistory.offer(snapshot);

            // Keep only recent history
            while (metricsHistory.size() > MAX_METRIC_HISTORY) {
                metricsHistory.poll();
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error collecting metrics snapshot: {}", e.getMessage());
        }
    }

    private static double getCurrentCpuUsage() {
        // Make CPU monitoring optional and safe
        if (!Config.enableMonitoring) {
            return 0.0; // Skip CPU monitoring if detailed monitoring is disabled
        }

        try {
            // Try different approaches for CPU monitoring
            java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

            // Method 1: Try the standard method if available
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOsBean) {
                double cpuLoad = sunOsBean.getProcessCpuLoad();
                if (cpuLoad >= 0 && cpuLoad <= 1) {
                    return cpuLoad * 100;
                }
            }

            // Method 2: Try reflection for cross-platform compatibility
            try {
                java.lang.reflect.Method method = osBean.getClass().getMethod("getProcessCpuLoad");
                method.setAccessible(true);
                Object result = method.invoke(osBean);
                if (result instanceof Double cpuLoad) {
                    if (cpuLoad >= 0 && cpuLoad <= 1) {
                        return cpuLoad * 100;
                    }
                }
            } catch (Exception e) {
                // Reflection failed, continue to fallback
            }

            // Method 3: Fallback - return -1 to indicate unavailable
            return -1.0;

        } catch (Exception e) {
            // Log error only once every 5 minutes to avoid spam
            if (System.currentTimeMillis() % (5 * 60 * 1000) < 1000) {
                LarbacoAuthMain.LOGGER.debug("CPU monitoring unavailable: {}", e.getMessage());
            }
            return -1.0;
        }
    }

    private static void performCleanupTasks() {
        try {
            // Only perform detailed cleanup if monitoring is enabled
            if (Config.enableMonitoring) {
                // Clean old metrics
                long cutoffTime = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(24);

                performanceHistory.values().forEach(history -> {
                    // This is simplified - in real implementation you'd need timestamps
                    if (history.size() > MAX_METRIC_HISTORY) {
                        int toRemove = history.size() - MAX_METRIC_HISTORY;
                        for (int i = 0; i < toRemove; i++) {
                            history.poll();
                        }
                    }
                });
            }

            // Always perform basic memory management
            MemoryInfo memoryInfo = getMemoryInfoSafe();
            if (memoryInfo.usagePercent() > 85) {
                System.gc();
                LarbacoAuthMain.LOGGER.debug("Suggested garbage collection due to high memory usage: {:.1f}%",
                        memoryInfo.usagePercent());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error during cleanup tasks: {}", e.getMessage());
        }
    }

    private static void shutdownMonitoringServices() {
        // Shutdown monitoring service
        if (monitoringService != null && !monitoringService.isShutdown()) {
            monitoringService.shutdown();
            try {
                if (!monitoringService.awaitTermination(10, TimeUnit.SECONDS)) {
                    LarbacoAuthMain.LOGGER.warn("Monitoring service did not terminate gracefully, forcing shutdown");
                    monitoringService.shutdownNow();
                    if (!monitoringService.awaitTermination(5, TimeUnit.SECONDS)) {
                        LarbacoAuthMain.LOGGER.error("Monitoring service did not terminate after forced shutdown");
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                monitoringService.shutdownNow();
            }
        }

        // Shutdown metrics service
        if (metricsService != null && !metricsService.isShutdown()) {
            metricsService.shutdown();
            try {
                if (!metricsService.awaitTermination(5, TimeUnit.SECONDS)) {
                    LarbacoAuthMain.LOGGER.warn("Metrics service did not terminate gracefully, forcing shutdown");
                    metricsService.shutdownNow();
                    if (!metricsService.awaitTermination(2, TimeUnit.SECONDS)) {
                        LarbacoAuthMain.LOGGER.error("Metrics service did not terminate after forced shutdown");
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                metricsService.shutdownNow();
            }
        }
    }

    private static void clearDataStructures() {
        try {
            componentHealth.clear();
            lastErrors.clear();
            lastHealthCheck.clear();
            componentErrorCounts.clear();
            componentResponseTimes.clear();
            componentVersions.clear();
            performanceHistory.values().forEach(Queue::clear);
            performanceHistory.clear();
            metricsHistory.clear();

            LarbacoAuthMain.LOGGER.debug("All monitoring data structures cleared");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error clearing monitoring data structures: {}", e.getMessage());
        }
    }

    // ==================== ENHANCED REPORTING METHODS ====================

    private static Map<String, Object> getConfigurationSnapshot() {
        Map<String, Object> config = new HashMap<>();
        try {
            config.put("maxLoginAttempts", Config.maxLoginAttempts);
            config.put("sessionDuration", Config.sessionDuration);
            config.put("requireMixedCase", Config.requireMixedCase);
            config.put("requireSpecialChar", Config.requireSpecialChar);
            config.put("lockoutDuration", Config.lockoutDuration);
            config.put("passwordMinLength", Config.passwordMinLength);
            config.put("requireNumbers", Config.requireNumbers);
            config.put("maxConcurrentSessions", Config.maxConcurrentSessions);
            config.put("enableDetailedLogging", Config.enableDetailedLogging);
            config.put("enableMonitoring", Config.enableMonitoring);
        } catch (Exception e) {
            config.put("error", "Failed to get configuration: " + e.getMessage());
        }
        return config;
    }

    private static Map<String, String> getEnhancedSystemInfo() {
        Map<String, String> info = new HashMap<>(componentVersions);

        try {
            Runtime runtime = Runtime.getRuntime();
            info.put("availableProcessors", String.valueOf(runtime.availableProcessors()));
            info.put("maxMemory", String.format("%.1f MB", runtime.maxMemory() / (1024.0 * 1024.0)));
            info.put("totalMemory", String.format("%.1f MB", runtime.totalMemory() / (1024.0 * 1024.0)));
            info.put("freeMemory", String.format("%.1f MB", runtime.freeMemory() / (1024.0 * 1024.0)));

            info.put("language", LarbacoAuthMain.getCurrentLanguage());
            info.put("uptime", formatDuration(Duration.ofMillis(System.currentTimeMillis() - startupTime)));
            info.put("healthCheckCount", String.valueOf(healthCheckCount.get()));
            info.put("lastHealthCheck", lastFullHealthCheck.get() > 0 ?
                    LocalDateTime.ofEpochSecond(lastFullHealthCheck.get() / 1000, 0, java.time.ZoneOffset.UTC)
                            .format(READABLE_FORMAT) : "Never");

        } catch (Exception e) {
            info.put("enhancedInfoError", "Failed to gather enhanced info: " + e.getMessage());
        }

        return info;
    }

    private static Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        try {
            // Response times
            Map<String, Object> responseTimes = new HashMap<>();
            componentResponseTimes.forEach((component, time) ->
                    responseTimes.put(component, time + "ms"));
            metrics.put("responseTimes", responseTimes);

            // Error counts
            Map<String, Object> errorCounts = new HashMap<>();
            componentErrorCounts.forEach((component, count) ->
                    errorCounts.put(component, count.get()));
            metrics.put("errorCounts", errorCounts);

            // Performance trends
            Map<String, Object> trends = new HashMap<>();
            performanceHistory.forEach((metric, history) -> {
                if (!history.isEmpty()) {
                    List<Long> recent = history.stream().collect(Collectors.toList());
                    double average = recent.stream().mapToLong(Long::longValue).average().orElse(0);
                    trends.put(metric + "_average", String.format("%.2f", average));
                    trends.put(metric + "_count", recent.size());
                }
            });
            metrics.put("trends", trends);

        } catch (Exception e) {
            metrics.put("error", "Failed to gather performance metrics: " + e.getMessage());
        }

        return metrics;
    }

    private static Map<String, Object> getComponentHealthDetails() {
        Map<String, Object> healthDetails = new HashMap<>();

        try {
            componentHealth.forEach((component, healthy) -> {
                Map<String, Object> details = new HashMap<>();
                details.put("healthy", healthy);
                details.put("lastCheck", lastHealthCheck.getOrDefault(component, 0L));
                details.put("errorCount", componentErrorCounts.getOrDefault(component, new AtomicLong(0)).get());
                details.put("lastError", lastErrors.get(component));
                details.put("responseTime", componentResponseTimes.get(component));
                healthDetails.put(component, details);
            });

        } catch (Exception e) {
            healthDetails.put("error", "Failed to gather component health details: " + e.getMessage());
        }

        return healthDetails;
    }

    private static Map<String, Object> getMetricsHistorySummary() {
        Map<String, Object> summary = new HashMap<>();

        try {
            if (!Config.enableMonitoring) {
                summary.put("message", "Detailed metrics collection disabled");
                return summary;
            }

            if (!metricsHistory.isEmpty()) {
                summary.put("totalSnapshots", metricsHistory.size());
                summary.put("oldestSnapshot", metricsHistory.peek().timestamp());
                summary.put("newestSnapshot", ((LinkedList<MetricSnapshot>) metricsHistory).peekLast().timestamp());

                // Calculate averages
                double avgMemory = metricsHistory.stream()
                        .mapToDouble(MetricSnapshot::memoryUsageMB)
                        .average().orElse(0);
                double avgSessions = metricsHistory.stream()
                        .mapToDouble(MetricSnapshot::activeSessions)
                        .average().orElse(0);

                summary.put("averageMemoryUsage", String.format("%.1f MB", avgMemory));
                summary.put("averageActiveSessions", String.format("%.1f", avgSessions));

                // Add CPU average only if available
                double avgCpu = metricsHistory.stream()
                        .mapToDouble(MetricSnapshot::cpuUsage)
                        .filter(cpu -> cpu >= 0) // Filter out unavailable readings
                        .average().orElse(-1);

                if (avgCpu >= 0) {
                    summary.put("averageCpuUsage", String.format("%.1f%%", avgCpu));
                } else {
                    summary.put("cpuUsage", "Unavailable");
                }
            } else {
                summary.put("message", "No metrics history available");
            }

        } catch (Exception e) {
            summary.put("error", "Failed to generate metrics history summary: " + e.getMessage());
        }

        return summary;
    }

    private static String formatDuration(Duration duration) {
        try {
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
        } catch (Exception e) {
            return "Unknown";
        }
    }

    // ==================== ENHANCED METHODS FOR EXTERNAL USE ====================

    /**
     * Record a password change operation
     */
    public static void recordPasswordChange() {
        passwordChanges.incrementAndGet();
    }

    /**
     * Record an admin action
     */
    public static void recordAdminAction() {
        adminActions.incrementAndGet();
    }

    /**
     * Record a system event
     */
    public static void recordSystemEvent() {
        systemEvents.incrementAndGet();
    }

    /**
     * Record a network error
     */
    public static void recordNetworkError() {
        networkErrors.incrementAndGet();
        incrementComponentError("NetworkIO");
    }

    /**
     * Record a configuration reload
     */
    public static void recordConfigReload() {
        configReloads.incrementAndGet();
    }

    /**
     * Get current system health status
     */
    public static String getSystemHealthStatus() {
        try {
            boolean allHealthy = componentHealth.values().stream().allMatch(Boolean::booleanValue);
            if (allHealthy) {
                return "HEALTHY";
            }

            long unhealthyCount = componentHealth.values().stream().mapToLong(h -> h ? 0 : 1).sum();
            if (unhealthyCount == 1) {
                return "DEGRADED";
            } else {
                return "CRITICAL";
            }
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    /**
     * Get performance summary for admin commands
     */
    public static String getPerformanceSummary() {
        try {
            SystemStatistics stats = getSystemStatistics();
            MemoryInfo memoryInfo = getMemoryInfoSafe();

            if (Config.enableMonitoring) {
                double cpuUsage = getCurrentCpuUsage();
                String cpuInfo = cpuUsage >= 0 ? String.format(" | CPU: %.1f%%", cpuUsage) : "";

                return String.format("Auth: %.1fms avg | Memory: %.1fMB (%.1f%%) | Sessions: %d%s | Uptime: %s",
                        stats.averageAuthTime(), memoryInfo.usageMB(), memoryInfo.usagePercent(),
                        stats.activeSessions(), cpuInfo, stats.uptime());
            } else {
                return String.format("Auth: %.1fms avg | Memory: %.1fMB (%.1f%%) | Sessions: %d | Uptime: %s",
                        stats.averageAuthTime(), memoryInfo.usageMB(), memoryInfo.usagePercent(),
                        stats.activeSessions(), stats.uptime());
            }
        } catch (Exception e) {
            return "Performance data unavailable: " + e.getMessage();
        }
    }

    // ==================== DATA RECORDS (BACKWARD COMPATIBILITY) ====================

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

    // ==================== ENHANCED DATA RECORDS ====================

    private record EnhancedMonitoringReport(
            String timestamp,
            SystemStatistics statistics,
            HealthCheckResult healthCheck,
            Map<String, Integer> eventStatistics,
            List<AuthLogger.SecurityAlert> securityAlerts,
            Map<String, Object> configuration,
            Map<String, String> systemInfo,
            Map<String, Object> performanceMetrics,
            Map<String, Object> componentHealthDetails,
            Map<String, Object> metricsHistorySummary
    ) {}

    private record SessionInfo(
            int activeSessions,
            int pendingOperations
    ) {}

    private record MemoryInfo(
            double usageMB,
            double usagePercent,
            long usedBytes,
            long maxBytes
    ) {}

    private record MetricSnapshot(
            long timestamp,
            double memoryUsageMB,
            double memoryUsagePercent,
            int activeSessions,
            int authOperations,
            int totalLogins,
            int failedLogins,
            long dbOperations,
            double cpuUsage
    ) {}
}