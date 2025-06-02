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
import com.google.gson.JsonSyntaxException;
import com.larbaco.larbaco_auth.LarbacoAuthMain;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Enhanced authentication logger with improved performance and reliability.
 * Maintains full backward compatibility while adding advanced logging capabilities.
 */
public class AuthLogger {
    // ==================== CONSTANTS ====================
    private static final String LOG_DIR = "config/larbaco_auth/logs";
    private static final String CURRENT_LOG_FILE = "auth.log";
    private static final String ARCHIVED_LOG_PREFIX = "auth.log.";
    private static final int MAX_LOG_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private static final int MAX_ARCHIVED_FILES = 10;
    private static final int MAX_MEMORY_ENTRIES = 1000;
    private static final int LOG_QUEUE_CAPACITY = 5000;

    // ==================== FORMATTERS ====================
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss");

    // Enhanced log format - structured but human-readable
    private static final String LOG_SEPARATOR = " | ";
    private static final String NULL_VALUE = "-";

    // ==================== DATA STRUCTURES ====================
    private static final Queue<LogEntry> memoryBuffer = new ConcurrentLinkedQueue<>();
    private static final Map<UUID, Queue<LogEntry>> playerLogs = new ConcurrentHashMap<>();
    private static final ReentrantReadWriteLock playerLogsLock = new ReentrantReadWriteLock();
    private static final Map<String, Integer> eventCounts = new ConcurrentHashMap<>();
    private static final Map<String, Long> eventTimestamps = new ConcurrentHashMap<>();

    // ==================== ENHANCED FEATURES ====================
    private static final Map<UUID, String> playerNameCache = new ConcurrentHashMap<>();
    private static final AtomicLong correlationIdCounter = new AtomicLong(1);
    private static final Map<String, Long> performanceMetrics = new ConcurrentHashMap<>();

    // Enhanced buffering and performance
    private static final BlockingQueue<LogEntry> writeQueue = new LinkedBlockingQueue<>(LOG_QUEUE_CAPACITY);
    private static final Map<String, AtomicLong> eventCounters = new ConcurrentHashMap<>();
    private static final Map<String, Long> lastEventTime = new ConcurrentHashMap<>();

    // ==================== DEDUPLICATION ====================
    private static final Map<String, Long> lastLogTime = new ConcurrentHashMap<>();
    private static final Map<String, Integer> logRepeatCount = new ConcurrentHashMap<>();
    private static final long DEDUP_WINDOW = TimeUnit.SECONDS.toMillis(30);
    private static final int MAX_REPEATS_BEFORE_SUPPRESS = 3;

    // ==================== IP CACHE ====================
    private static final Map<UUID, String> ipCache = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> ipCacheTime = new ConcurrentHashMap<>();
    private static final Map<UUID, String> storedPlayerIPs = new ConcurrentHashMap<>();
    private static final long IP_CACHE_DURATION = TimeUnit.MINUTES.toMillis(5);

    // ==================== THREAD MANAGEMENT ====================
    private static volatile ScheduledExecutorService loggerService;
    private static volatile ExecutorService writerService;
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final AtomicBoolean shutdownInProgress = new AtomicBoolean(false);
    private static final AtomicLong totalBytesWritten = new AtomicLong(0);
    private static final AtomicLong writeOperationCount = new AtomicLong(0);

    // ==================== INITIALIZATION ====================

    public static void initialize() {
        if (!initialized.compareAndSet(false, true)) {
            LarbacoAuthMain.LOGGER.debug("AuthLogger already initialized, skipping");
            return;
        }

        try {
            createLogDirectoryStructure();
            initializeThreadPools();
            loadRecentLogsOptimized();
            scheduleMaintenanceTasks();

            LarbacoAuthMain.LOGGER.info("Enhanced AuthLogger initialized successfully");

        } catch (Exception e) {
            initialized.set(false);
            LarbacoAuthMain.LOGGER.error("Failed to initialize AuthLogger: {}", e.getMessage(), e);
            throw new RuntimeException("AuthLogger initialization failed", e);
        }
    }

    // ==================== ORIGINAL METHODS (BACKWARD COMPATIBILITY) ====================

    public static void logAuthEvent(UUID playerId, String playerName, String eventType, String details) {
        if (!isLoggerReady()) {
            return;
        }

        try {
            // Check for log deduplication first
            if (shouldDeduplicateLog(eventType, details)) {
                return;
            }

            String resolvedPlayerName = resolveAndCachePlayerName(playerId, playerName);
            LogEntry entry = createLogEntry(
                    playerId,
                    resolvedPlayerName,
                    eventType,
                    enhanceEventDetails(eventType, details, playerId),
                    getClientIPCached(playerId)
            );

            processLogEntry(entry);

            if (!writeQueue.offer(entry)) {
                handleQueueOverflow(entry);
            }

        } catch (Exception e) {
            handleLoggingError("auth event", eventType, e);
        }
    }

    public static void logAdminAction(String adminName, String action, String details) {
        if (!isLoggerReady()) {
            return;
        }

        try {
            String enhancedDetails = buildAdminActionDetails(adminName, action, details);

            if (shouldDeduplicateLog("ADMIN_ACTION", enhancedDetails)) {
                return;
            }

            LogEntry entry = createLogEntry(
                    null,
                    adminName,
                    "ADMIN_ACTION",
                    enhancedDetails,
                    null
            );

            processLogEntry(entry);

            if (!writeQueue.offer(entry)) {
                handleQueueOverflow(entry);
            }

        } catch (Exception e) {
            handleLoggingError("admin action", action, e);
        }
    }

    public static void logSystemEvent(String eventType, String details) {
        if (!isLoggerReady()) {
            return;
        }

        try {
            String enhancedDetails = buildSystemEventDetails(eventType, details);

            if (shouldDeduplicateLog(eventType, enhancedDetails)) {
                return;
            }

            LogEntry entry = createLogEntry(
                    null,
                    "SYSTEM",
                    eventType,
                    enhancedDetails,
                    null
            );

            processLogEntry(entry);

            if (!writeQueue.offer(entry)) {
                handleQueueOverflow(entry);
            }

        } catch (Exception e) {
            handleLoggingError("system event", eventType, e);
        }
    }

    public static List<LogEntry> getRecentLogs(int limit) {
        if (!initialized.get()) {
            return Collections.emptyList();
        }

        try {
            return memoryBuffer.stream()
                    .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                    .limit(Math.max(1, Math.min(limit, 10000)))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error retrieving recent logs: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    public static List<LogEntry> getPlayerLogs(UUID playerId, int limit) {
        if (!initialized.get() || playerId == null) {
            return Collections.emptyList();
        }

        playerLogsLock.readLock().lock();
        try {
            Queue<LogEntry> logs = playerLogs.get(playerId);
            if (logs == null || logs.isEmpty()) {
                return Collections.emptyList();
            }

            return logs.stream()
                    .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                    .limit(Math.max(1, Math.min(limit, 1000)))
                    .collect(Collectors.toList());

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error retrieving player logs for {}: {}", playerId, e.getMessage());
            return Collections.emptyList();
        } finally {
            playerLogsLock.readLock().unlock();
        }
    }

    public static Map<String, Integer> getEventStatistics() {
        if (!initialized.get()) {
            return Collections.emptyMap();
        }

        try {
            Map<String, Integer> stats = new HashMap<>();

            synchronized (eventCounts) {
                stats.putAll(eventCounts);
            }

            eventCounters.forEach((key, value) ->
                    stats.merge(key, value.intValue(), Integer::sum));

            return stats;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error retrieving event statistics: {}", e.getMessage());
            return Collections.emptyMap();
        }
    }

    public static List<LogEntry> searchLogs(String eventType, UUID playerId, long fromTimestamp, long toTimestamp, int limit) {
        if (!initialized.get()) {
            return Collections.emptyList();
        }

        try {
            if (toTimestamp < fromTimestamp) {
                long temp = fromTimestamp;
                fromTimestamp = toTimestamp;
                toTimestamp = temp;
            }

            int safeLimit = Math.max(1, Math.min(limit, 10000));

            long finalFromTimestamp = fromTimestamp;
            long finalToTimestamp = toTimestamp;
            return memoryBuffer.stream()
                    .filter(entry -> eventType == null || eventType.equals(entry.type()))
                    .filter(entry -> playerId == null || playerId.equals(entry.playerId()))
                    .filter(entry -> entry.timestamp() >= finalFromTimestamp)
                    .filter(entry -> entry.timestamp() <= finalToTimestamp)
                    .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                    .limit(safeLimit)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error searching logs: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    public static String exportLogs(long fromTimestamp, long toTimestamp) throws IOException {
        if (!initialized.get()) {
            throw new IllegalStateException("AuthLogger not initialized");
        }

        try {
            String exportFileName = String.format("auth_export_%s.log",
                    LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT));
            Path exportPath = Paths.get(LOG_DIR, "exports", exportFileName);

            Files.createDirectories(exportPath.getParent());

            List<LogEntry> logsToExport = searchLogs(null, null, fromTimestamp, toTimestamp, Integer.MAX_VALUE);

            try (BufferedWriter writer = Files.newBufferedWriter(exportPath, StandardCharsets.UTF_8)) {
                writer.write("# LarbacoAuth Log Export");
                writer.newLine();
                writer.write("# Export Time: " + LocalDateTime.now().format(TIMESTAMP_FORMAT));
                writer.newLine();
                writer.write("# From: " + LocalDateTime.ofEpochSecond(fromTimestamp / 1000, 0, java.time.ZoneOffset.UTC).format(TIMESTAMP_FORMAT));
                writer.newLine();
                writer.write("# To: " + LocalDateTime.ofEpochSecond(toTimestamp / 1000, 0, java.time.ZoneOffset.UTC).format(TIMESTAMP_FORMAT));
                writer.newLine();
                writer.write("# Total Entries: " + logsToExport.size());
                writer.newLine();
                writer.write("# Format: TIMESTAMP | TYPE | PLAYER_ID | PLAYER_NAME | CLIENT_IP | DETAILS");
                writer.newLine();
                writer.write("#");
                writer.newLine();

                for (LogEntry entry : logsToExport) {
                    writer.write(formatLogEntry(entry));
                    writer.newLine();
                }
            }

            LarbacoAuthMain.LOGGER.info("Export completed: {} entries exported to {}",
                    logsToExport.size(), exportPath);
            return exportPath.toString();

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error exporting logs: {}", e.getMessage(), e);
            throw e;
        }
    }

    public static List<SecurityAlert> getSecurityAlerts() {
        if (!initialized.get()) {
            return Collections.emptyList();
        }

        List<SecurityAlert> alerts = new ArrayList<>();

        try {
            detectFailedLoginPatterns(alerts);
            detectSessionAbusePatterns(alerts);
            detectAdminActivityPatterns(alerts);
            detectSystemAnomalies(alerts);

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error generating security alerts: {}", e.getMessage());
            alerts.add(new SecurityAlert(
                    "ALERT_GENERATION_ERROR",
                    "Error generating security alerts: " + e.getMessage(),
                    SecurityAlert.Level.HIGH,
                    System.currentTimeMillis()
            ));
        }

        return alerts;
    }

    public static void cleanup(UUID playerId) {
        if (!initialized.get() || playerId == null) {
            return;
        }

        try {
            playerLogsLock.writeLock().lock();
            try {
                Queue<LogEntry> removedLogs = playerLogs.remove(playerId);
                playerNameCache.remove(playerId);

                if (removedLogs != null) {
                    LarbacoAuthMain.LOGGER.debug("Cleaned up {} log entries for player {}",
                            removedLogs.size(), playerId);
                }
            } finally {
                playerLogsLock.writeLock().unlock();
            }

            cleanupIPCache(playerId);
            removeStoredPlayerIP(playerId);
            memoryBuffer.removeIf(entry -> playerId.equals(entry.playerId()));

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error cleaning up player logs for {}: {}", playerId, e.getMessage());
        }
    }

    public static void cleanupCorruptedLogFile() {
        if (!initialized.get()) {
            return;
        }

        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(logFile)) {
                return;
            }

            List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
            List<String> validLines = new ArrayList<>();
            int removedCount = 0;

            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.isEmpty()) {
                    continue;
                }

                if (validateLogEntryLine(line)) {
                    validLines.add(lines.get(i));
                } else {
                    removedCount++;
                }
            }

            if (removedCount > 0) {
                createCorruptedBackup(logFile);
                Files.write(logFile, validLines, StandardCharsets.UTF_8);

                LarbacoAuthMain.LOGGER.info("Log cleanup completed: removed {} corrupted entries, kept {} valid entries",
                        removedCount, validLines.size());

                logSystemEvent("LOG_CLEANUP",
                        String.format("Removed %d corrupted entries, kept %d valid entries",
                                removedCount, validLines.size()));
            }

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error during log cleanup: {}", e.getMessage(), e);
        }
    }

    public static void shutdown() {
        if (!initialized.get() || shutdownInProgress.getAndSet(true)) {
            return;
        }

        try {
            LarbacoAuthMain.LOGGER.info("AuthLogger shutdown initiated...");

            flushLogs();
            shutdownThreadPools();
            clearDataStructures();

            initialized.set(false);
            LarbacoAuthMain.LOGGER.info("AuthLogger shutdown completed");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during AuthLogger shutdown: {}", e.getMessage(), e);
        }
    }

    // ==================== IP RESOLUTION METHODS ====================

    public static void storePlayerIP(UUID playerId, String ip) {
        if (playerId != null && ip != null && !ip.trim().isEmpty()) {
            storedPlayerIPs.put(playerId, ip);
            ipCache.put(playerId, ip);
            ipCacheTime.put(playerId, System.currentTimeMillis());
        }
    }

    public static void removeStoredPlayerIP(UUID playerId) {
        if (playerId != null) {
            storedPlayerIPs.remove(playerId);
        }
    }

    public static String extractIPFromConnection(net.minecraft.server.level.ServerPlayer player) {
        if (player == null || player.connection == null) {
            return null;
        }

        try {
            java.net.SocketAddress remoteAddress = player.connection.getConnection().getRemoteAddress();
            if (remoteAddress != null) {
                String addressString = remoteAddress.toString();

                if (addressString.startsWith("/")) {
                    addressString = addressString.substring(1);
                }

                if (addressString.contains(":")) {
                    addressString = addressString.substring(0, addressString.indexOf(":"));
                }

                return addressString;
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.debug("Error extracting IP from player connection: {}", e.getMessage());
        }

        return null;
    }

    // ==================== PRIVATE HELPER METHODS ====================

    private static boolean isLoggerReady() {
        return initialized.get() && !shutdownInProgress.get();
    }

    private static boolean shouldDeduplicateLog(String eventType, String details) {
        String logKey = eventType + "|" + (details != null ? details.hashCode() : 0);
        long currentTime = System.currentTimeMillis();

        Long lastTime = lastLogTime.get(logKey);
        if (lastTime == null) {
            lastLogTime.put(logKey, currentTime);
            logRepeatCount.put(logKey, 1);
            return false;
        }

        if (currentTime - lastTime < DEDUP_WINDOW) {
            int count = logRepeatCount.getOrDefault(logKey, 0) + 1;
            logRepeatCount.put(logKey, count);

            if (count > MAX_REPEATS_BEFORE_SUPPRESS) {
                lastLogTime.put(logKey, currentTime);
                return true;
            }
        } else {
            logRepeatCount.put(logKey, 1);
        }

        lastLogTime.put(logKey, currentTime);
        return false;
    }

    private static String resolveAndCachePlayerName(UUID playerId, String providedName) {
        if (playerId == null) return providedName;

        String cachedName = playerNameCache.get(playerId);
        if (cachedName != null) return cachedName;

        if (providedName != null && !providedName.equals("UNKNOWN") && !providedName.trim().isEmpty()) {
            playerNameCache.put(playerId, providedName);
            return providedName;
        }

        return playerId.toString().substring(0, 8);
    }

    private static LogEntry createLogEntry(UUID playerId, String playerName, String eventType, String details, String clientIP) {
        return new LogEntry(
                System.currentTimeMillis(),
                playerId,
                playerName,
                eventType,
                details,
                clientIP
        );
    }

    private static void processLogEntry(LogEntry entry) {
        addToMemoryBuffer(entry);

        if (entry.playerId() != null) {
            addToPlayerLogs(entry.playerId(), entry);
        }

        updateEventStatistics(entry.type());
    }

    private static void addToMemoryBuffer(LogEntry entry) {
        memoryBuffer.offer(entry);

        if (memoryBuffer.size() > MAX_MEMORY_ENTRIES) {
            int toRemove = memoryBuffer.size() - MAX_MEMORY_ENTRIES;
            for (int i = 0; i < toRemove; i++) {
                memoryBuffer.poll();
            }
        }
    }

    private static void addToPlayerLogs(UUID playerId, LogEntry entry) {
        playerLogsLock.writeLock().lock();
        try {
            Queue<LogEntry> logs = playerLogs.computeIfAbsent(playerId, k -> new ConcurrentLinkedQueue<>());
            logs.offer(entry);

            if (logs.size() > 100) {
                int toRemove = logs.size() - 100;
                for (int i = 0; i < toRemove; i++) {
                    logs.poll();
                }
            }
        } finally {
            playerLogsLock.writeLock().unlock();
        }
    }

    private static void updateEventStatistics(String eventType) {
        eventCounters.computeIfAbsent(eventType, k -> new AtomicLong(0)).incrementAndGet();
        lastEventTime.put(eventType, System.currentTimeMillis());

        synchronized (eventCounts) {
            eventCounts.merge(eventType, 1, Integer::sum);
            eventTimestamps.put(eventType, System.currentTimeMillis());
        }
    }

    private static String getClientIPCached(UUID playerId) {
        if (playerId == null) {
            return null;
        }

        String cachedIP = ipCache.get(playerId);
        Long cacheTime = ipCacheTime.get(playerId);

        if (cachedIP != null && cacheTime != null &&
                System.currentTimeMillis() - cacheTime < IP_CACHE_DURATION) {
            return cachedIP;
        }

        String ip = getClientIP(playerId);

        if (ip != null) {
            ipCache.put(playerId, ip);
            ipCacheTime.put(playerId, System.currentTimeMillis());
        } else {
            ip = storedPlayerIPs.get(playerId);
            if (ip != null) {
                ipCache.put(playerId, ip);
                ipCacheTime.put(playerId, System.currentTimeMillis());
            }
        }

        return ip;
    }

    private static String getClientIP(UUID playerId) {
        if (playerId == null) {
            return null;
        }

        try {
            net.minecraft.server.MinecraftServer server = net.neoforged.neoforge.server.ServerLifecycleHooks.getCurrentServer();

            if (server != null) {
                return extractIPFromServer(server, playerId);
            }

            return null;

        } catch (Exception e) {
            if (System.currentTimeMillis() % 30000 < 1000) {
                LarbacoAuthMain.LOGGER.debug("Could not resolve IP for player {}: {}", playerId, e.getMessage());
            }
            return null;
        }
    }

    private static String extractIPFromServer(net.minecraft.server.MinecraftServer server, UUID playerId) {
        try {
            net.minecraft.server.players.PlayerList playerList = server.getPlayerList();
            if (playerList == null) {
                return null;
            }

            net.minecraft.server.level.ServerPlayer serverPlayer = playerList.getPlayer(playerId);
            if (serverPlayer == null) {
                return null;
            }

            net.minecraft.server.network.ServerGamePacketListenerImpl connection = serverPlayer.connection;
            if (connection == null || connection.getConnection() == null) {
                return null;
            }

            java.net.SocketAddress socketAddress = connection.getConnection().getRemoteAddress();
            if (socketAddress instanceof java.net.InetSocketAddress inetSocketAddress) {
                java.net.InetAddress address = inetSocketAddress.getAddress();
                String ip = address.getHostAddress();

                if (ip.startsWith("0:0:0:0:0:ffff:")) {
                    ip = ip.substring(15);
                } else if (ip.startsWith("::ffff:")) {
                    ip = ip.substring(7);
                }

                return ip;
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }

    private static void cleanupIPCache(UUID playerId) {
        if (playerId != null) {
            ipCache.remove(playerId);
            ipCacheTime.remove(playerId);
        }
    }

    private static String enhanceEventDetails(String eventType, String details, UUID playerId) {
        StringBuilder enhanced = new StringBuilder(details);

        if (eventType.contains("LOGIN") || eventType.contains("REGISTER")) {
            String perfKey = eventType + "_" + (playerId != null ? playerId.toString() : "SYSTEM");
            Long lastTime = performanceMetrics.get(perfKey);
            if (lastTime != null) {
                long duration = System.currentTimeMillis() - lastTime;
                enhanced.append(String.format(" [Duration: %dms]", duration));
            }
        }

        return enhanced.toString();
    }

    private static String buildAdminActionDetails(String adminName, String action, String details) {
        return String.format("[ADMIN:%s] %s: %s [Uptime: %dms]",
                adminName, action, details, LarbacoAuthMain.getUptimeMillis());
    }

    private static String buildSystemEventDetails(String eventType, String details) {
        return String.format("[SYS] %s (Uptime: %dms, Memory: %.1fMB)",
                details, LarbacoAuthMain.getUptimeMillis(), getMemoryUsageMB());
    }

    private static double getMemoryUsageMB() {
        try {
            Runtime runtime = Runtime.getRuntime();
            long usedMemory = runtime.totalMemory() - runtime.freeMemory();
            return usedMemory / (1024.0 * 1024.0);
        } catch (Exception e) {
            return 0.0;
        }
    }

    private static void handleQueueOverflow(LogEntry entry) {
        try {
            writeQueue.poll();
            if (!writeQueue.offer(entry)) {
                writeLogEntryDirect(entry);
            }
            LarbacoAuthMain.LOGGER.warn("Log queue overflow handled for event: {}", entry.type());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error handling queue overflow: {}", e.getMessage());
        }
    }

    private static void handleLoggingError(String operation, String context, Exception e) {
        LarbacoAuthMain.LOGGER.error("Error logging {}: {} - {}", operation, context, e.getMessage());
    }

    private static boolean validateLogEntryLine(String line) {
        if (line == null || line.trim().isEmpty()) {
            return false;
        }

        try {
            return parseLogEntryFromLine(line) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static LogEntry parseLogEntryFromLine(String line) {
        try {
            String[] parts = line.split("\\" + LOG_SEPARATOR, 6);
            if (parts.length < 4) {
                return null;
            }

            long timestamp = LocalDateTime.parse(parts[0].trim(), TIMESTAMP_FORMAT)
                    .atZone(java.time.ZoneOffset.UTC)
                    .toInstant()
                    .toEpochMilli();

            String type = parts[1].trim();

            UUID playerId = null;
            if (!parts[2].trim().equals(NULL_VALUE)) {
                try {
                    playerId = UUID.fromString(parts[2].trim());
                } catch (IllegalArgumentException e) {
                    // Invalid UUID format, keep as null
                }
            }

            String playerName = parts[3].trim().equals(NULL_VALUE) ? null : parts[3].trim();
            String clientIP = parts.length > 4 && !parts[4].trim().equals(NULL_VALUE) ? parts[4].trim() : null;
            String details = parts.length > 5 ? parts[5].trim() : "";

            return new LogEntry(timestamp, playerId, playerName, type, details, clientIP);

        } catch (Exception e) {
            return null;
        }
    }

    private static String formatLogEntry(LogEntry entry) {
        StringBuilder sb = new StringBuilder();

        sb.append(LocalDateTime.ofEpochSecond(entry.timestamp() / 1000, 0, java.time.ZoneOffset.UTC)
                .format(TIMESTAMP_FORMAT));
        sb.append(LOG_SEPARATOR);

        sb.append(entry.type());
        sb.append(LOG_SEPARATOR);

        sb.append(entry.playerId() != null ? entry.playerId().toString() : NULL_VALUE);
        sb.append(LOG_SEPARATOR);

        sb.append(entry.playerName() != null ? entry.playerName() : NULL_VALUE);
        sb.append(LOG_SEPARATOR);

        sb.append(entry.clientIP() != null ? entry.clientIP() : NULL_VALUE);
        sb.append(LOG_SEPARATOR);

        String details = entry.details() != null ? entry.details().replace("|", "\\|") : "";
        sb.append(details);

        return sb.toString();
    }

    private static void createCorruptedBackup(Path logFile) throws IOException {
        String timestamp = LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
        Path backupFile = Paths.get(LOG_DIR, "corrupted_backup_" + timestamp + ".log");
        Files.copy(logFile, backupFile, StandardCopyOption.REPLACE_EXISTING);
        LarbacoAuthMain.LOGGER.info("Created corrupted log backup: {}", backupFile.getFileName());
    }

    private static void detectFailedLoginPatterns(List<SecurityAlert> alerts) {
        try {
            long oneHourAgo = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1);

            Map<UUID, Long> failedAttempts = memoryBuffer.stream()
                    .filter(entry -> "LOGIN_FAILED".equals(entry.type()))
                    .filter(entry -> entry.timestamp() > oneHourAgo)
                    .collect(Collectors.groupingBy(LogEntry::playerId, Collectors.counting()));

            failedAttempts.entrySet().stream()
                    .filter(entry -> entry.getValue() >= 3)
                    .forEach(entry -> {
                        String playerName = resolveAndCachePlayerName(entry.getKey(), null);
                        SecurityAlert.Level level = entry.getValue() >= 5 ?
                                SecurityAlert.Level.HIGH : SecurityAlert.Level.MEDIUM;

                        alerts.add(new SecurityAlert(
                                "MULTIPLE_FAILED_LOGINS",
                                String.format("Player %s (%s) has %d failed login attempts in the last hour",
                                        playerName, entry.getKey(), entry.getValue()),
                                level,
                                System.currentTimeMillis()
                        ));
                    });

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error detecting failed login patterns: {}", e.getMessage());
        }
    }

    private static void detectSessionAbusePatterns(List<SecurityAlert> alerts) {
        try {
            long fiveMinutesAgo = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(5);

            long recentSessions = memoryBuffer.stream()
                    .filter(entry -> "SESSION_CREATED".equals(entry.type()))
                    .filter(entry -> entry.timestamp() > fiveMinutesAgo)
                    .count();

            if (recentSessions > 8) {
                SecurityAlert.Level level = recentSessions > 15 ?
                        SecurityAlert.Level.HIGH : SecurityAlert.Level.MEDIUM;

                alerts.add(new SecurityAlert(
                        "RAPID_SESSION_CREATION",
                        String.format("%d sessions created in the last 5 minutes - possible abuse", recentSessions),
                        level,
                        System.currentTimeMillis()
                ));
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error detecting session abuse patterns: {}", e.getMessage());
        }
    }

    private static void detectAdminActivityPatterns(List<SecurityAlert> alerts) {
        try {
            long oneHourAgo = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1);

            long adminActions = memoryBuffer.stream()
                    .filter(entry -> "ADMIN_ACTION".equals(entry.type()))
                    .filter(entry -> entry.timestamp() > oneHourAgo)
                    .count();

            if (adminActions > 5) {
                SecurityAlert.Level level = adminActions > 10 ?
                        SecurityAlert.Level.HIGH : SecurityAlert.Level.MEDIUM;

                alerts.add(new SecurityAlert(
                        "HIGH_ADMIN_ACTIVITY",
                        String.format("%d admin actions in the last hour", adminActions),
                        level,
                        System.currentTimeMillis()
                ));
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error detecting admin activity patterns: {}", e.getMessage());
        }
    }

    private static void detectSystemAnomalies(List<SecurityAlert> alerts) {
        try {
            long sixHoursAgo = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(6);

            long restartCount = memoryBuffer.stream()
                    .filter(entry -> "MOD_INITIALIZED".equals(entry.type()) || "SERVER_STARTING".equals(entry.type()))
                    .filter(entry -> entry.timestamp() > sixHoursAgo)
                    .count();

            if (restartCount > 3) {
                alerts.add(new SecurityAlert(
                        "FREQUENT_RESTARTS",
                        String.format("%d system restarts detected in the last 6 hours", restartCount),
                        SecurityAlert.Level.MEDIUM,
                        System.currentTimeMillis()
                ));
            }

            long loggingErrors = memoryBuffer.stream()
                    .filter(entry -> "LOGGING_ERROR".equals(entry.type()))
                    .filter(entry -> entry.timestamp() > System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1))
                    .count();

            if (loggingErrors > 5) {
                alerts.add(new SecurityAlert(
                        "LOGGING_ERRORS",
                        String.format("%d logging errors detected in the last hour", loggingErrors),
                        SecurityAlert.Level.HIGH,
                        System.currentTimeMillis()
                ));
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error detecting system anomalies: {}", e.getMessage());
        }
    }

    // ==================== INITIALIZATION HELPERS ====================

    private static void createLogDirectoryStructure() throws IOException {
        Path logPath = Paths.get(LOG_DIR);
        Path exportsPath = Paths.get(LOG_DIR, "exports");
        Path archivesPath = Paths.get(LOG_DIR, "archives");

        Files.createDirectories(logPath);
        Files.createDirectories(exportsPath);
        Files.createDirectories(archivesPath);

        LarbacoAuthMain.LOGGER.debug("Log directory structure created successfully");
    }

    private static void initializeThreadPools() {
        loggerService = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "LarbacoAuth-Logger");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, ex) -> {
                LarbacoAuthMain.LOGGER.error("Uncaught exception in logger thread: {}", ex.getMessage(), ex);
            });
            return t;
        });

        writerService = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "LarbacoAuth-Writer");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, ex) -> {
                LarbacoAuthMain.LOGGER.error("Uncaught exception in writer thread: {}", ex.getMessage(), ex);
            });
            return t;
        });

        createLogFileHeader();
        writerService.submit(new AsyncLogWriter());

        LarbacoAuthMain.LOGGER.debug("Thread pools initialized for enhanced logging");
    }

    private static void createLogFileHeader() {
        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);

            if (!Files.exists(logFile) || Files.size(logFile) == 0) {
                StringBuilder header = new StringBuilder();
                header.append("# LarbacoAuth Authentication Log").append(System.lineSeparator());
                header.append("# Started: ").append(LocalDateTime.now().format(TIMESTAMP_FORMAT)).append(System.lineSeparator());
                header.append("# Format: TIMESTAMP | TYPE | PLAYER_ID | PLAYER_NAME | CLIENT_IP | DETAILS").append(System.lineSeparator());
                header.append("#").append(System.lineSeparator());

                Files.write(logFile, header.toString().getBytes(StandardCharsets.UTF_8),
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);

                LarbacoAuthMain.LOGGER.debug("Created log file header");
            }
        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error creating log file header: {}", e.getMessage());
        }
    }

    private static void scheduleMaintenanceTasks() {
        loggerService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    checkAndRotateLogs();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during log rotation check: {}", e.getMessage());
                }
            }
        }, 1, 6, TimeUnit.HOURS);

        loggerService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    cleanupOldMetrics();
                    cleanupOldIPCache();
                    cleanupDeduplicationMaps();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during cleanup: {}", e.getMessage());
                }
            }
        }, 1, 1, TimeUnit.HOURS);

        loggerService.scheduleAtFixedRate(() -> {
            if (!shutdownInProgress.get()) {
                try {
                    optimizeMemoryUsage();
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error during memory optimization: {}", e.getMessage());
                }
            }
        }, 5, 30, TimeUnit.MINUTES);
    }

    private static void loadRecentLogsOptimized() {
        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(logFile)) {
                LarbacoAuthMain.LOGGER.debug("No existing log file found, starting fresh");
                return;
            }

            List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);

            if (lines.isEmpty()) {
                return;
            }

            int startIndex = Math.max(0, lines.size() - 100);
            int validEntries = 0;
            int malformedEntries = 0;

            for (int i = startIndex; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                try {
                    LogEntry entry = parseLogEntryFromLine(line);
                    if (entry != null && isValidLogEntry(entry)) {
                        addToMemoryBuffer(entry);

                        if (entry.playerId() != null) {
                            addToPlayerLogs(entry.playerId(), entry);
                            if (entry.playerName() != null && !entry.playerName().equals("UNKNOWN")) {
                                playerNameCache.put(entry.playerId(), entry.playerName());
                            }
                        }

                        updateEventStatistics(entry.type());
                        validEntries++;
                    } else {
                        malformedEntries++;
                    }
                } catch (Exception e) {
                    malformedEntries++;
                    if (malformedEntries <= 3) {
                        LarbacoAuthMain.LOGGER.debug("Skipping malformed log entry at line {}: {}",
                                i + 1, e.getMessage());
                    }
                }
            }

            if (malformedEntries > 5) {
                LarbacoAuthMain.LOGGER.warn("Found {} malformed log entries in {}. Consider running log cleanup.",
                        malformedEntries, CURRENT_LOG_FILE);
            }

            LarbacoAuthMain.LOGGER.info("Loaded {} valid log entries from {} total lines",
                    validEntries, lines.size() - startIndex);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error loading recent logs: {}", e.getMessage(), e);
        }
    }

    private static boolean isValidLogEntry(LogEntry entry) {
        return entry.timestamp() > 0 &&
                entry.type() != null &&
                !entry.type().trim().isEmpty() &&
                entry.details() != null &&
                entry.timestamp() <= System.currentTimeMillis() + 60000;
    }

    // ==================== MAINTENANCE METHODS ====================

    private static void checkAndRotateLogs() {
        if (shutdownInProgress.get()) {
            return;
        }

        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(logFile)) {
                return;
            }

            long fileSize = Files.size(logFile);
            if (fileSize > MAX_LOG_FILE_SIZE) {
                rotateLogs();
                LarbacoAuthMain.LOGGER.info("Log file rotated due to size: {} bytes", fileSize);
            }

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error checking log file size: {}", e.getMessage());
        }
    }

    private static void rotateLogs() {
        if (shutdownInProgress.get()) {
            return;
        }

        try {
            Path currentLog = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(currentLog) || Files.size(currentLog) == 0) {
                return;
            }

            String archiveFileName = ARCHIVED_LOG_PREFIX + LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
            Path archivePath = Paths.get(LOG_DIR, "archives", archiveFileName);

            Files.createDirectories(archivePath.getParent());
            Files.move(currentLog, archivePath);
            cleanupOldArchives();

            LarbacoAuthMain.LOGGER.info("Log rotated successfully: {}", archiveFileName);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error rotating logs: {}", e.getMessage(), e);
        }
    }

    private static void cleanupOldArchives() throws IOException {
        Path archivesDir = Paths.get(LOG_DIR, "archives");
        if (!Files.exists(archivesDir)) {
            return;
        }

        List<Path> archives = Files.list(archivesDir)
                .filter(path -> path.getFileName().toString().startsWith(ARCHIVED_LOG_PREFIX))
                .sorted((a, b) -> {
                    try {
                        return Long.compare(Files.getLastModifiedTime(b).toMillis(),
                                Files.getLastModifiedTime(a).toMillis());
                    } catch (IOException e) {
                        return 0;
                    }
                })
                .collect(Collectors.toList());

        for (int i = MAX_ARCHIVED_FILES; i < archives.size(); i++) {
            Files.delete(archives.get(i));
            LarbacoAuthMain.LOGGER.debug("Deleted old log archive: {}", archives.get(i).getFileName());
        }
    }

    private static void cleanupOldMetrics() {
        long cutoffTime = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(24);

        performanceMetrics.entrySet().removeIf(entry -> entry.getValue() < cutoffTime);
        lastEventTime.entrySet().removeIf(entry -> entry.getValue() < cutoffTime);
    }

    private static void cleanupOldIPCache() {
        long cutoffTime = System.currentTimeMillis() - IP_CACHE_DURATION;

        ipCacheTime.entrySet().removeIf(entry -> {
            if (entry.getValue() < cutoffTime) {
                ipCache.remove(entry.getKey());
                return true;
            }
            return false;
        });
    }

    private static void cleanupDeduplicationMaps() {
        long cutoffTime = System.currentTimeMillis() - DEDUP_WINDOW * 2;

        lastLogTime.entrySet().removeIf(entry -> entry.getValue() < cutoffTime);
        logRepeatCount.keySet().removeIf(key -> !lastLogTime.containsKey(key));
    }

    private static void optimizeMemoryUsage() {
        try {
            long cutoffTime = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(2);

            playerLogsLock.writeLock().lock();
            try {
                playerLogs.entrySet().removeIf(entry -> {
                    Queue<LogEntry> logs = entry.getValue();
                    if (logs.isEmpty()) {
                        return true;
                    }

                    return logs.stream().allMatch(log -> log.timestamp() < cutoffTime);
                });
            } finally {
                playerLogsLock.writeLock().unlock();
            }

            double memoryUsage = getMemoryUsageMB();
            if (memoryUsage > 200) {
                System.gc();
                LarbacoAuthMain.LOGGER.debug("Suggested garbage collection due to high memory usage: {:.1f}MB", memoryUsage);
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during memory optimization: {}", e.getMessage());
        }
    }

    // ==================== SHUTDOWN METHODS ====================

    private static void flushLogs() {
        try {
            int flushedCount = 0;
            List<LogEntry> remainingEntries = new ArrayList<>();

            LogEntry entry;
            while ((entry = writeQueue.poll()) != null) {
                remainingEntries.add(entry);
                flushedCount++;
            }

            if (!remainingEntries.isEmpty()) {
                for (LogEntry logEntry : remainingEntries) {
                    writeLogEntryDirect(logEntry);
                }
                LarbacoAuthMain.LOGGER.info("Flushed {} pending log entries during shutdown", flushedCount);
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during log flush: {}", e.getMessage());
        }
    }

    private static void shutdownThreadPools() {
        if (writerService != null && !writerService.isShutdown()) {
            writerService.shutdown();
            try {
                if (!writerService.awaitTermination(10, TimeUnit.SECONDS)) {
                    LarbacoAuthMain.LOGGER.warn("Writer service did not terminate gracefully, forcing shutdown");
                    writerService.shutdownNow();
                    if (!writerService.awaitTermination(5, TimeUnit.SECONDS)) {
                        LarbacoAuthMain.LOGGER.error("Writer service did not terminate after forced shutdown");
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                writerService.shutdownNow();
            }
        }

        if (loggerService != null && !loggerService.isShutdown()) {
            loggerService.shutdown();
            try {
                if (!loggerService.awaitTermination(5, TimeUnit.SECONDS)) {
                    LarbacoAuthMain.LOGGER.warn("Logger service did not terminate gracefully, forcing shutdown");
                    loggerService.shutdownNow();
                    if (!loggerService.awaitTermination(2, TimeUnit.SECONDS)) {
                        LarbacoAuthMain.LOGGER.error("Logger service did not terminate after forced shutdown");
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                loggerService.shutdownNow();
            }
        }
    }

    private static void clearDataStructures() {
        try {
            memoryBuffer.clear();

            playerLogsLock.writeLock().lock();
            try {
                playerLogs.clear();
                playerNameCache.clear();
            } finally {
                playerLogsLock.writeLock().unlock();
            }

            synchronized (eventCounts) {
                eventCounts.clear();
                eventTimestamps.clear();
            }

            performanceMetrics.clear();
            eventCounters.clear();
            lastEventTime.clear();
            writeQueue.clear();

            ipCache.clear();
            ipCacheTime.clear();
            storedPlayerIPs.clear();

            lastLogTime.clear();
            logRepeatCount.clear();

            LarbacoAuthMain.LOGGER.debug("All logging data structures cleared");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error clearing data structures: {}", e.getMessage());
        }
    }

    private static void writeLogEntryDirect(LogEntry entry) {
        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);

            if (Files.exists(logFile) && Files.size(logFile) > MAX_LOG_FILE_SIZE) {
                rotateLogs();
            }

            String logLine = formatLogEntry(entry) + System.lineSeparator();
            Files.write(logFile, logLine.getBytes(StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);

            writeOperationCount.incrementAndGet();
            totalBytesWritten.addAndGet(logLine.getBytes(StandardCharsets.UTF_8).length);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error writing log entry directly: {}", e.getMessage());
        }
    }

    // ==================== ASYNC WRITER CLASS ====================

    private static class AsyncLogWriter implements Runnable {
        private static final int BATCH_SIZE = 50;
        private final List<LogEntry> batch = new ArrayList<>(BATCH_SIZE);

        @Override
        public void run() {
            LarbacoAuthMain.LOGGER.debug("AsyncLogWriter started");

            while (!shutdownInProgress.get() || !writeQueue.isEmpty()) {
                try {
                    batch.clear();

                    LogEntry entry = writeQueue.poll(1, TimeUnit.SECONDS);
                    if (entry != null) {
                        batch.add(entry);

                        while (batch.size() < BATCH_SIZE) {
                            LogEntry additionalEntry = writeQueue.poll();
                            if (additionalEntry == null) {
                                break;
                            }
                            batch.add(additionalEntry);
                        }

                        writeBatch(batch);
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    LarbacoAuthMain.LOGGER.error("Error in AsyncLogWriter: {}", e.getMessage());

                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            LarbacoAuthMain.LOGGER.debug("AsyncLogWriter terminated");
        }

        private void writeBatch(List<LogEntry> entries) {
            if (entries.isEmpty()) {
                return;
            }

            try {
                Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);

                if (Files.exists(logFile) && Files.size(logFile) > MAX_LOG_FILE_SIZE) {
                    rotateLogs();
                }

                StringBuilder batchContent = new StringBuilder();
                for (LogEntry entry : entries) {
                    batchContent.append(formatLogEntry(entry)).append(System.lineSeparator());
                }

                byte[] batchBytes = batchContent.toString().getBytes(StandardCharsets.UTF_8);
                Files.write(logFile, batchBytes,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);

                writeOperationCount.addAndGet(entries.size());
                totalBytesWritten.addAndGet(batchBytes.length);

            } catch (IOException e) {
                LarbacoAuthMain.LOGGER.error("Error writing log batch of {} entries: {}",
                        entries.size(), e.getMessage());

                for (LogEntry entry : entries) {
                    try {
                        writeLogEntryDirect(entry);
                    } catch (Exception ex) {
                        LarbacoAuthMain.LOGGER.error("Failed to write individual log entry: {}", ex.getMessage());
                    }
                }
            }
        }
    }

    // ==================== DATA RECORDS ====================

    public record LogEntry(
            long timestamp,
            UUID playerId,
            String playerName,
            String type,
            String details,
            String clientIP
    ) {
        public String formattedTimestamp() {
            return LocalDateTime.ofEpochSecond(timestamp / 1000, 0, java.time.ZoneOffset.UTC)
                    .format(TIMESTAMP_FORMAT);
        }
    }

    public record SecurityAlert(
            String type,
            String message,
            Level level,
            long timestamp
    ) {
        public enum Level {
            LOW, MEDIUM, HIGH, CRITICAL
        }

        public String formattedTimestamp() {
            return LocalDateTime.ofEpochSecond(timestamp / 1000, 0, java.time.ZoneOffset.UTC)
                    .format(TIMESTAMP_FORMAT);
        }
    }
}