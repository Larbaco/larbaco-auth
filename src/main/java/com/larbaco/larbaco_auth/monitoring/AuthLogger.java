package com.larbaco.larbaco_auth.monitoring;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.larbaco.larbaco_auth.LarbacoAuthMain;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

public class AuthLogger {
    private static final String LOG_DIR = "config/larbaco_auth/logs";
    private static final String CURRENT_LOG_FILE = "auth.log";
    private static final String ARCHIVED_LOG_PREFIX = "auth.log.";
    private static final int MAX_LOG_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private static final int MAX_ARCHIVED_FILES = 10;
    private static final int MAX_MEMORY_ENTRIES = 1000;

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss");

    private static final Queue<LogEntry> memoryBuffer = new ConcurrentLinkedQueue<>();
    private static final Map<UUID, Queue<LogEntry>> playerLogs = new HashMap<>();
    private static final ReentrantReadWriteLock playerLogsLock = new ReentrantReadWriteLock();
    private static final Map<String, Integer> eventCounts = new HashMap<>();
    private static final Map<String, Long> eventTimestamps = new HashMap<>();

    private static final ScheduledExecutorService loggerService = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "LarbacoAuth-Logger");
        t.setDaemon(true);
        return t;
    });

    private static volatile boolean initialized = false;

    static {
        initialize();
        loggerService.scheduleAtFixedRate(AuthLogger::flushLogs, 30, 30, TimeUnit.SECONDS);
        loggerService.scheduleAtFixedRate(AuthLogger::rotateLogs, 1, 24, TimeUnit.HOURS);
    }

    public static void initialize() {
        try {
            createLogDirectory();
            loadRecentLogs();
            initialized = true;
            LarbacoAuthMain.LOGGER.info("AuthLogger initialized successfully");
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to initialize AuthLogger: {}", e.getMessage(), e);
        }
    }

    public static void logAuthEvent(UUID playerId, String playerName, String eventType, String details) {
        if (!initialized) {
            LarbacoAuthMain.LOGGER.warn("AuthLogger not initialized, skipping log entry");
            return;
        }

        try {
            LogEntry entry = new LogEntry(
                    System.currentTimeMillis(),
                    playerId,
                    playerName,
                    eventType,
                    details,
                    getClientIP(playerId)
            );

            addToMemoryBuffer(entry);
            addToPlayerLogs(playerId, entry);
            updateEventStatistics(eventType);

            loggerService.execute(() -> writeLogEntry(entry));

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging auth event: {}", e.getMessage(), e);
        }
    }

    public static void logAdminAction(String adminName, String action, String details) {
        try {
            LogEntry entry = new LogEntry(
                    System.currentTimeMillis(),
                    null,
                    adminName,
                    "ADMIN_ACTION",
                    String.format("%s: %s", action, details),
                    null
            );

            addToMemoryBuffer(entry);
            updateEventStatistics("ADMIN_ACTION");
            loggerService.execute(() -> writeLogEntry(entry));

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging admin action: {}", e.getMessage(), e);
        }
    }

    public static void logSystemEvent(String eventType, String details) {
        try {
            LogEntry entry = new LogEntry(
                    System.currentTimeMillis(),
                    null,
                    "SYSTEM",
                    eventType,
                    details,
                    null
            );

            addToMemoryBuffer(entry);
            updateEventStatistics(eventType);
            loggerService.execute(() -> writeLogEntry(entry));

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging system event: {}", e.getMessage(), e);
        }
    }

    public static List<LogEntry> getRecentLogs(int limit) {
        return memoryBuffer.stream()
                .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                .limit(limit)
                .collect(Collectors.toList());
    }

    public static List<LogEntry> getPlayerLogs(UUID playerId, int limit) {
        playerLogsLock.readLock().lock();
        try {
            Queue<LogEntry> logs = playerLogs.get(playerId);
            if (logs == null || logs.isEmpty()) {
                return Collections.emptyList();
            }

            return logs.stream()
                    .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                    .limit(limit)
                    .collect(Collectors.toList());

        } finally {
            playerLogsLock.readLock().unlock();
        }
    }

    public static Map<String, Integer> getEventStatistics() {
        synchronized (eventCounts) {
            return new HashMap<>(eventCounts);
        }
    }

    public static List<LogEntry> searchLogs(String eventType, UUID playerId, long fromTimestamp, long toTimestamp, int limit) {
        return memoryBuffer.stream()
                .filter(entry -> eventType == null || eventType.equals(entry.type()))
                .filter(entry -> playerId == null || playerId.equals(entry.playerId()))
                .filter(entry -> entry.timestamp() >= fromTimestamp)
                .filter(entry -> entry.timestamp() <= toTimestamp)
                .sorted((a, b) -> Long.compare(b.timestamp(), a.timestamp()))
                .limit(limit)
                .collect(Collectors.toList());
    }

    public static String exportLogs(long fromTimestamp, long toTimestamp) throws IOException {
        String exportFileName = String.format("auth_export_%s.json",
                LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT));
        Path exportPath = Paths.get(LOG_DIR, "exports", exportFileName);

        Files.createDirectories(exportPath.getParent());

        List<LogEntry> logsToExport = searchLogs(null, null, fromTimestamp, toTimestamp, Integer.MAX_VALUE);

        try (FileWriter writer = new FileWriter(exportPath.toFile())) {
            gson.toJson(logsToExport, writer);
        }

        LarbacoAuthMain.LOGGER.info("Exported {} log entries to {}", logsToExport.size(), exportPath);
        return exportPath.toString();
    }

    public static List<SecurityAlert> getSecurityAlerts() {
        List<SecurityAlert> alerts = new ArrayList<>();

        // Check for multiple failed login attempts
        Map<UUID, Long> failedAttempts = memoryBuffer.stream()
                .filter(entry -> "LOGIN_FAILED".equals(entry.type()))
                .filter(entry -> entry.timestamp() > System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1))
                .collect(Collectors.groupingBy(LogEntry::playerId, Collectors.counting()));

        failedAttempts.entrySet().stream()
                .filter(entry -> entry.getValue() >= 5)
                .forEach(entry -> alerts.add(new SecurityAlert(
                        "MULTIPLE_FAILED_LOGINS",
                        String.format("Player %s has %d failed login attempts in the last hour",
                                getPlayerName(entry.getKey()), entry.getValue()),
                        SecurityAlert.Level.HIGH,
                        System.currentTimeMillis()
                )));

        // Check for rapid session creation
        long recentSessions = memoryBuffer.stream()
                .filter(entry -> "SESSION_CREATED".equals(entry.type()))
                .filter(entry -> entry.timestamp() > System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(5))
                .count();

        if (recentSessions > 10) {
            alerts.add(new SecurityAlert(
                    "RAPID_SESSION_CREATION",
                    String.format("%d sessions created in the last 5 minutes", recentSessions),
                    SecurityAlert.Level.MEDIUM,
                    System.currentTimeMillis()
            ));
        }

        return alerts;
    }

    public static void cleanup(UUID playerId) {
        playerLogsLock.writeLock().lock();
        try {
            playerLogs.remove(playerId);
        } finally {
            playerLogsLock.writeLock().unlock();
        }

        memoryBuffer.removeIf(entry -> playerId.equals(entry.playerId()));
    }

    public static void shutdown() {
        try {
            flushLogs();
            loggerService.shutdown();

            if (!loggerService.awaitTermination(5, TimeUnit.SECONDS)) {
                loggerService.shutdownNow();
            }

            LarbacoAuthMain.LOGGER.info("AuthLogger shutdown completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            loggerService.shutdownNow();
        }
    }

    // Private helper methods

    private static void createLogDirectory() throws IOException {
        Path logPath = Paths.get(LOG_DIR);
        if (!Files.exists(logPath)) {
            Files.createDirectories(logPath);
        }

        Path exportsPath = Paths.get(LOG_DIR, "exports");
        if (!Files.exists(exportsPath)) {
            Files.createDirectories(exportsPath);
        }
    }

    private static void addToMemoryBuffer(LogEntry entry) {
        memoryBuffer.offer(entry);

        while (memoryBuffer.size() > MAX_MEMORY_ENTRIES) {
            memoryBuffer.poll();
        }
    }

    private static void addToPlayerLogs(UUID playerId, LogEntry entry) {
        if (playerId == null) return;

        playerLogsLock.writeLock().lock();
        try {
            playerLogs.computeIfAbsent(playerId, k -> new ConcurrentLinkedQueue<>()).offer(entry);

            Queue<LogEntry> logs = playerLogs.get(playerId);
            while (logs.size() > 100) {
                logs.poll();
            }
        } finally {
            playerLogsLock.writeLock().unlock();
        }
    }

    private static void updateEventStatistics(String eventType) {
        synchronized (eventCounts) {
            eventCounts.merge(eventType, 1, Integer::sum);
            eventTimestamps.put(eventType, System.currentTimeMillis());
        }
    }

    private static void writeLogEntry(LogEntry entry) {
        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);

            if (Files.exists(logFile) && Files.size(logFile) > MAX_LOG_FILE_SIZE) {
                rotateLogs();
            }

            try (FileWriter writer = new FileWriter(logFile.toFile(), true)) {
                writer.write(gson.toJson(entry));
                writer.write(System.lineSeparator());
            }

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error writing log entry: {}", e.getMessage(), e);
        }
    }

    private static void flushLogs() {
        loggerService.execute(() -> {
            // This ensures any queued log writes are processed
        });
    }

    private static void rotateLogs() {
        try {
            Path currentLog = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(currentLog) || Files.size(currentLog) == 0) {
                return;
            }

            String archiveFileName = ARCHIVED_LOG_PREFIX + LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
            Path archivePath = Paths.get(LOG_DIR, archiveFileName);

            Files.move(currentLog, archivePath);
            cleanupOldArchives();

            LarbacoAuthMain.LOGGER.info("Log rotated: {}", archiveFileName);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error rotating logs: {}", e.getMessage(), e);
        }
    }

    private static void cleanupOldArchives() throws IOException {
        List<Path> archives = Files.list(Paths.get(LOG_DIR))
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
            LarbacoAuthMain.LOGGER.debug("Deleted old log archive: {}", archives.get(i));
        }
    }

    private static void loadRecentLogs() {
        try {
            Path logFile = Paths.get(LOG_DIR, CURRENT_LOG_FILE);
            if (!Files.exists(logFile)) {
                return;
            }

            List<String> lines = Files.readAllLines(logFile);
            int startIndex = Math.max(0, lines.size() - 500);

            for (int i = startIndex; i < lines.size(); i++) {
                try {
                    LogEntry entry = gson.fromJson(lines.get(i), LogEntry.class);
                    if (entry != null) {
                        addToMemoryBuffer(entry);
                        if (entry.playerId() != null) {
                            addToPlayerLogs(entry.playerId(), entry);
                        }
                        updateEventStatistics(entry.type());
                    }
                } catch (JsonSyntaxException e) {
                    LarbacoAuthMain.LOGGER.warn("Skipping malformed log entry at line {}", i + 1);
                }
            }

            LarbacoAuthMain.LOGGER.info("Loaded {} recent log entries into memory",
                    Math.min(500, lines.size()));

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.error("Error loading recent logs: {}", e.getMessage(), e);
        }
    }

    private static String getClientIP(UUID playerId) {
        return null; // Would need server player lookup for actual IP
    }

    private static String getPlayerName(UUID playerId) {
        return memoryBuffer.stream()
                .filter(entry -> playerId.equals(entry.playerId()))
                .map(LogEntry::playerName)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(playerId.toString());
    }

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