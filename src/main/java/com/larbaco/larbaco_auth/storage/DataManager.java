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

package com.larbaco.larbaco_auth.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.monitoring.SystemMonitor;
import net.minecraft.world.level.GameType;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DataManager {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final String DATA_DIR = "config/larbaco_auth";
    private static final String PLAYERS_FILE = "players.json";
    private static final String GAME_MODES_FILE = "game_modes.json";
    private static final String BACKUP_DIR = "backups";
    private static final DateTimeFormatter BACKUP_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    private static final Map<UUID, String> playerPasswords = new ConcurrentHashMap<>();
    private static final Map<UUID, GameType> playerGameModes = new ConcurrentHashMap<>();

    private static final ReentrantReadWriteLock dataLock = new ReentrantReadWriteLock();

    private static volatile long lastBackupTime = 0;
    private static volatile long lastOptimizationTime = 0;
    private static volatile boolean initialized = false;

    public static void initialize() {
        dataLock.writeLock().lock();
        try {
            createDataDirectory();
            loadPlayerData();
            loadGameModes();
            createBackupDirectory();

            initialized = true;
            SystemMonitor.updateComponentHealth("Database", true, null);

            LarbacoAuthMain.LOGGER.info("DataManager initialized successfully - {} players, {} game modes",
                    playerPasswords.size(), playerGameModes.size());

            AuthLogger.logSystemEvent("DATABASE_INIT",
                    String.format("Loaded %d players and %d game modes", playerPasswords.size(), playerGameModes.size()));

        } catch (Exception e) {
            SystemMonitor.updateComponentHealth("Database", false, e.getMessage());
            LarbacoAuthMain.LOGGER.error("Failed to initialize DataManager: {}", e.getMessage(), e);
            throw new RuntimeException("DataManager initialization failed", e);
        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static void shutdown() {
        dataLock.writeLock().lock();
        try {
            savePlayerData();
            saveGameModes();

            LarbacoAuthMain.LOGGER.info("DataManager shutdown - all data saved ({} players, {} game modes)",
                    playerPasswords.size(), playerGameModes.size());

            AuthLogger.logSystemEvent("DATABASE_SHUTDOWN",
                    String.format("Saved %d players and %d game modes", playerPasswords.size(), playerGameModes.size()));

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during DataManager shutdown: {}", e.getMessage(), e);
        } finally {
            initialized = false;
            dataLock.writeLock().unlock();
        }
    }

    public static void registerPlayer(UUID uuid, String passwordHash) {
        if (!initialized) {
            throw new IllegalStateException("DataManager not initialized");
        }

        dataLock.writeLock().lock();
        try {
            playerPasswords.put(uuid, passwordHash);
            savePlayerDataAsync();
            SystemMonitor.recordDatabaseOperation();

            LarbacoAuthMain.LOGGER.debug("Registered player: {}", uuid);

        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static void unregisterPlayer(UUID uuid) {
        if (!initialized) {
            throw new IllegalStateException("DataManager not initialized");
        }

        dataLock.writeLock().lock();
        try {
            String removed = playerPasswords.remove(uuid);
            if (removed != null) {
                savePlayerDataAsync();
                SystemMonitor.recordDatabaseOperation();
                LarbacoAuthMain.LOGGER.debug("Unregistered player: {}", uuid);
            }
        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static boolean isPlayerRegistered(UUID uuid) {
        if (!initialized) {
            return false;
        }

        dataLock.readLock().lock();
        try {
            return playerPasswords.containsKey(uuid);
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static String getPlayerPasswordHash(UUID uuid) {
        if (!initialized) {
            return null;
        }

        dataLock.readLock().lock();
        try {
            SystemMonitor.recordDatabaseOperation();
            return playerPasswords.get(uuid);
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static void setPlayerGameMode(UUID uuid, GameType gameType) {
        if (!initialized) {
            return;
        }

        dataLock.writeLock().lock();
        try {
            playerGameModes.put(uuid, gameType);
            saveGameModesAsync();
            SystemMonitor.recordDatabaseOperation();
        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static GameType getPlayerGameMode(UUID uuid) {
        if (!initialized) {
            return null;
        }

        dataLock.readLock().lock();
        try {
            SystemMonitor.recordDatabaseOperation();
            return playerGameModes.get(uuid);
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static void removePlayerGameMode(UUID uuid) {
        if (!initialized) {
            return;
        }

        dataLock.writeLock().lock();
        try {
            GameType removed = playerGameModes.remove(uuid);
            if (removed != null) {
                saveGameModesAsync();
                SystemMonitor.recordDatabaseOperation();
            }
        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static int getRegisteredPlayerCount() {
        if (!initialized) {
            return 0;
        }

        dataLock.readLock().lock();
        try {
            return playerPasswords.size();
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static Map<UUID, String> getAllPlayerPasswords() {
        if (!initialized) {
            return Collections.emptyMap();
        }

        dataLock.readLock().lock();
        try {
            return new HashMap<>(playerPasswords);
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static String createBackup() throws IOException {
        if (!initialized) {
            throw new IllegalStateException("DataManager not initialized");
        }

        dataLock.readLock().lock();
        try {
            savePlayerData();
            saveGameModes();

            String timestamp = LocalDateTime.now().format(BACKUP_TIMESTAMP);
            String backupFileName = String.format("larbaco_auth_backup_%s.zip", timestamp);
            Path backupPath = Paths.get(DATA_DIR, BACKUP_DIR, backupFileName);

            Files.createDirectories(backupPath.getParent());

            try (ZipOutputStream zipOut = new ZipOutputStream(Files.newOutputStream(backupPath))) {
                addFileToZip(zipOut, Paths.get(DATA_DIR, PLAYERS_FILE), PLAYERS_FILE);
                addFileToZip(zipOut, Paths.get(DATA_DIR, GAME_MODES_FILE), GAME_MODES_FILE);

                String metadata = createBackupMetadata();
                ZipEntry metadataEntry = new ZipEntry("backup_metadata.json");
                zipOut.putNextEntry(metadataEntry);
                zipOut.write(metadata.getBytes());
                zipOut.closeEntry();
            }

            lastBackupTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Created backup: {}", backupPath);
            AuthLogger.logSystemEvent("DATABASE_BACKUP", "Backup created: " + backupFileName);

            cleanupOldBackups();

            return backupPath.toString();

        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static void optimizeDatabase() {
        if (!initialized) {
            throw new IllegalStateException("DataManager not initialized");
        }

        dataLock.writeLock().lock();
        try {
            long beforeSize = getDatabaseSize();

            playerPasswords.entrySet().removeIf(entry ->
                    entry.getKey() == null || entry.getValue() == null || entry.getValue().trim().isEmpty());

            playerGameModes.entrySet().removeIf(entry ->
                    entry.getKey() == null || entry.getValue() == null);

            savePlayerData();
            saveGameModes();

            long afterSize = getDatabaseSize();
            long savedBytes = beforeSize - afterSize;

            lastOptimizationTime = System.currentTimeMillis();

            LarbacoAuthMain.LOGGER.info("Database optimized - saved {} bytes", savedBytes);
            AuthLogger.logSystemEvent("DATABASE_OPTIMIZE",
                    String.format("Optimized database, saved %d bytes", savedBytes));

        } finally {
            dataLock.writeLock().unlock();
        }
    }

    public static DatabaseVerification verifyIntegrity() {
        if (!initialized) {
            return new DatabaseVerification(false, 0, 0, 0,
                    List.of("DataManager not initialized"), Collections.emptyMap());
        }

        dataLock.readLock().lock();
        try {
            List<String> issues = new ArrayList<>();
            Map<String, Object> details = new HashMap<>();
            int totalRecords = 0;
            int validRecords = 0;
            int corruptedRecords = 0;

            totalRecords += playerPasswords.size();
            for (Map.Entry<UUID, String> entry : playerPasswords.entrySet()) {
                if (entry.getKey() == null) {
                    issues.add("Player entry with null UUID");
                    corruptedRecords++;
                } else if (entry.getValue() == null || entry.getValue().trim().isEmpty()) {
                    issues.add("Player " + entry.getKey() + " has null or empty password hash");
                    corruptedRecords++;
                } else if (!entry.getValue().startsWith("$2")) {
                    issues.add("Player " + entry.getKey() + " has invalid BCrypt hash format");
                    corruptedRecords++;
                } else {
                    validRecords++;
                }
            }

            totalRecords += playerGameModes.size();
            for (Map.Entry<UUID, GameType> entry : playerGameModes.entrySet()) {
                if (entry.getKey() == null) {
                    issues.add("Game mode entry with null UUID");
                    corruptedRecords++;
                } else if (entry.getValue() == null) {
                    issues.add("Player " + entry.getKey() + " has null game mode");
                    corruptedRecords++;
                } else {
                    validRecords++;
                }
            }

            Path playersFile = Paths.get(DATA_DIR, PLAYERS_FILE);
            Path gameModesFile = Paths.get(DATA_DIR, GAME_MODES_FILE);

            if (!Files.exists(playersFile)) {
                issues.add("Players data file does not exist");
            } else {
                details.put("playersFileSize", getFileSize(playersFile));
            }

            if (!Files.exists(gameModesFile)) {
                issues.add("Game modes data file does not exist");
            } else {
                details.put("gameModesFileSize", getFileSize(gameModesFile));
            }

            details.put("playerPasswords", playerPasswords.size());
            details.put("playerGameModes", playerGameModes.size());
            details.put("lastBackup", lastBackupTime);
            details.put("lastOptimization", lastOptimizationTime);

            boolean isValid = issues.isEmpty() && corruptedRecords == 0;

            LarbacoAuthMain.LOGGER.info("Database integrity check completed - Valid: {}, Issues: {}",
                    isValid, issues.size());

            return new DatabaseVerification(isValid, totalRecords, validRecords, corruptedRecords, issues, details);

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during integrity verification: {}", e.getMessage(), e);
            return new DatabaseVerification(false, 0, 0, 0,
                    List.of("Verification failed: " + e.getMessage()), Collections.emptyMap());
        } finally {
            dataLock.readLock().unlock();
        }
    }

    public static long getDatabaseSize() {
        try {
            long totalSize = 0;

            Path playersFile = Paths.get(DATA_DIR, PLAYERS_FILE);
            if (Files.exists(playersFile)) {
                totalSize += Files.size(playersFile);
            }

            Path gameModesFile = Paths.get(DATA_DIR, GAME_MODES_FILE);
            if (Files.exists(gameModesFile)) {
                totalSize += Files.size(gameModesFile);
            }

            return totalSize;

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.warn("Error calculating database size: {}", e.getMessage());
            return 0;
        }
    }

    public static String getDataDirectory() {
        return DATA_DIR;
    }

    public static BackupStatistics getBackupStatistics() {
        try {
            Path backupDir = Paths.get(DATA_DIR, BACKUP_DIR);
            if (!Files.exists(backupDir)) {
                return new BackupStatistics(0, 0, 0, null);
            }

            List<Path> backups = Files.list(backupDir)
                    .filter(path -> path.toString().endsWith(".zip"))
                    .sorted((a, b) -> {
                        try {
                            return Long.compare(Files.getLastModifiedTime(b).toMillis(),
                                    Files.getLastModifiedTime(a).toMillis());
                        } catch (IOException e) {
                            return 0;
                        }
                    })
                    .toList();

            long totalSize = backups.stream()
                    .mapToLong(DataManager::getFileSize)
                    .sum();

            String latestBackup = backups.isEmpty() ? null : backups.get(0).getFileName().toString();

            return new BackupStatistics(backups.size(), totalSize, lastBackupTime, latestBackup);

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.warn("Error getting backup statistics: {}", e.getMessage());
            return new BackupStatistics(0, 0, 0, null);
        }
    }

    // Private helper methods

    private static void createDataDirectory() throws IOException {
        Path dataPath = Paths.get(DATA_DIR);
        if (!Files.exists(dataPath)) {
            Files.createDirectories(dataPath);
            LarbacoAuthMain.LOGGER.info("Created data directory: {}", DATA_DIR);
        }
    }

    private static void createBackupDirectory() throws IOException {
        Path backupPath = Paths.get(DATA_DIR, BACKUP_DIR);
        if (!Files.exists(backupPath)) {
            Files.createDirectories(backupPath);
            LarbacoAuthMain.LOGGER.debug("Created backup directory: {}", backupPath);
        }
    }

    private static void loadPlayerData() {
        Path filePath = Paths.get(DATA_DIR, PLAYERS_FILE);
        if (!Files.exists(filePath)) {
            LarbacoAuthMain.LOGGER.info("No existing player data file found");
            return;
        }

        try (FileReader reader = new FileReader(filePath.toFile())) {
            Type type = new TypeToken<Map<String, String>>(){}.getType();
            Map<String, String> data = gson.fromJson(reader, type);

            if (data != null) {
                playerPasswords.clear();
                int validEntries = 0;
                int invalidEntries = 0;

                for (Map.Entry<String, String> entry : data.entrySet()) {
                    try {
                        UUID uuid = UUID.fromString(entry.getKey());
                        String hash = entry.getValue();

                        if (hash != null && !hash.trim().isEmpty()) {
                            playerPasswords.put(uuid, hash);
                            validEntries++;
                        } else {
                            invalidEntries++;
                            LarbacoAuthMain.LOGGER.warn("Skipping player {} with empty password hash", entry.getKey());
                        }
                    } catch (IllegalArgumentException e) {
                        invalidEntries++;
                        LarbacoAuthMain.LOGGER.warn("Invalid UUID in player data: {}", entry.getKey());
                    }
                }

                LarbacoAuthMain.LOGGER.info("Loaded {} valid player entries, skipped {} invalid",
                        validEntries, invalidEntries);
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load player data: {}", e.getMessage(), e);
            SystemMonitor.updateComponentHealth("Database", false, "Failed to load player data: " + e.getMessage());
        }
    }

    private static void savePlayerData() {
        Path filePath = Paths.get(DATA_DIR, PLAYERS_FILE);
        Map<String, String> data = new HashMap<>();

        for (Map.Entry<UUID, String> entry : playerPasswords.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                data.put(entry.getKey().toString(), entry.getValue());
            }
        }

        try (FileWriter writer = new FileWriter(filePath.toFile())) {
            gson.toJson(data, writer);
            LarbacoAuthMain.LOGGER.debug("Saved player data: {} entries", data.size());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to save player data: {}", e.getMessage(), e);
            SystemMonitor.updateComponentHealth("Database", false, "Failed to save player data: " + e.getMessage());
        }
    }

    private static void loadGameModes() {
        Path filePath = Paths.get(DATA_DIR, GAME_MODES_FILE);
        if (!Files.exists(filePath)) {
            LarbacoAuthMain.LOGGER.info("No existing game mode data file found");
            return;
        }

        try (FileReader reader = new FileReader(filePath.toFile())) {
            Type type = new TypeToken<Map<String, String>>(){}.getType();
            Map<String, String> data = gson.fromJson(reader, type);

            if (data != null) {
                playerGameModes.clear();
                int validEntries = 0;
                int invalidEntries = 0;

                for (Map.Entry<String, String> entry : data.entrySet()) {
                    try {
                        UUID uuid = UUID.fromString(entry.getKey());
                        GameType gameType = GameType.valueOf(entry.getValue());
                        playerGameModes.put(uuid, gameType);
                        validEntries++;
                    } catch (Exception e) {
                        invalidEntries++;
                        LarbacoAuthMain.LOGGER.warn("Invalid game mode data: {} -> {}", entry.getKey(), entry.getValue());
                    }
                }

                LarbacoAuthMain.LOGGER.info("Loaded {} valid game mode entries, skipped {} invalid",
                        validEntries, invalidEntries);
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load game mode data: {}", e.getMessage(), e);
        }
    }

    private static void saveGameModes() {
        Path filePath = Paths.get(DATA_DIR, GAME_MODES_FILE);
        Map<String, String> data = new HashMap<>();

        for (Map.Entry<UUID, GameType> entry : playerGameModes.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                data.put(entry.getKey().toString(), entry.getValue().name());
            }
        }

        try (FileWriter writer = new FileWriter(filePath.toFile())) {
            gson.toJson(data, writer);
            LarbacoAuthMain.LOGGER.debug("Saved game mode data: {} entries", data.size());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to save game mode data: {}", e.getMessage(), e);
        }
    }

    private static void savePlayerDataAsync() {
        new Thread(() -> savePlayerData(), "LarbacoAuth-SavePlayers").start();
    }

    private static void saveGameModesAsync() {
        new Thread(() -> saveGameModes(), "LarbacoAuth-SaveGameModes").start();
    }

    private static void addFileToZip(ZipOutputStream zipOut, Path filePath, String zipEntryName) throws IOException {
        if (!Files.exists(filePath)) {
            return;
        }

        ZipEntry zipEntry = new ZipEntry(zipEntryName);
        zipOut.putNextEntry(zipEntry);

        Files.copy(filePath, zipOut);
        zipOut.closeEntry();
    }

    private static String createBackupMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", System.currentTimeMillis());
        metadata.put("version", LarbacoAuthMain.getVersion());
        metadata.put("playerCount", playerPasswords.size());
        metadata.put("gameModeCount", playerGameModes.size());
        metadata.put("databaseSize", getDatabaseSize());

        return gson.toJson(metadata);
    }

    private static void cleanupOldBackups() {
        try {
            Path backupDir = Paths.get(DATA_DIR, BACKUP_DIR);
            if (!Files.exists(backupDir)) {
                return;
            }

            List<Path> backups = Files.list(backupDir)
                    .filter(path -> path.toString().endsWith(".zip"))
                    .sorted((a, b) -> {
                        try {
                            return Long.compare(Files.getLastModifiedTime(b).toMillis(),
                                    Files.getLastModifiedTime(a).toMillis());
                        } catch (IOException e) {
                            return 0;
                        }
                    })
                    .toList();

            for (int i = 10; i < backups.size(); i++) {
                try {
                    Files.delete(backups.get(i));
                    LarbacoAuthMain.LOGGER.debug("Deleted old backup: {}", backups.get(i).getFileName());
                } catch (IOException e) {
                    LarbacoAuthMain.LOGGER.warn("Failed to delete old backup {}: {}",
                            backups.get(i).getFileName(), e.getMessage());
                }
            }

        } catch (IOException e) {
            LarbacoAuthMain.LOGGER.warn("Error cleaning up old backups: {}", e.getMessage());
        }
    }

    private static long getFileSize(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return 0;
        }
    }

    public record DatabaseVerification(
            boolean isValid,
            int totalRecords,
            int validRecords,
            int corruptedRecords,
            List<String> issues,
            Map<String, Object> details
    ) {}

    public record BackupStatistics(
            int backupCount,
            long totalBackupSize,
            long lastBackupTime,
            String latestBackupName
    ) {}
}