package com.larbaco.larbaco_auth.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import net.minecraft.world.level.GameType;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class DataManager {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final String DATA_DIR = "config/larbaco_auth";
    private static final String PLAYERS_FILE = "players.json";
    private static final String GAME_MODES_FILE = "game_modes.json";

    private static final Map<UUID, String> playerPasswords = new ConcurrentHashMap<>();
    private static final Map<UUID, GameType> playerGameModes = new ConcurrentHashMap<>();

    public static void initialize() {
        try {
            createDataDirectory();
            loadPlayerData();
            loadGameModes();
            LarbacoAuthMain.LOGGER.info("DataManager initialized successfully");
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to initialize DataManager: {}", e.getMessage(), e);
        }
    }

    public static void shutdown() {
        try {
            savePlayerData();
            saveGameModes();
            LarbacoAuthMain.LOGGER.info("DataManager shutdown - all data saved");
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during DataManager shutdown: {}", e.getMessage(), e);
        }
    }

    private static void createDataDirectory() throws IOException {
        Path dataPath = Paths.get(DATA_DIR);
        if (!Files.exists(dataPath)) {
            Files.createDirectories(dataPath);
            LarbacoAuthMain.LOGGER.info("Created data directory: {}", DATA_DIR);
        }
    }

    public static void registerPlayer(UUID uuid, String passwordHash) {
        playerPasswords.put(uuid, passwordHash);
        savePlayerDataAsync();
        LarbacoAuthMain.LOGGER.debug("Registered player: {}", uuid);
    }

    public static void unregisterPlayer(UUID uuid) {
        playerPasswords.remove(uuid);
        savePlayerDataAsync();
        LarbacoAuthMain.LOGGER.debug("Unregistered player: {}", uuid);
    }

    public static boolean isPlayerRegistered(UUID uuid) {
        return playerPasswords.containsKey(uuid);
    }

    public static String getPlayerPasswordHash(UUID uuid) {
        return playerPasswords.get(uuid);
    }

    public static void setPlayerGameMode(UUID uuid, GameType gameType) {
        playerGameModes.put(uuid, gameType);
        saveGameModesAsync();
    }

    public static GameType getPlayerGameMode(UUID uuid) {
        return playerGameModes.get(uuid);
    }

    public static void removePlayerGameMode(UUID uuid) {
        playerGameModes.remove(uuid);
        saveGameModesAsync();
    }

    public static int getRegisteredPlayerCount() {
        return playerPasswords.size();
    }

    public static Map<UUID, String> getAllPlayerPasswords() {
        return new HashMap<>(playerPasswords);
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
                for (Map.Entry<String, String> entry : data.entrySet()) {
                    try {
                        UUID uuid = UUID.fromString(entry.getKey());
                        playerPasswords.put(uuid, entry.getValue());
                    } catch (IllegalArgumentException e) {
                        LarbacoAuthMain.LOGGER.warn("Invalid UUID in player data: {}", entry.getKey());
                    }
                }
                LarbacoAuthMain.LOGGER.info("Loaded {} registered players", playerPasswords.size());
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load player data: {}", e.getMessage(), e);
        }
    }

    private static void savePlayerData() {
        Path filePath = Paths.get(DATA_DIR, PLAYERS_FILE);
        Map<String, String> data = new HashMap<>();

        for (Map.Entry<UUID, String> entry : playerPasswords.entrySet()) {
            data.put(entry.getKey().toString(), entry.getValue());
        }

        try (FileWriter writer = new FileWriter(filePath.toFile())) {
            gson.toJson(data, writer);
            LarbacoAuthMain.LOGGER.debug("Saved player data: {} entries", data.size());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to save player data: {}", e.getMessage(), e);
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
                for (Map.Entry<String, String> entry : data.entrySet()) {
                    try {
                        UUID uuid = UUID.fromString(entry.getKey());
                        GameType gameType = GameType.valueOf(entry.getValue());
                        playerGameModes.put(uuid, gameType);
                    } catch (Exception e) {
                        LarbacoAuthMain.LOGGER.warn("Invalid game mode data: {} -> {}", entry.getKey(), entry.getValue());
                    }
                }
                LarbacoAuthMain.LOGGER.info("Loaded {} player game modes", playerGameModes.size());
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to load game mode data: {}", e.getMessage(), e);
        }
    }

    private static void saveGameModes() {
        Path filePath = Paths.get(DATA_DIR, GAME_MODES_FILE);
        Map<String, String> data = new HashMap<>();

        for (Map.Entry<UUID, GameType> entry : playerGameModes.entrySet()) {
            data.put(entry.getKey().toString(), entry.getValue().name());
        }

        try (FileWriter writer = new FileWriter(filePath.toFile())) {
            gson.toJson(data, writer);
            LarbacoAuthMain.LOGGER.debug("Saved game mode data: {} entries", data.size());
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to save game mode data: {}", e.getMessage(), e);
        }
    }

    private static void savePlayerDataAsync() {
        new Thread(() -> savePlayerData()).start();
    }

    private static void saveGameModesAsync() {
        new Thread(() -> saveGameModes()).start();
    }
}