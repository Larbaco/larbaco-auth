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

import com.google.gson.Gson;
import com.larbaco.larbaco_auth.commands.*;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.monitoring.SystemMonitor;
import com.larbaco.larbaco_auth.storage.TranslationTemplateManager;
import com.mojang.logging.LogUtils;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import net.neoforged.fml.event.lifecycle.FMLCommonSetupEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.server.ServerStartingEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import org.slf4j.Logger;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main class for LarbacoAuth - handles mod initialization, authentication state,
 * and system lifecycle management.
 *
 * Thread-safe and follows proper shutdown procedures.
 */
@Mod(LarbacoAuthMain.MODID)
public class LarbacoAuthMain {
    public static final String MODID = "larbaco_auth";
    public static final Logger LOGGER = LogUtils.getLogger();

    // Mod metadata
    private static final String MOD_VERSION = "1.0.0";
    private static final long STARTUP_TIME = System.currentTimeMillis();

    // Core state management
    private static final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final AtomicBoolean shutdownInProgress = new AtomicBoolean(false);

    // Translation management
    private static final Map<String, String> translations = new ConcurrentHashMap<>();
    private static final Gson gson = new Gson();
    private static String currentLanguage = "en_us";

    /**
     * Mod constructor - sets up event listeners and configuration
     */
    public LarbacoAuthMain(IEventBus modEventBus, ModContainer modContainer) {
        try {
            // Register configuration
            modContainer.registerConfig(ModConfig.Type.COMMON, Config.SPEC);

            // Register mod lifecycle events
            modEventBus.addListener(this::onModSetup);

            // Register server events
            NeoForge.EVENT_BUS.addListener(this::registerCommands);
            NeoForge.EVENT_BUS.addListener(LarbacoAuthMain::onServerStarting);
            NeoForge.EVENT_BUS.addListener(LarbacoAuthMain::onServerStopping);

            LOGGER.info("LarbacoAuth v{} constructor completed", MOD_VERSION);

        } catch (Exception e) {
            LOGGER.error("Failed to initialize LarbacoAuth: {}", e.getMessage(), e);
            throw new RuntimeException("LarbacoAuth initialization failed", e);
        }
    }

    // ==================== MOD LIFECYCLE ====================

    /**
     * Mod setup phase - initializes core systems
     */
    private void onModSetup(final FMLCommonSetupEvent event) {
        event.enqueueWork(() -> {
            LOGGER.info("Starting LarbacoAuth initialization...");

            try {
                validateConfiguration();
                initializeCoreComponents();
                initializeMonitoringSystems();

                initialized.set(true);
                logSuccessfulInitialization();

            } catch (Exception e) {
                handleInitializationFailure(e);
            }
        });
    }

    private void validateConfiguration() {
        if (Config.SPEC == null) {
            throw new IllegalStateException("Configuration not properly loaded");
        }

        if (!Config.validate()) {
            throw new IllegalStateException("Configuration validation failed");
        }
    }

    private void initializeCoreComponents() {
        loadTranslations();

        // Create language template files if they don't exist
        String langDir = "config/" + MODID + "/lang";
        try {
            java.nio.file.Files.createDirectories(java.nio.file.Paths.get(langDir));
            TranslationTemplateManager.createLanguageFiles(langDir);
        } catch (Exception e) {
            LOGGER.warn("Could not create language template files: {}", e.getMessage());
        }

        com.larbaco.larbaco_auth.storage.DataManager.initialize();
    }

    private void initializeMonitoringSystems() {
        AuthLogger.initialize();

        // Clean up any corrupted log files from previous runs
        try {
            AuthLogger.cleanupCorruptedLogFile();
        } catch (Exception e) {
            LOGGER.warn("Could not clean up corrupted log file: {}", e.getMessage());
        }

        SystemMonitor.updateComponentHealth("Authentication", true, null);
    }

    private void logSuccessfulInitialization() {
        LOGGER.info("LarbacoAuth v{} initialized successfully", MOD_VERSION);
        AuthLogger.logSystemEvent("MOD_INITIALIZED",
                String.format("LarbacoAuth v%s initialized successfully", MOD_VERSION));
    }

    private void handleInitializationFailure(Exception e) {
        LOGGER.error("LarbacoAuth initialization failed: {}", e.getMessage(), e);
        SystemMonitor.updateComponentHealth("Authentication", false, e.getMessage());
        throw new RuntimeException("Mod setup failed", e);
    }

    // ==================== SERVER LIFECYCLE ====================

    @SubscribeEvent
    public static void onServerStarting(ServerStartingEvent event) {
        if (!initialized.get()) {
            LOGGER.warn("Server starting but LarbacoAuth not fully initialized!");
            return;
        }

        try {
            startMonitoringIfEnabled();
            logServerStartup();

        } catch (Exception e) {
            LOGGER.error("Error during server startup: {}", e.getMessage(), e);
            SystemMonitor.updateComponentHealth("Authentication", false,
                    "Server startup error: " + e.getMessage());
        }
    }

    private static void startMonitoringIfEnabled() {
        if (Config.enableMonitoring) {
            SystemMonitor.startRealTimeMonitoring();
            LOGGER.info("Real-time monitoring started");
        }
    }

    private static void logServerStartup() {
        LOGGER.info("Authentication system ready - Max login attempts: {}", Config.maxLoginAttempts);
        AuthLogger.logSystemEvent("SERVER_STARTING",
                String.format("Server starting with LarbacoAuth v%s, max attempts: %d",
                        MOD_VERSION, Config.maxLoginAttempts));
    }

    @SubscribeEvent
    public static void onServerStopping(ServerStoppingEvent event) {
        if (!shutdownInProgress.compareAndSet(false, true)) {
            return; // Already shutting down
        }

        LOGGER.info("LarbacoAuth shutdown initiated...");

        try {
            AuthLogger.logSystemEvent("SERVER_STOPPING", "LarbacoAuth shutdown initiated");

            shutdownComponentsInOrder();

            LOGGER.info("LarbacoAuth shutdown completed successfully");

        } catch (Exception e) {
            LOGGER.error("Error during LarbacoAuth shutdown: {}", e.getMessage(), e);
        }
    }

    private static void shutdownComponentsInOrder() {
        // Phase 1: Stop monitoring
        shutdownComponent("SystemMonitor", () -> SystemMonitor.shutdown());

        // Phase 2: Session management
        shutdownComponent("AuthSessionManager",
                () -> com.larbaco.larbaco_auth.handlers.AuthSessionManager.shutdown());

        // Phase 3: Data persistence
        shutdownComponent("DataManager",
                () -> com.larbaco.larbaco_auth.storage.DataManager.shutdown());

        // Phase 4: Clean up memory
        shutdownComponent("Cleanup", LarbacoAuthMain::cleanup);

        // Phase 5: Logger (last)
        shutdownComponent("AuthLogger", () -> AuthLogger.shutdown());
    }

    private static void shutdownComponent(String componentName, Runnable shutdownTask) {
        try {
            shutdownTask.run();
            LOGGER.debug("✅ {} shutdown completed", componentName);
        } catch (Exception e) {
            LOGGER.error("❌ Error shutting down {}: {}", componentName, e.getMessage(), e);
        }
    }

    // ==================== AUTHENTICATION MANAGEMENT ====================

    /**
     * Check if a player is authenticated
     */
    public static boolean isPlayerAuthenticated(UUID uuid) {
        return uuid != null && authenticatedPlayers.contains(uuid);
    }

    /**
     * Set player authentication status with proper logging and monitoring
     */
    public static void setAuthenticated(UUID uuid, boolean status) {
        if (uuid == null || shutdownInProgress.get()) {
            return;
        }

        if (status) {
            handleAuthentication(uuid);
        } else {
            handleDeauthentication(uuid);
        }
    }

    private static void handleAuthentication(UUID uuid) {
        boolean wasAdded = authenticatedPlayers.add(uuid);
        if (wasAdded) {
            LOGGER.debug("Player {} authenticated successfully", uuid);
            SystemMonitor.recordLoginAttempt(true);

            /*try {
                String playerName = getPlayerNameFromUUID(uuid);
                AuthLogger.logAuthEvent(uuid, playerName, "LOGIN_SUCCESS", "Player authenticated successfully");
            } catch (Exception e) {
                LOGGER.debug("Could not log auth event for {}: {}", uuid, e.getMessage());
            }*/
        }
    }

    private static void handleDeauthentication(UUID uuid) {
        boolean wasRemoved = authenticatedPlayers.remove(uuid);
        LOGGER.debug("Player {} deauthenticated (was authenticated: {})", uuid, wasRemoved);
    }

    /**
     * Force authentication status update (for admin commands)
     */
    public static void forceSetAuthenticated(UUID uuid, boolean status) {
        if (uuid == null || shutdownInProgress.get()) {
            return;
        }

        if (status) {
            authenticatedPlayers.add(uuid);
        } else {
            authenticatedPlayers.remove(uuid);
        }

        LOGGER.info("Force authentication status update: {} -> {}", uuid, status);

        String action = status ? "FORCE_AUTHENTICATE" : "FORCE_DEAUTHENTICATE";
        AuthLogger.logAuthEvent(uuid, getPlayerNameFromUUID(uuid), action,
                "Authentication status force-updated by admin");
    }

    // ==================== SYSTEM INFORMATION ====================

    public static int getAuthenticatedPlayerCount() {
        return authenticatedPlayers.size();
    }

    public static boolean hasAuthenticatedPlayers() {
        return !authenticatedPlayers.isEmpty();
    }

    public static Set<UUID> getAuthenticatedPlayers() {
        return Set.copyOf(authenticatedPlayers);
    }

    public static boolean isInitialized() {
        return initialized.get() && !shutdownInProgress.get();
    }

    public static boolean isShuttingDown() {
        return shutdownInProgress.get();
    }

    public static boolean isSystemHealthy() {
        return isInitialized() &&
                com.larbaco.larbaco_auth.handlers.AuthSessionManager.isHealthy() &&
                Config.validate();
    }

    // ==================== VERSION INFORMATION ====================

    public static String getVersion() {
        return MOD_VERSION;
    }

    public static String getNeoForgeVersion() {
        try {
            return net.neoforged.fml.loading.FMLLoader.getLoadingModList()
                    .getModFileById("neoforge")
                    .versionString();
        } catch (Exception e) {
            return "Unknown";
        }
    }

    public static String getMinecraftVersion() {
        try {
            return net.minecraft.SharedConstants.getCurrentVersion().getName();
        } catch (Exception e) {
            return "1.21.1";
        }
    }

    public static String getLogLevel() {
        return LOGGER.isDebugEnabled() ? "DEBUG" :
                LOGGER.isInfoEnabled() ? "INFO" :
                        LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
    }

    public static long getUptimeMillis() {
        return System.currentTimeMillis() - STARTUP_TIME;
    }

    // ==================== TRANSLATION MANAGEMENT ====================

    public static String getTranslation(String key, Object... args) {
        if (shutdownInProgress.get()) {
            return key; // Return key during shutdown
        }

        String translation = translations.get(key);
        if (translation == null) {
            LOGGER.warn("Missing translation for key: {} in language: {}", key, currentLanguage);
            return key;
        }

        if (args.length > 0) {
            for (Object arg : args) {
                translation = translation.replaceFirst("%s", String.valueOf(arg));
            }
        }

        return translation;
    }

    public static String getCurrentLanguage() {
        return currentLanguage;
    }

    public static void loadTranslations() {
        if (shutdownInProgress.get()) {
            return;
        }

        LOGGER.debug("Loading translations...");

        java.util.Locale systemLocale = java.util.Locale.getDefault();
        String langCode = systemLocale.getLanguage().equals("pt") ? "pt_br" : "en_us";
        currentLanguage = langCode;

        LOGGER.debug("Loading language: {} (system locale: {})", langCode, systemLocale);

        String configPath = "config/" + MODID + "/lang/" + langCode + ".json";
        String resourcePath = "/assets/" + MODID + "/lang/" + langCode + ".json";

        if (loadTranslationsFromFile(configPath)) {
            LOGGER.debug("Loaded translations from config file");
            return;
        }

        if (loadTranslationsFromResource(resourcePath)) {
            LOGGER.debug("Loaded translations from mod resources");
            return;
        }

        if (!langCode.equals("en_us")) {
            LOGGER.debug("Falling back to English...");
            currentLanguage = "en_us";
            loadTranslations();
        }
    }

    private static boolean loadTranslationsFromFile(String filePath) {
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(filePath);
            if (!java.nio.file.Files.exists(path)) return false;

            try (java.io.FileReader reader = new java.io.FileReader(path.toFile())) {
                com.google.gson.reflect.TypeToken<java.util.Map<String, String>> typeToken =
                        new com.google.gson.reflect.TypeToken<java.util.Map<String, String>>() {};
                java.util.Map<String, String> langMap = gson.fromJson(reader, typeToken.getType());

                if (langMap != null) {
                    translations.clear();
                    translations.putAll(langMap);
                    LOGGER.debug("Loaded {} translations from config file", translations.size());
                    return true;
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error loading translations from file {}: {}", filePath, e.getMessage());
        }
        return false;
    }

    private static boolean loadTranslationsFromResource(String resourcePath) {
        try {
            var inputStream = LarbacoAuthMain.class.getResourceAsStream(resourcePath);
            if (inputStream == null) return false;

            String content = new String(inputStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            com.google.gson.reflect.TypeToken<java.util.Map<String, String>> typeToken =
                    new com.google.gson.reflect.TypeToken<java.util.Map<String, String>>() {};
            java.util.Map<String, String> langMap = gson.fromJson(content, typeToken.getType());

            if (langMap != null) {
                translations.clear();
                translations.putAll(langMap);
                LOGGER.debug("Loaded {} translations from mod resources", translations.size());
                inputStream.close();
                return true;
            }
            inputStream.close();
        } catch (Exception e) {
            LOGGER.error("Error loading translations from resource {}: {}", resourcePath, e.getMessage());
        }
        return false;
    }

    // ==================== COMMAND REGISTRATION ====================

    private void registerCommands(RegisterCommandsEvent event) {
        try {
            var dispatcher = event.getDispatcher();

            // Core authentication commands
            RegisterCommand.register(dispatcher);
            LoginCommand.register(dispatcher);
            AuthCommand.register(dispatcher);

            // User management commands
            ChangePasswordCommand.register(dispatcher);
            DisconnectCommand.register(dispatcher);

            // Administrative commands
            AuthAdminCommand.register(dispatcher);

            LOGGER.debug("All authentication commands registered successfully");
            AuthLogger.logSystemEvent("COMMANDS_REGISTERED", "All authentication commands registered");

        } catch (Exception e) {
            LOGGER.error("Failed to register commands: {}", e.getMessage(), e);
            SystemMonitor.updateComponentHealth("Authentication", false,
                    "Command registration failed: " + e.getMessage());
        }
    }

    // ==================== CLIENT EVENTS ====================

    @EventBusSubscriber(modid = MODID, bus = EventBusSubscriber.Bus.MOD, value = Dist.CLIENT)
    public static class ClientModEvents {
        @SubscribeEvent
        public static void onClientSetup(FMLClientSetupEvent event) {
            LOGGER.debug("LarbacoAuth client setup completed");
        }
    }

    // ==================== UTILITY METHODS ====================

    private static void cleanup() {
        int authenticatedCount = authenticatedPlayers.size();
        authenticatedPlayers.clear();

        // Clear translations
        int translationCount = translations.size();
        translations.clear();

        initialized.set(false);

        LOGGER.info("LarbacoAuth cleanup completed - cleared {} authenticated players, {} translations",
                authenticatedCount, translationCount);
    }

    /**
     * Helper method to get player name from UUID (simplified version)
     */
    private static String getPlayerNameFromUUID(UUID uuid) {
        return uuid != null ? uuid.toString().substring(0, 8) : "Unknown";
    }
}