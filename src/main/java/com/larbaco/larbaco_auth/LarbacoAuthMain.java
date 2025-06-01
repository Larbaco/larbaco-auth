package com.larbaco.larbaco_auth;

import com.larbaco.larbaco_auth.commands.AuthCommand;
import com.larbaco.larbaco_auth.commands.LoginCommand;
import com.larbaco.larbaco_auth.commands.RegisterCommand;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import net.neoforged.fml.event.lifecycle.FMLCommonSetupEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import org.slf4j.Logger;
import com.mojang.logging.LogUtils;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.event.server.ServerStartingEvent;

import java.io.FileReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Mod(LarbacoAuthMain.MODID)
public class LarbacoAuthMain {
    public static final String MODID = "larbaco_auth";
    public static final Logger LOGGER = LogUtils.getLogger();

    private static final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private static final Map<String, String> translations = new ConcurrentHashMap<>();
    private static final Gson gson = new Gson();
    private static String currentLanguage = "en_us";
    private static volatile boolean isInitialized = false;

    public static boolean isPlayerAuthenticated(UUID uuid) {
        return authenticatedPlayers.contains(uuid);
    }

    public static void setAuthenticated(UUID uuid, boolean status) {
        if(status) {
            boolean wasAdded = authenticatedPlayers.add(uuid);
            if (wasAdded) {
                LOGGER.debug("Player {} authenticated successfully", uuid);
            }
        } else {
            boolean wasRemoved = authenticatedPlayers.remove(uuid);
            LOGGER.debug("Player {} deauthenticated (was authenticated: {})", uuid, wasRemoved);
        }
    }

    public static int getAuthenticatedPlayerCount() {
        return authenticatedPlayers.size();
    }

    public static boolean hasAuthenticatedPlayers() {
        return !authenticatedPlayers.isEmpty();
    }

    public static boolean isInitialized() {
        return isInitialized;
    }

    public static String getTranslation(String key, Object... args) {
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

    public LarbacoAuthMain(IEventBus modEventBus, ModContainer modContainer) {
        try {
            modContainer.registerConfig(ModConfig.Type.COMMON, Config.SPEC);

            modEventBus.addListener(this::onModSetup);

            NeoForge.EVENT_BUS.addListener(this::registerCommands);
            NeoForge.EVENT_BUS.addListener(LarbacoAuthMain::onServerStarting);

            LOGGER.info("Larbaco Auth initialized");

        } catch (Exception e) {
            LOGGER.error("Failed to initialize Larbaco Auth: {}", e.getMessage(), e);
            throw new RuntimeException("Larbaco Auth initialization failed", e);
        }
    }

    private void onModSetup(final FMLCommonSetupEvent event) {
        event.enqueueWork(() -> {
            LOGGER.info("=== MOD SETUP PHASE ===");

            if (Config.SPEC == null) {
                LOGGER.error("Configuration not properly loaded!");
                return;
            }

            loadTranslations();
            com.larbaco.larbaco_auth.storage.DataManager.initialize();

            isInitialized = true;
            LOGGER.info("Larbaco Auth common setup completed successfully");
            LOGGER.info("======================");
        });
    }

    private void debugResourceLoading() {
        LOGGER.info("=== RESOURCE LOADING DEBUG ===");

        String[] langFiles = {"en_us.json", "pt_br.json"};

        for (String langFile : langFiles) {
            String resourcePath = "/assets/" + MODID + "/lang/" + langFile;
            LOGGER.info("Checking resource: {}", resourcePath);

            try {
                var resource = getClass().getResourceAsStream(resourcePath);
                if (resource != null) {
                    LOGGER.info("✅ Found language file: {}", langFile);
                    resource.close();
                } else {
                    LOGGER.error("❌ Language file NOT FOUND: {}", langFile);
                }
            } catch (Exception e) {
                LOGGER.error("❌ Error checking language file {}: {}", langFile, e.getMessage());
            }
        }

        try {
            var modResource = getClass().getResource("/assets/" + MODID + "/");
            if (modResource != null) {
                LOGGER.info("✅ Mod assets directory found: {}", modResource);
            } else {
                LOGGER.error("❌ Mod assets directory NOT FOUND: /assets/{}/", MODID);
            }
        } catch (Exception e) {
            LOGGER.error("❌ Error checking mod assets: {}", e.getMessage());
        }

        LOGGER.info("===============================");
    }

    private void registerLanguageProviders() {
        LOGGER.info("=== REGISTERING LANGUAGE PROVIDERS ===");

        try {
            LOGGER.info("Attempting to register language providers for mod: {}", MODID);

            registerTranslations();

            LOGGER.info("Language provider registration completed");
        } catch (Exception e) {
            LOGGER.error("Failed to register language providers: {}", e.getMessage(), e);
        }

        LOGGER.info("=====================================");
    }

    private void registerTranslations() {
        LOGGER.info("Manual translation registration starting...");

        String[] langCodes = {"en_us", "pt_br"};

        for (String langCode : langCodes) {
            try {
                String resourcePath = "/assets/" + MODID + "/lang/" + langCode + ".json";
                var inputStream = getClass().getResourceAsStream(resourcePath);

                if (inputStream != null) {
                    String content = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
                    LOGGER.info("Language file {} content length: {} characters", langCode, content.length());
                    LOGGER.info("First 100 chars of {}: {}", langCode, content.substring(0, Math.min(100, content.length())));

                    if (content.contains("command.larbaco_auth.register.prompt")) {
                        LOGGER.info("✅ {} contains required translation keys", langCode);
                    } else {
                        LOGGER.warn("❌ {} missing required translation keys", langCode);
                    }

                    inputStream.close();
                }
            } catch (Exception e) {
                LOGGER.error("Error reading language file {}: {}", langCode, e.getMessage());
            }
        }
    }

    public static void loadTranslations() {
        LOGGER.debug("=== MANUAL TRANSLATION LOADING ===");

        Locale systemLocale = Locale.getDefault();
        String langCode = systemLocale.getLanguage().equals("pt") ? "pt_br" : "en_us";
        currentLanguage = langCode;

        LOGGER.debug("Loading language: {} (system locale: {})", langCode, systemLocale);

        String configPath = "config/larbaco_auth/lang/" + langCode + ".json";
        String resourcePath = "/assets/" + MODID + "/lang/" + langCode + ".json";

        if (loadTranslationsFromFile(configPath)) {
            LOGGER.debug("✅ Loaded translations from config file");
            return;
        }

        if (loadTranslationsFromResource(resourcePath)) {
            LOGGER.debug("✅ Loaded translations from mod resources");
            return;
        }

        if (!langCode.equals("en_us")) {
            LOGGER.debug("Falling back to English...");
            currentLanguage = "en_us";
            loadTranslations();
        }

        LOGGER.debug("==================================");
    }

    private static boolean loadTranslationsFromFile(String filePath) {
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(filePath);
            if (!java.nio.file.Files.exists(path)) return false;

            try (java.io.FileReader reader = new java.io.FileReader(path.toFile())) {
                TypeToken<Map<String, String>> typeToken = new TypeToken<Map<String, String>>() {};
                Map<String, String> langMap = gson.fromJson(reader, typeToken.getType());

                if (langMap != null) {
                    translations.clear();
                    translations.putAll(langMap);
                    LOGGER.debug("✅ Loaded {} translations from config file", translations.size());
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

            String content = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            TypeToken<Map<String, String>> typeToken = new TypeToken<Map<String, String>>() {};
            Map<String, String> langMap = gson.fromJson(content, typeToken.getType());

            if (langMap != null) {
                translations.clear();
                translations.putAll(langMap);
                LOGGER.debug("✅ Loaded {} translations from mod resources", translations.size());
                inputStream.close();
                return true;
            }
            inputStream.close();
        } catch (Exception e) {
            LOGGER.error("Error loading translations from resource {}: {}", resourcePath, e.getMessage());
        }
        return false;
    }

    private void testManualTranslationSystem() {
        LOGGER.info("=== TESTING MANUAL TRANSLATION ===");
        String testKey = "command.larbaco_auth.register.prompt";
        String manualResult = getTranslation(testKey);
        LOGGER.info("Manual translation test: {} -> '{}'", testKey, manualResult);

        if (manualResult.contains("Bem-vindo")) {
            LOGGER.info("✅ Manual Portuguese translation working!");
        } else if (manualResult.contains("Welcome")) {
            LOGGER.info("✅ Manual English translation working!");
        } else {
            LOGGER.warn("❌ Manual translation not working properly");
        }
        LOGGER.info("=================================");
    }

    @SubscribeEvent
    public static void onServerStarting(ServerStartingEvent event) {
        if (!isInitialized) {
            LOGGER.warn("Server starting but mod not fully initialized!");
        }

        try {
            int maxAttempts = Config.maxLoginAttempts;
            LOGGER.info("Authentication system ready - Max login attempts: {}", maxAttempts);
        } catch (Exception e) {
            LOGGER.error("Configuration not properly loaded: {}", e.getMessage());
        }
    }

    private void registerCommands(RegisterCommandsEvent event) {
        try {
            RegisterCommand.register(event.getDispatcher());
            LoginCommand.register(event.getDispatcher());
            AuthCommand.register(event.getDispatcher());
            LOGGER.debug("All authentication commands registered successfully");
        } catch (Exception e) {
            LOGGER.error("Failed to register commands: {}", e.getMessage(), e);
        }
    }

    @EventBusSubscriber(modid = MODID, bus = EventBusSubscriber.Bus.MOD, value = Dist.CLIENT)
    public static class ClientModEvents {
        @SubscribeEvent
        public static void onClientSetup(FMLClientSetupEvent event) {
            LOGGER.debug("Larbaco Auth client setup completed");
        }
    }

    public static void cleanup() {
        authenticatedPlayers.clear();
        translations.clear();
        com.larbaco.larbaco_auth.storage.DataManager.shutdown();
        isInitialized = false;
        LOGGER.info("Larbaco Auth cleaned up successfully");
    }
}