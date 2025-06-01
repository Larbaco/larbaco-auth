package com.larbaco.larbaco_auth.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.larbaco.larbaco_auth.LarbacoAuthMain;

import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class TranslationTemplateManager {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void createLanguageFiles(String langDir) {
        copyLanguageFileFromResources(langDir, "pt_br.json");
        copyLanguageFileFromResources(langDir, "en_us.json");
    }

    private static void copyLanguageFileFromResources(String langDir, String fileName) {
        Path filePath = Paths.get(langDir, fileName);
        if (Files.exists(filePath)) return;

        try {
            String resourcePath = "/assets/larbaco_auth/lang/" + fileName;
            InputStream resourceStream = TranslationTemplateManager.class.getResourceAsStream(resourcePath);

            if (resourceStream == null) {
                LarbacoAuthMain.LOGGER.warn("Resource not found: {}, creating minimal template", resourcePath);
                createMinimalTemplate(filePath, fileName);
                return;
            }

            try (InputStreamReader reader = new InputStreamReader(resourceStream, StandardCharsets.UTF_8)) {
                Type mapType = new TypeToken<Map<String, String>>(){}.getType();
                Map<String, String> translations = gson.fromJson(reader, mapType);

                if (translations != null) {
                    String content = gson.toJson(translations);
                    try (FileWriter writer = new FileWriter(filePath.toFile())) {
                        writer.write(content);
                        LarbacoAuthMain.LOGGER.info("Created language file from resources: {}", filePath);
                    }
                } else {
                    createMinimalTemplate(filePath, fileName);
                }
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to copy language file {} from resources: {}", fileName, e.getMessage());
            createMinimalTemplate(filePath, fileName);
        }
    }

    private static void createMinimalTemplate(Path filePath, String fileName) {
        try {
            Map<String, String> minimalTranslations = getMinimalTemplate(fileName);
            String content = gson.toJson(minimalTranslations);

            try (FileWriter writer = new FileWriter(filePath.toFile())) {
                writer.write(content);
                LarbacoAuthMain.LOGGER.info("Created minimal template for: {}", filePath);
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to create minimal template for {}: {}", fileName, e.getMessage());
        }
    }

    private static Map<String, String> getMinimalTemplate(String fileName) {
        Map<String, String> translations = new HashMap<>();

        if (fileName.equals("pt_br.json")) {
            translations.put("command.larbaco_auth.login.prompt", "§eBem-vindo de volta! Faça login usando §6/login§e ou §6/auth <senha>");
            translations.put("command.larbaco_auth.register.prompt", "§eBem-vindo! Registre-se usando §6/register§e ou §6/auth <senha>");
            translations.put("command.larbaco_auth.login.success", "§aLogin bem-sucedido! Bem-vindo de volta");
            translations.put("command.larbaco_auth.register.success", "§aRegistro bem-sucedido! Agora você pode fazer login");
        } else {
            translations.put("command.larbaco_auth.login.prompt", "§eWelcome back! Please login using §6/login§e or §6/auth <password>");
            translations.put("command.larbaco_auth.register.prompt", "§eWelcome! Please register using §6/register§e or §6/auth <password>");
            translations.put("command.larbaco_auth.login.success", "§aLogin successful! Welcome back");
            translations.put("command.larbaco_auth.register.success", "§aRegistration successful! You can now login");
        }

        return translations;
    }
}