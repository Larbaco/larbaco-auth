package com.larbaco.larbaco_auth.utils;

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.HoverEvent;
import net.minecraft.network.chat.Style;
import net.minecraft.server.level.ServerPlayer;

public class MessageHelper {
    private static final boolean DEBUG_ENABLED = false;

    private static void sendTranslatedInternal(ServerPlayer player, String key, Object... args) {
        try {
            String manualTranslation = LarbacoAuthMain.getTranslation(key, args);
            if (DEBUG_ENABLED) {
                LarbacoAuthMain.LOGGER.info("=== MANUAL TRANSLATION DEBUG ===");
                LarbacoAuthMain.LOGGER.info("Player: {}", player.getName().getString());
                LarbacoAuthMain.LOGGER.info("Key: {}", key);
                LarbacoAuthMain.LOGGER.info("Manual result: '{}'", manualTranslation);
                LarbacoAuthMain.LOGGER.info("Current language: {}", LarbacoAuthMain.getCurrentLanguage());
            }
            Component finalMessage;
            if (!manualTranslation.equals(key)) {
                finalMessage = Component.literal(manualTranslation);
                if (DEBUG_ENABLED) {
                    LarbacoAuthMain.LOGGER.info("✅ Using manual translation");
                    if (manualTranslation.contains("Bem-vindo") || manualTranslation.contains("Por favor") ||
                            manualTranslation.contains("registrado") || manualTranslation.contains("autenticado")) {
                        LarbacoAuthMain.LOGGER.info("🇧🇷 Sending Portuguese message");
                    } else if (manualTranslation.contains("Welcome") || manualTranslation.contains("Please") ||
                            manualTranslation.contains("register") || manualTranslation.contains("authenticated")) {
                        LarbacoAuthMain.LOGGER.info("🇺🇸 Sending English message");
                    }
                }
            } else {
                finalMessage = Component.translatable(key, args);
                if (DEBUG_ENABLED) {
                    LarbacoAuthMain.LOGGER.warn("⚠️ Manual translation failed, using NeoForge fallback");
                }
            }
            player.sendSystemMessage(finalMessage);
            if (DEBUG_ENABLED) {
                LarbacoAuthMain.LOGGER.info("===============================");
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to send message with key: {} - Error: {}", key, e.getMessage(), e);
            sendLiteral(player, "§cTranslation error for key: " + key);
        }
    }

    public static void sendTranslated(ServerPlayer player, String key, Object... args) {
        sendTranslatedInternal(player, key, args);
    }

    public static void sendLiteral(ServerPlayer player, String text) {
        Component message = Component.literal(text);
        player.sendSystemMessage(message);
        if (DEBUG_ENABLED) {
            LarbacoAuthMain.LOGGER.debug("Sent literal message: '{}' to player: {}", text, player.getName().getString());
        }
    }

    public static void sendSuccess(ServerPlayer player, String key, Object... args) {
        sendTranslatedInternal(player, key, args);
    }

    public static void sendError(ServerPlayer player, String key, Object... args) {
        sendTranslatedInternal(player, key, args);
    }

    public static void sendInfo(ServerPlayer player, String key, Object... args) {
        sendTranslatedInternal(player, key, args);
    }

    public static void sendTokenMessage(ServerPlayer player, String messageKey, String token) {
        try {
            String baseMessage = LarbacoAuthMain.getTranslation(messageKey);
            String beforeToken = baseMessage.substring(0, baseMessage.indexOf("%s"));
            String afterToken = baseMessage.substring(baseMessage.indexOf("%s") + 2);

            String command = beforeToken.contains("register") || beforeToken.contains("registro") ?
                    "/register " + token : "/login " + token;

            String hoverKey = "command.larbaco_auth.token.click_hint";
            String hoverText = LarbacoAuthMain.getTranslation(hoverKey);
            if (hoverText.equals(hoverKey)) {
                hoverText = "§aClick to insert command";
            }

            Component message = Component.literal(beforeToken)
                    .append(Component.literal(token)
                            .setStyle(Style.EMPTY
                                    .withColor(0x55FF55)
                                    .withBold(true)
                                    .withClickEvent(new ClickEvent(ClickEvent.Action.SUGGEST_COMMAND, command))
                                    .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT,
                                            Component.literal(hoverText)))))
                    .append(Component.literal(afterToken));

            player.sendSystemMessage(message);

            if (DEBUG_ENABLED) {
                LarbacoAuthMain.LOGGER.debug("Sent clickable token message to: {}", player.getName().getString());
            }
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error sending token message: {}", e.getMessage());
            sendTranslatedInternal(player, messageKey, token);
        }
    }

    public static String getTranslation(String key, Object... args) {
        return LarbacoAuthMain.getTranslation(key, args);
    }

    public static boolean hasTranslation(String key) {
        String translation = LarbacoAuthMain.getTranslation(key);
        return !translation.equals(key);
    }
}