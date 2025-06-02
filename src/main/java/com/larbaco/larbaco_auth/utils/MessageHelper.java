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

    /**
     * Send a clickable token message that formats the token correctly
     */
    public static void sendTokenMessage(ServerPlayer player, String messageKey, String token) {
        try {
            // Get the base message template
            String baseMessage = LarbacoAuthMain.getTranslation(messageKey);

            // Replace %s with the actual token for display
            String displayMessage = baseMessage.replace("%s", token);

            // Create the /auth command
            String authCommand = "/auth " + token;

            // Get hover text
            String hoverKey = "command.larbaco_auth.token.click_hint";
            String hoverText = LarbacoAuthMain.getTranslation(hoverKey);
            if (hoverText.equals(hoverKey)) {
                hoverText = "§aClick to insert command";
            }

            // Find where the token appears in the message
            int tokenStart = displayMessage.indexOf(token);
            if (tokenStart == -1) {
                // Fallback if token not found in message
                sendTranslatedInternal(player, messageKey, token);
                return;
            }

            // Split the message into parts
            String beforeToken = displayMessage.substring(0, tokenStart);
            String afterToken = displayMessage.substring(tokenStart + token.length());

            // Build the clickable message
            Component message = Component.literal(beforeToken)
                    .append(Component.literal(token)
                            .setStyle(Style.EMPTY
                                    .withColor(0x55FFFF) // Cyan color for the token
                                    .withBold(true)
                                    .withUnderlined(true)
                                    .withClickEvent(new ClickEvent(ClickEvent.Action.SUGGEST_COMMAND, authCommand))
                                    .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT,
                                            Component.literal(hoverText)))))
                    .append(Component.literal(afterToken));

            player.sendSystemMessage(message);

            if (DEBUG_ENABLED) {
                LarbacoAuthMain.LOGGER.debug("Sent clickable token message to: {} with command: {}",
                        player.getName().getString(), authCommand);
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error sending token message to {}: {}",
                    player.getName().getString(), e.getMessage(), e);

            // Fallback to regular message
            sendTranslatedInternal(player, messageKey, token);
        }
    }

    /**
     * Send a clickable command message
     */
    public static void sendClickableCommand(ServerPlayer player, String message, String command, String hoverText) {
        try {
            Component clickableMessage = Component.literal(message)
                    .setStyle(Style.EMPTY
                            .withColor(0x55FF55) // Green color
                            .withUnderlined(true)
                            .withClickEvent(new ClickEvent(ClickEvent.Action.SUGGEST_COMMAND, command))
                            .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT,
                                    Component.literal(hoverText != null ? hoverText : "§aClick to insert command"))));

            player.sendSystemMessage(clickableMessage);

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error sending clickable command: {}", e.getMessage());
            sendLiteral(player, message);
        }
    }

    /**
     * Send a formatted authentication step message
     */
    public static void sendAuthStepMessage(ServerPlayer player, String stepMessage, String token) {
        try {
            String authCommand = "/auth " + token;

            Component message = Component.literal(stepMessage + " ")
                    .append(Component.literal(authCommand)
                            .setStyle(Style.EMPTY
                                    .withColor(0xFFAA00) // Orange color
                                    .withBold(true)
                                    .withClickEvent(new ClickEvent(ClickEvent.Action.SUGGEST_COMMAND, authCommand))
                                    .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT,
                                            Component.literal("§aClick to run authentication command")))));

            player.sendSystemMessage(message);

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error sending auth step message: {}", e.getMessage());
            sendLiteral(player, stepMessage + " /auth " + token);
        }
    }

    public static String getTranslation(String key, Object... args) {
        return LarbacoAuthMain.getTranslation(key, args);
    }

    public static boolean hasTranslation(String key) {
        String translation = LarbacoAuthMain.getTranslation(key);
        return !translation.equals(key);
    }

    /**
     * Enable or disable debug logging
     */
    public static void setDebugEnabled(boolean enabled) {
        // This could be made configurable if needed
        LarbacoAuthMain.LOGGER.info("MessageHelper debug logging: {}", enabled ? "enabled" : "disabled");
    }
}