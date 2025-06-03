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

package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.handlers.OperationType;
import com.larbaco.larbaco_auth.handlers.PlayerActionHandler;
import com.larbaco.larbaco_auth.handlers.SessionData;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.monitoring.SystemMonitor;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LoginCommand {
    private static final Map<UUID, Integer> failedAttempts = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> lastAttemptTime = new ConcurrentHashMap<>();
    private static final long COOLDOWN_MS = 5000;

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("login")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String password = StringArgumentType.getString(context, "password");
                            return processLoginWithPassword(player, password);
                        }))
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return initiateLogin(player);
                })
        );
    }

    private static int initiateLogin(ServerPlayer player) {
        UUID uuid = player.getUUID();

        // Check if already authenticated
        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.already_authenticated");
            return 0;
        }

        // Check if registered
        if (!RegisterCommand.isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.not_registered");
            return 0;
        }

        // Check if account is locked
        int attempts = failedAttempts.getOrDefault(uuid, 0);
        if (attempts >= Config.maxLoginAttempts) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.locked");
            return 0;
        }

        // Check cooldown
        if (isOnCooldown(uuid)) {
            long remainingMs = getRemainingCooldown(uuid);
            int remainingSeconds = (int) Math.ceil(remainingMs / 1000.0);
            MessageHelper.sendError(player, "command.larbaco_auth.login.cooldown", remainingSeconds);
            return 0;
        }

        // Prompt for password
        MessageHelper.sendInfo(player, "command.larbaco_auth.login.enter_password");
        return Command.SINGLE_SUCCESS;
    }

    private static int processLoginWithPassword(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        // Perform all the same checks as initiateLogin
        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.already_authenticated");
            return 0;
        }

        if (!RegisterCommand.isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.not_registered");
            return 0;
        }

        int attempts = failedAttempts.getOrDefault(uuid, 0);
        if (attempts >= Config.maxLoginAttempts) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.locked");
            return 0;
        }

        if (isOnCooldown(uuid)) {
            long remainingMs = getRemainingCooldown(uuid);
            int remainingSeconds = (int) Math.ceil(remainingMs / 1000.0);
            MessageHelper.sendError(player, "command.larbaco_auth.login.cooldown", remainingSeconds);
            return 0;
        }

        updateLastAttemptTime(uuid);

        // Create session token for this login attempt
        String token = AuthSessionManager.createSession(player, password, OperationType.LOGIN);
        if (token == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.error");
            return 0;
        }

        String messageKey = "command.larbaco_auth.login.token_generated";
        MessageHelper.sendTokenMessage(player, messageKey, token);
        return Command.SINGLE_SUCCESS;
    }

    // Token validation method for /auth command compatibility
    public static int processLogin(ServerPlayer player, String token) {
        SessionData session = AuthSessionManager.validateSession(token);
        UUID uuid = player.getUUID();

        if (session == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.invalid_token");
            return 0;
        }

        if (!session.getPlayerId().equals(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.token_mismatch");
            return 0;
        }

        if (session.getOperation() != OperationType.LOGIN) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.invalid_operation");
            return 0;
        }

        try {
            String password = session.getPassword();
            return handlePasswordLogin(player, password);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error processing login for {}: {}", player.getScoreboardName(), e.getMessage());
            MessageHelper.sendError(player, "command.larbaco_auth.login.error");
            return 0;
        }
    }

    private static int handlePasswordLogin(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        // Final validation before attempting login
        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.already_authenticated");
            return 0;
        }

        if (!RegisterCommand.isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.not_registered");
            return 0;
        }

        int attempts = failedAttempts.getOrDefault(uuid, 0);
        if (attempts >= Config.maxLoginAttempts) {
            MessageHelper.sendError(player, "command.larbaco_auth.login.locked");
            return 0;
        }

        // Record the authentication attempt
        SystemMonitor.recordLoginAttempt(false); // Will be updated to true if successful

        // Verify password
        if (RegisterCommand.verifyPassword(uuid, password)) {
            // SUCCESS: Login successful
            LarbacoAuthMain.setAuthenticated(uuid, true);
            PlayerActionHandler.onAuthenticationSuccess(player);
            clearAttempts(uuid);
            clearCooldown(uuid);

            // Update monitoring
            SystemMonitor.recordLoginAttempt(true); // Override previous false record

            // Log successful login
            AuthLogger.logAuthEvent(uuid, player.getName().getString(), "LOGIN_SUCCESS",
                    "Player successfully authenticated");

            MessageHelper.sendSuccess(player, "command.larbaco_auth.login.success");
            LarbacoAuthMain.LOGGER.info("Player {} logged in successfully", player.getName().getString());

            return Command.SINGLE_SUCCESS;

        } else {
            // FAILURE: Invalid password
            attempts++;
            failedAttempts.put(uuid, attempts);
            int remaining = Config.maxLoginAttempts - attempts;

            // Log failed attempt
            AuthLogger.logAuthEvent(uuid, player.getName().getString(), "LOGIN_FAILED",
                    String.format("Invalid password, %d attempts remaining", remaining));

            MessageHelper.sendError(player, "command.larbaco_auth.login.failed", remaining);

            if (remaining <= 0) {
                MessageHelper.sendError(player, "command.larbaco_auth.login.locked");
                AuthLogger.logAuthEvent(uuid, player.getName().getString(), "ACCOUNT_LOCKED",
                        String.format("Account locked after %d failed attempts", Config.maxLoginAttempts));
                LarbacoAuthMain.LOGGER.warn("Player {} locked out after {} attempts",
                        player.getName().getString(), Config.maxLoginAttempts);
            }

            return 0;
        }
    }

    // Helper methods
    private static boolean isOnCooldown(UUID uuid) {
        Long lastAttempt = lastAttemptTime.get(uuid);
        if (lastAttempt == null) return false;
        return (System.currentTimeMillis() - lastAttempt) < COOLDOWN_MS;
    }

    private static long getRemainingCooldown(UUID uuid) {
        Long lastAttempt = lastAttemptTime.get(uuid);
        if (lastAttempt == null) return 0;
        long elapsed = System.currentTimeMillis() - lastAttempt;
        return Math.max(0, COOLDOWN_MS - elapsed);
    }

    private static void updateLastAttemptTime(UUID uuid) {
        lastAttemptTime.put(uuid, System.currentTimeMillis());
    }

    private static void clearCooldown(UUID uuid) {
        lastAttemptTime.remove(uuid);
    }

    public static void clearAttempts(UUID uuid) {
        failedAttempts.remove(uuid);
    }

    public static void unlockAccount(UUID uuid) {
        failedAttempts.remove(uuid);
        lastAttemptTime.remove(uuid);
        LarbacoAuthMain.LOGGER.info("Account unlocked for UUID: {}", uuid);
    }

    public static void cleanupPlayerData(UUID uuid) {
        failedAttempts.remove(uuid);
        lastAttemptTime.remove(uuid);
    }

    public static boolean isLockedOut(UUID uuid) {
        return failedAttempts.getOrDefault(uuid, 0) >= Config.maxLoginAttempts;
    }

    public static int getFailedAttempts(UUID uuid) {
        return failedAttempts.getOrDefault(uuid, 0);
    }
}