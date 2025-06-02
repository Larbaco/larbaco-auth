package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
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

public class ChangePasswordCommand {
    private static final Map<UUID, Long> lastChangeAttempt = new ConcurrentHashMap<>();
    private static final long COOLDOWN_MS = 30000; // 30 seconds cooldown

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("changepassword")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("newpassword", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String newPassword = StringArgumentType.getString(context, "newpassword");
                            return processPasswordChangeWithPassword(player, newPassword);
                        }))
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return initiatePasswordChange(player);
                })
        );
    }

    private static int initiatePasswordChange(ServerPlayer player) {
        UUID uuid = player.getUUID();

        // Check if player is authenticated
        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.not_authenticated");
            return 0;
        }

        // Check if player is registered
        if (!RegisterCommand.isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.not_registered");
            return 0;
        }

        // Check cooldown
        if (isOnCooldown(uuid)) {
            long remainingMs = getRemainingCooldown(uuid);
            int remainingSeconds = (int) Math.ceil(remainingMs / 1000.0);
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.cooldown", remainingSeconds);
            return 0;
        }

        // Show password requirements
        String requirements = Config.getPasswordRequirementsString();
        MessageHelper.sendInfo(player, "command.larbaco_auth.changepassword.requirements", requirements);
        MessageHelper.sendInfo(player, "command.larbaco_auth.changepassword.enter_new_password");

        return Command.SINGLE_SUCCESS;
    }

    private static int processPasswordChangeWithPassword(ServerPlayer player, String newPassword) {
        UUID uuid = player.getUUID();

        // Check if player is authenticated
        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.not_authenticated");
            return 0;
        }

        // Check if player is registered
        if (!RegisterCommand.isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.not_registered");
            return 0;
        }

        // Check cooldown
        if (isOnCooldown(uuid)) {
            long remainingMs = getRemainingCooldown(uuid);
            int remainingSeconds = (int) Math.ceil(remainingMs / 1000.0);
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.cooldown", remainingSeconds);
            return 0;
        }

        // Validate new password
        if (!Config.validatePassword(newPassword)) {
            String requirements = Config.getPasswordRequirementsString();
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.invalid_password", requirements);
            return 0;
        }

        // Check if new password is same as current
        if (RegisterCommand.verifyPassword(uuid, newPassword)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.same_password");
            return 0;
        }

        updateLastChangeAttempt(uuid);

        // Create session token for password change
        String token = AuthSessionManager.createSession(player, newPassword, AuthSessionManager.OperationType.CHANGE_PASSWORD);
        if (token == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.error");
            return 0;
        }

        String messageKey = "command.larbaco_auth.changepassword.token_generated";
        MessageHelper.sendTokenMessage(player, messageKey, token);
        return Command.SINGLE_SUCCESS;
    }

    // Token validation method for /auth command compatibility
    public static int processPasswordChange(ServerPlayer player, String token) {
        AuthSessionManager.SessionData session = AuthSessionManager.validateSession(token);
        UUID uuid = player.getUUID();

        if (session == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.invalid_token");
            return 0;
        }

        if (!session.getPlayerId().equals(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.token_mismatch");
            return 0;
        }

        if (session.getOperation() != AuthSessionManager.OperationType.CHANGE_PASSWORD) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.invalid_operation");
            return 0;
        }

        try {
            String newPassword = session.getPassword();
            return handlePasswordChange(player, newPassword);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error processing password change for {}: {}",
                    player.getScoreboardName(), e.getMessage());
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.error");
            return 0;
        }
    }

    private static int handlePasswordChange(ServerPlayer player, String newPassword) {
        UUID uuid = player.getUUID();

        // Double-check authentication
        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.not_authenticated");
            return 0;
        }

        // Validate new password again
        if (!Config.validatePassword(newPassword)) {
            String requirements = Config.getPasswordRequirementsString();
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.invalid_password", requirements);
            return 0;
        }

        // Check if new password is same as current
        if (RegisterCommand.verifyPassword(uuid, newPassword)) {
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.same_password");
            return 0;
        }

        try {
            // Change the password
            boolean success = RegisterCommand.changePassword(uuid, newPassword);

            if (success) {
                MessageHelper.sendSuccess(player, "command.larbaco_auth.changepassword.success");

                // Log the password change
                AuthLogger.logAuthEvent(uuid, player.getName().getString(), "PASSWORD_CHANGED",
                        "Password successfully changed");

                LarbacoAuthMain.LOGGER.info("Player {} changed their password", player.getName().getString());

                return Command.SINGLE_SUCCESS;
            } else {
                MessageHelper.sendError(player, "command.larbaco_auth.changepassword.failed");
                return 0;
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error changing password for player {}: {}",
                    player.getName().getString(), e.getMessage());
            MessageHelper.sendError(player, "command.larbaco_auth.changepassword.error");
            return 0;
        }
    }

    private static boolean isOnCooldown(UUID uuid) {
        Long lastAttempt = lastChangeAttempt.get(uuid);
        if (lastAttempt == null) return false;
        return (System.currentTimeMillis() - lastAttempt) < COOLDOWN_MS;
    }

    private static long getRemainingCooldown(UUID uuid) {
        Long lastAttempt = lastChangeAttempt.get(uuid);
        if (lastAttempt == null) return 0;
        long elapsed = System.currentTimeMillis() - lastAttempt;
        return Math.max(0, COOLDOWN_MS - elapsed);
    }

    private static void updateLastChangeAttempt(UUID uuid) {
        lastChangeAttempt.put(uuid, System.currentTimeMillis());
    }

    public static void cleanupPlayerData(UUID uuid) {
        lastChangeAttempt.remove(uuid);
    }
}