package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.handlers.OperationType;
import com.larbaco.larbaco_auth.handlers.SessionData;
import com.larbaco.larbaco_auth.storage.DataManager;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;
import org.mindrot.jbcrypt.BCrypt;

import java.util.UUID;

public class RegisterCommand {

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("register")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String password = StringArgumentType.getString(context, "password");
                            return processRegistrationWithPassword(player, password);
                        }))
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return initiateRegistration(player);
                })
        );
    }

    private static int initiateRegistration(ServerPlayer player) {
        UUID uuid = player.getUUID();

        if (isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.already_registered");
            return 0;
        }

        String requirements = Config.getPasswordRequirementsString();
        if (!requirements.isEmpty()) {
            MessageHelper.sendInfo(player, "command.larbaco_auth.register.requirements", requirements);
        }
        MessageHelper.sendInfo(player, "command.larbaco_auth.register.enter_password");
        return Command.SINGLE_SUCCESS;
    }

    private static int processRegistrationWithPassword(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        if (isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.already_registered");
            return 0;
        }

        if (!Config.validatePassword(password)) {
            String requirements = Config.getPasswordRequirementsString();
            MessageHelper.sendError(player, "command.larbaco_auth.register.invalid_password", requirements);
            return 0;
        }

        // Create session token for this registration attempt
        String token = AuthSessionManager.createSession(player, password, OperationType.REGISTER);
        if (token == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.error");
            return 0;
        }

        String messageKey = "command.larbaco_auth.register.token_generated";
        MessageHelper.sendTokenMessage(player, messageKey, token);
        return Command.SINGLE_SUCCESS;
    }

    // Keep the original token validation method for /auth command compatibility
    public static int processRegistration(ServerPlayer player, String token) {
        SessionData session = AuthSessionManager.validateSession(token);
        UUID uuid = player.getUUID();

        if (session == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.invalid_token");
            return 0;
        }

        if (!session.getPlayerId().equals(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.token_mismatch");
            return 0;
        }

        if (session.getOperation() != OperationType.REGISTER) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.invalid_operation");
            return 0;
        }

        try {
            String password = session.getPassword();
            return handlePasswordRegistration(player, password);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error processing registration for {}: {}", player.getScoreboardName(), e.getMessage());
            MessageHelper.sendError(player, "command.larbaco_auth.register.error");
            return 0;
        }
    }

    private static int handlePasswordRegistration(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        if (isRegistered(uuid)) {
            MessageHelper.sendError(player, "command.larbaco_auth.register.already_registered");
            return 0;
        }

        if (!Config.validatePassword(password)) {
            String requirements = Config.getPasswordRequirementsString();
            MessageHelper.sendError(player, "command.larbaco_auth.register.invalid_password", requirements);
            return 0;
        }

        try {
            String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));
            DataManager.registerPlayer(uuid, hashed);

            // Auto-authenticate after successful registration
            LarbacoAuthMain.setAuthenticated(uuid, true);
            com.larbaco.larbaco_auth.handlers.PlayerActionHandler.onAuthenticationSuccess(player);

            MessageHelper.sendSuccess(player, "command.larbaco_auth.register.success");
            LarbacoAuthMain.LOGGER.info("Player {} registered successfully", player.getName().getString());
            return Command.SINGLE_SUCCESS;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during password hashing for player {}: {}", player.getName().getString(), e.getMessage());
            MessageHelper.sendError(player, "command.larbaco_auth.register.error");
            return 0;
        }
    }

    public static boolean isRegistered(UUID uuid) {
        return DataManager.isPlayerRegistered(uuid);
    }

    public static boolean verifyPassword(UUID uuid, String password) {
        String hash = DataManager.getPlayerPasswordHash(uuid);
        if (hash == null || password == null) return false;
        try {
            return BCrypt.checkpw(password, hash);
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during password verification for UUID {}: {}", uuid, e.getMessage());
            return false;
        }
    }

    public static int getRegisteredPlayerCount() {
        return DataManager.getRegisteredPlayerCount();
    }

    public static boolean unregisterPlayer(UUID uuid) {
        if (!isRegistered(uuid)) return false;
        DataManager.unregisterPlayer(uuid);
        LarbacoAuthMain.LOGGER.info("Player unregistered: {}", uuid);
        return true;
    }

    public static boolean changePassword(UUID uuid, String newPassword) {
        if (!isRegistered(uuid) || !Config.validatePassword(newPassword)) return false;
        try {
            String hashed = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
            DataManager.registerPlayer(uuid, hashed);
            LarbacoAuthMain.LOGGER.info("Password changed for UUID: {}", uuid);
            return true;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error changing password for UUID {}: {}", uuid, e.getMessage());
            return false;
        }
    }
}