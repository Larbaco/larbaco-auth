package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.util.UUID;

public class DisconnectCommand {

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("disconnect")
                .requires(source -> source.hasPermission(0))
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return executeDisconnect(player);
                })
        );

        // Also register /logout as an alias
        dispatcher.register(Commands.literal("logout")
                .requires(source -> source.hasPermission(0))
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return executeDisconnect(player);
                })
        );
    }

    private static int executeDisconnect(ServerPlayer player) {
        UUID uuid = player.getUUID();
        String playerName = player.getName().getString();

        try {
            // Notify player before disconnecting
            MessageHelper.sendInfo(player, "command.larbaco_auth.disconnect.processing");

            // Clear authentication status
            boolean wasAuthenticated = LarbacoAuthMain.isPlayerAuthenticated(uuid);
            LarbacoAuthMain.setAuthenticated(uuid, false);

            // Clear any active sessions and pending operations
            AuthSessionManager.clearPendingOperation(uuid);

            // Clear login attempts and change password attempts
            LoginCommand.cleanupPlayerData(uuid);
            ChangePasswordCommand.cleanupPlayerData(uuid);

            // Clear all player data from action handler
            com.larbaco.larbaco_auth.handlers.PlayerActionHandler.clearAllPlayerData(uuid);

            // Log the disconnect action
            String logDetails = wasAuthenticated ? "Authenticated player disconnected" : "Unauthenticated player disconnected";
            AuthLogger.logAuthEvent(uuid, playerName, "PLAYER_DISCONNECT", logDetails);

            // Send localized disconnect message to player
            String disconnectMessage = MessageHelper.getTranslation("command.larbaco_auth.disconnect.message");
            Component disconnectComponent = Component.literal(disconnectMessage);
            player.connection.disconnect(disconnectComponent);

            LarbacoAuthMain.LOGGER.info("Player {} disconnected via command, session reset", playerName);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error processing disconnect for player {}: {}", playerName, e.getMessage(), e);

            // Still try to disconnect the player even if there was an error
            try {
                String errorMessage = MessageHelper.getTranslation("command.larbaco_auth.disconnect.error");
                Component errorComponent = Component.literal(errorMessage);
                player.connection.disconnect(errorComponent);
            } catch (Exception disconnectError) {
                LarbacoAuthMain.LOGGER.error("Failed to disconnect player {}: {}", playerName, disconnectError.getMessage());
            }

            return 0;
        }
    }
}