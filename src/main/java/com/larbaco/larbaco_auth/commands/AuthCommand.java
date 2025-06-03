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

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.handlers.OperationType;
import com.larbaco.larbaco_auth.handlers.SessionData;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;

import java.util.UUID;

/**
 * AuthCommand handles the second step of authentication using tokens.
 * Players use this command with tokens received from /login, /register, or /changepassword.
 *
 * Usage: /auth <token>
 */
public class AuthCommand {

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("auth")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("token", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String token = StringArgumentType.getString(context, "token");
                            return processAuthRequest(player, token);
                        })
                )
                .executes(context -> {
                    ServerPlayer player = context.getSource().getPlayerOrException();
                    return showAuthHelp(player);
                })
        );
    }

    /**
     * Process authentication request with the provided token
     */
    private static int processAuthRequest(ServerPlayer player, String token) {
        UUID uuid = player.getUUID();
        String playerName = player.getName().getString();

        try {
            // First, validate the session token - check if it exists and is valid without consuming
            SessionData session = AuthSessionManager.getSessionWithoutValidation(token);

            if (session == null) {
                MessageHelper.sendError(player, "command.larbaco_auth.auth.invalid_token");

                // Log invalid token attempt
                AuthLogger.logAuthEvent(uuid, playerName, "INVALID_TOKEN",
                        "Attempted to use invalid or expired token");

                LarbacoAuthMain.LOGGER.debug("Player {} used invalid/expired token: {}",
                        playerName, token.substring(0, Math.min(4, token.length())) + "...");

                return 0;
            }

            // Verify token belongs to this player
            if (!session.getPlayerId().equals(uuid)) {
                MessageHelper.sendError(player, "command.larbaco_auth.auth.token_mismatch");

                // Log token mismatch - potential security issue
                AuthLogger.logAuthEvent(uuid, playerName, "TOKEN_MISMATCH",
                        "Token belongs to different player - possible token theft attempt");

                LarbacoAuthMain.LOGGER.warn("Player {} attempted to use token belonging to different player",
                        playerName);

                return 0;
            }

            // Route to appropriate handler based on operation type
            // These handlers will consume the token themselves
            return switch (session.getOperation()) {
                case LOGIN -> {
                    LarbacoAuthMain.LOGGER.debug("Processing login authentication for {}", playerName);
                    yield LoginCommand.processLogin(player, token);
                }
                case REGISTER -> {
                    LarbacoAuthMain.LOGGER.debug("Processing registration authentication for {}", playerName);
                    yield RegisterCommand.processRegistration(player, token);
                }
                case CHANGE_PASSWORD -> {
                    LarbacoAuthMain.LOGGER.debug("Processing password change authentication for {}", playerName);
                    yield ChangePasswordCommand.processPasswordChange(player, token);
                }
                default -> {
                    MessageHelper.sendError(player, "command.larbaco_auth.auth.invalid_operation");

                    AuthLogger.logAuthEvent(uuid, playerName, "UNKNOWN_OPERATION",
                            "Token contains unknown operation: " + session.getOperation());

                    LarbacoAuthMain.LOGGER.error("Unknown operation type in token for player {}: {}",
                            playerName, session.getOperation());

                    yield 0;
                }
            };

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error processing auth request for player {}: {}",
                    playerName, e.getMessage(), e);

            MessageHelper.sendError(player, "command.larbaco_auth.auth.error");

            AuthLogger.logAuthEvent(uuid, playerName, "AUTH_ERROR",
                    "Error processing authentication: " + e.getMessage());

            return 0;
        }
    }

    /**
     * Show help message when /auth is used without a token
     */
    private static int showAuthHelp(ServerPlayer player) {
        UUID uuid = player.getUUID();

        // Check if player has a pending operation
        OperationType pendingOp = AuthSessionManager.getPendingOperation(uuid);

        if (pendingOp != null) {
            String operationMsg = switch (pendingOp) {
                case LOGIN -> "command.larbaco_auth.auth.help.login";
                case REGISTER -> "command.larbaco_auth.auth.help.register";
                case CHANGE_PASSWORD -> "command.larbaco_auth.auth.help.changepassword";
            };
            MessageHelper.sendInfo(player, operationMsg);
        } else {
            // No pending operation, show general help
            if (RegisterCommand.isRegistered(uuid)) {
                if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
                    MessageHelper.sendInfo(player, "command.larbaco_auth.auth.help.already_authenticated");
                } else {
                    MessageHelper.sendInfo(player, "command.larbaco_auth.auth.help.need_login");
                }
            } else {
                MessageHelper.sendInfo(player, "command.larbaco_auth.auth.help.need_register");
            }
        }

        return Command.SINGLE_SUCCESS;
    }
}