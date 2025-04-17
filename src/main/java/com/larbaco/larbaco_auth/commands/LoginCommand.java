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
import com.larbaco.larbaco_auth.handlers.PlayerActionHandler;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LoginCommand {
    private static final Map<UUID, Integer> failedAttempts = new ConcurrentHashMap<>();

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("login")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String password = StringArgumentType.getString(context, "password");
                            return handleLogin(player, password);
                        })
                )
        );
    }

    private static int handleLogin(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            player.sendSystemMessage(Component.translatable("command.login.already_authenticated"));
            return 0;
        }

        if (!RegisterCommand.isRegistered(uuid)) {
            player.sendSystemMessage(Component.translatable("command.login.not_registered"));
            return 0;
        }

        int attempts = failedAttempts.getOrDefault(uuid, 0);
        if (attempts >= Config.maxLoginAttempts) {
            player.sendSystemMessage(Component.translatable("command.login.locked"));
            return 0;
        }

        if (RegisterCommand.verifyPassword(uuid, password)) {
            LarbacoAuthMain.setAuthenticated(uuid, true);
            PlayerActionHandler.onAuthenticationSuccess(player);
            failedAttempts.remove(uuid);
            player.sendSystemMessage(Component.translatable("command.login.success"));
            return Command.SINGLE_SUCCESS;
        } else {
            attempts++;
            failedAttempts.put(uuid, attempts);
            int remaining = Config.maxLoginAttempts - attempts;
            player.sendSystemMessage(Component.translatable("command.login.failed", remaining));
            if (remaining <= 0) {
                player.sendSystemMessage(Component.translatable("command.login.locked"));
            }
            return 0;
        }
    }

    public static void clearAttempts(UUID uuid) {
        failedAttempts.remove(uuid);
    }
}