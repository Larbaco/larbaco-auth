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
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class RegisterCommand {
    // Temporary storage until SQLite is implemented
    private static final Map<UUID, String> registeredPlayers = new ConcurrentHashMap<>();

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("register")
                .requires(source -> source.hasPermission(0)) // Allow non-OP usage
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String password = StringArgumentType.getString(context, "password");
                            return handleRegistration(player, password);
                        })
                )
        );
    }

    private static int handleRegistration(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();

        if (registeredPlayers.containsKey(uuid)) {
            player.sendSystemMessage(Component.translatable("command.register.already_registered"));
            return 0;
        }

        if (!validatePassword(password)) {
            player.sendSystemMessage(Component.translatable("command.register.invalid_password"));
            return 0;
        }

        String hashed = BCrypt.hashpw(password, BCrypt.gensalt());
        registeredPlayers.put(uuid, hashed);
        player.sendSystemMessage(Component.translatable("command.register.success"));
        return Command.SINGLE_SUCCESS;
    }

    private static boolean validatePassword(String password) {
        boolean valid = true;

        if (Config.requireMixedCase) {
            valid &= !password.equals(password.toLowerCase()) &&
                    !password.equals(password.toUpperCase());
        }

        if (Config.requireSpecialChar) {
            valid &= password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*");
        }

        return valid;
    }

    public static boolean isRegistered(UUID uuid) {
        return registeredPlayers.containsKey(uuid);
    }

    public static boolean verifyPassword(UUID uuid, String password) {
        String hash = registeredPlayers.get(uuid);
        return hash != null && BCrypt.checkpw(password, hash);
    }
}