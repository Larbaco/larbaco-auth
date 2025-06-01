package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;

import java.util.UUID;

public class AuthCommand {
    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("auth")
                .requires(source -> source.hasPermission(0))
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            ServerPlayer player = context.getSource().getPlayerOrException();
                            String password = StringArgumentType.getString(context, "password");
                            return processAuthRequest(player, password);
                        })
                )
        );
    }

    private static int processAuthRequest(ServerPlayer player, String password) {
        UUID uuid = player.getUUID();
        AuthSessionManager.OperationType operation = AuthSessionManager.getPendingOperation(uuid);
        AuthSessionManager.clearPendingOperation(uuid);
        if (operation == null) {
            if (RegisterCommand.isRegistered(uuid)) {
                operation = AuthSessionManager.OperationType.LOGIN;
            } else {
                operation = AuthSessionManager.OperationType.REGISTER;
            }
        }
        String token = AuthSessionManager.createSession(player, password, operation);
        if (token == null) {
            MessageHelper.sendError(player, "command.larbaco_auth.auth.error");
            return 0;
        }
        String messageKey = (operation == AuthSessionManager.OperationType.REGISTER) ?
                "command.larbaco_auth.register.token_generated" :
                "command.larbaco_auth.login.token_generated";
        MessageHelper.sendTokenMessage(player, messageKey, token);
        return Command.SINGLE_SUCCESS;
    }
}