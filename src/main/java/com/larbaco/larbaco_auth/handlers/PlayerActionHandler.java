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

/*
 * Copyright (C) 2025 Larbaco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.larbaco.larbaco_auth.handlers;

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.effect.MobEffects;
import net.minecraft.world.entity.player.Player;
import net.minecraft.network.chat.Component;
import net.minecraft.world.level.GameType;
import net.minecraft.world.phys.Vec3;
import net.neoforged.bus.api.EventPriority;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.neoforge.event.tick.PlayerTickEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.entity.player.PlayerInteractEvent;
import net.neoforged.neoforge.event.ServerChatEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.event.level.BlockEvent;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID)
public class PlayerActionHandler {
    private static void log(String message) {
        LarbacoAuthMain.LOGGER.debug("[Auth] {}", message);
    }

    private static final Map<UUID, Vec3> lastValidPositions = new HashMap<>();
    private static final double POSITION_EPSILON = 0.001;

    @SubscribeEvent
    public static void onPlayerTick(PlayerTickEvent.Pre event) {
        Player player = event.getEntity();
        if (!(player instanceof ServerPlayer serverPlayer)) return;

        UUID uuid = serverPlayer.getUUID();
        Vec3 currentPos = serverPlayer.position();

        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            if (!lastValidPositions.containsKey(uuid)) {
                lastValidPositions.put(uuid, currentPos);
            }

            Vec3 lastPos = lastValidPositions.get(uuid);
            restrictMovement(serverPlayer);

            if (!positionsEqual(currentPos, lastPos)) {
                serverPlayer.teleportTo(
                        serverPlayer.serverLevel(),
                        lastPos.x,
                        lastPos.y,
                        lastPos.z,
                        serverPlayer.getYRot(),
                        serverPlayer.getXRot()
                );
                log("Corrected position for: " + serverPlayer.getName().getString());
            }

            lastValidPositions.put(uuid, serverPlayer.position());
        }
    }

    @SubscribeEvent
    public static void onPlayerLogout(PlayerEvent.PlayerLoggedOutEvent event) {
        UUID uuid = event.getEntity().getUUID();
        lastValidPositions.remove(uuid);
        log("Cleared position tracking for: " + event.getEntity().getName().getString());
    }

    @SubscribeEvent
    public static void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
        Player player = event.getEntity();
        if (!(player instanceof ServerPlayer serverPlayer)) return;

        UUID uuid = serverPlayer.getUUID();
        log("Player logged in: " + serverPlayer.getName().getString());
        lastValidPositions.put(uuid, serverPlayer.position());

        sendAuthPrompt(serverPlayer);

        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            restrictMovement(serverPlayer);
            serverPlayer.sendSystemMessage(Component.literal("Please authenticate using /login"));
        }
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onBlockBreak(BlockEvent.BreakEvent event) {
        Player player = event.getPlayer();
        if (!LarbacoAuthMain.isPlayerAuthenticated(player.getUUID())) {
            event.setCanceled(true); // Directly cancel the block break
            player.sendSystemMessage(Component.literal("§cPlease authenticate first!"));
            log("Blocked block break by: " + player.getName().getString());
        }
    }

    private static void sendAuthPrompt(Player player) {
        log("Sending auth prompt to: " + player.getName().getString());
        player.sendSystemMessage(Component.literal("Welcome! Please use /login <password> or /register <password>"));
    }

    private static void restrictMovement(Player player) {
        log("Restricting movement for " + player.getName().getString());

        if (player instanceof ServerPlayer serverPlayer) {
            // Set to spectator mode
            serverPlayer.setGameMode(GameType.SPECTATOR);

            // Apply permanent blindness effect (duration in ticks, 20 ticks = 1 second)
            serverPlayer.addEffect(new MobEffectInstance(
                    MobEffects.BLINDNESS,
                    Integer.MAX_VALUE,  // Duration (effectively infinite)
                    1,                  // Amplifier (0 = level I, 1 = level II)
                    false,               // Ambient particle effect
                    false               // Show icon
            ));
        }
        // Reset movement vectors
        player.setDeltaMovement(Vec3.ZERO);

        // Update abilities
        player.getAbilities().flying = false;
        player.getAbilities().invulnerable = true;
        player.getAbilities().instabuild = false;
        player.onUpdateAbilities();
    }

    private static void restoreMovement(Player player) {
        log("Restoring movement for " + player.getName().getString());
        player.getAbilities().invulnerable = false;
        player.onUpdateAbilities();
        lastValidPositions.remove(player.getUUID());
    }

    private static boolean positionsEqual(Vec3 a, Vec3 b) {
        return Math.abs(a.x - b.x) < POSITION_EPSILON &&
                Math.abs(a.y - b.y) < POSITION_EPSILON &&
                Math.abs(a.z - b.z) < POSITION_EPSILON;
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onBlockInteract(PlayerInteractEvent.RightClickBlock event) {
        handleUnauthorizedInteraction(event.getEntity(), event);
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onItemUse(PlayerInteractEvent.RightClickItem event) {
        handleUnauthorizedInteraction(event.getEntity(), event);
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onChatMessage(ServerChatEvent event) {
        Player player = event.getPlayer();
        if (!LarbacoAuthMain.isPlayerAuthenticated(player.getUUID())) {
            event.setCanceled(true);
            player.sendSystemMessage(Component.literal("You must login before chatting!"));
            log("Blocked chat from: " + player.getName().getString());
        }
    }

    private static void handleUnauthorizedInteraction(Player player, Object event) {
        UUID uuid = player.getUUID();
        if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            log("Blocked interaction for: " + player.getName().getString());
            if (event instanceof PlayerInteractEvent interactEvent) {
                //interactEvent.setCanceled(true);
            }
            player.sendSystemMessage(Component.literal("Please authenticate first!"));
        }
    }

    public static void onAuthenticationSuccess(ServerPlayer player) {
        log("Authentication successful for: " + player.getName().getString());
        restoreMovement(player);
        player.sendSystemMessage(Component.literal("Authentication successful!"));
    }
}