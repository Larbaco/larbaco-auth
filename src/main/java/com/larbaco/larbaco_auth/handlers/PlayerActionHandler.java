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
import com.larbaco.larbaco_auth.commands.LoginCommand;
import com.larbaco.larbaco_auth.commands.RegisterCommand;
import net.minecraft.core.Holder;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.Tag;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.effect.MobEffect;
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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID)
public class PlayerActionHandler {
    private static void log(String message) {
        LarbacoAuthMain.LOGGER.debug("[Auth] {}", message);
    }

    private static void log(String message, Integer level) {
        if (level == 0) {
            LarbacoAuthMain.LOGGER.debug("[Auth] {}", message);
        }
        if (level == 1) {
            LarbacoAuthMain.LOGGER.info("[Auth] {}", message);
        }
        if (level == 2) {
            LarbacoAuthMain.LOGGER.error("[Auth] {}", message);
        }
    }

    private static final Map<UUID, Vec3> lastValidPositions = new HashMap<>();
    private static final double POSITION_EPSILON = 0.001;

    private static record PlayerState(
            GameType gameType,
            List<CompoundTag> effectTags,
            boolean mayFly,
            boolean isFlying,
            boolean invulnerable,
            boolean instabuild
    ) {
    }

    private static final Map<UUID, PlayerState> originalStates = new ConcurrentHashMap<>();

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
        if (event.getEntity() instanceof ServerPlayer serverPlayer) {
            log("Restoring before logout: " + serverPlayer.getName().getString());
            try {
                restoreOriginalPlayerState(serverPlayer);
                // also undo any movement or ability flags here if you’ve changed them
                serverPlayer.getAbilities().mayfly = false;
                serverPlayer.getAbilities().flying = false;
                serverPlayer.getAbilities().invulnerable = false;
                serverPlayer.getAbilities().instabuild = false;
                serverPlayer.onUpdateAbilities();
            } catch (Exception e) {
                log("Error in logout restore: " + e.getMessage(), 2);
            }
        }

        UUID uuid = event.getEntity().getUUID();
        LarbacoAuthMain.setAuthenticated(uuid, false);
        LoginCommand.clearAttempts(uuid);
        lastValidPositions.remove(uuid);
        originalStates.remove(uuid);
        log("Cleared auth data for: " + event.getEntity().getName().getString());
    }


    @SubscribeEvent
    public static void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
        Player player = event.getEntity();
        if (!(player instanceof ServerPlayer serverPlayer)) return;

        UUID uuid = serverPlayer.getUUID();
        log("Player logged in: " + serverPlayer.getName().getString(), 1);
        lastValidPositions.put(uuid, serverPlayer.position());

        originalStates.remove(uuid);

        List<CompoundTag> effectTags = new ArrayList<>();
        List<MobEffectInstance> currentEffects = new ArrayList<>(serverPlayer.getActiveEffects());

        for (MobEffectInstance effect : currentEffects) {
            Tag genericTag = effect.save();
            if (genericTag instanceof CompoundTag tag) {
                effectTags.add(tag);
            }
        }

        var ab = serverPlayer.getAbilities();
        originalStates.put(uuid, new PlayerState(
                serverPlayer.gameMode.getGameModeForPlayer(),
                effectTags, // Store NBT instead of instances
                ab.mayfly,
                ab.flying,
                ab.invulnerable,
                ab.instabuild
        ));


        sendAuthPrompt(serverPlayer);
        applyLoginRestrictions(serverPlayer);

        if (!RegisterCommand.isRegistered(uuid)) {
            serverPlayer.sendSystemMessage(Component.translatable("command.register.prompt"));
        } else if (!LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            serverPlayer.sendSystemMessage(Component.translatable("command.login.prompt"));
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

    private static void applyLoginRestrictions(ServerPlayer player) {
        log("Applying login restrictions to: " + player.getName().getString());

        // Set spectator mode
        player.setGameMode(GameType.SPECTATOR);

        // Apply blindness
        player.addEffect(new MobEffectInstance(
                MobEffects.BLINDNESS,
                Integer.MAX_VALUE,
                1,
                false,
                false
        ));

        // Clear other effects
        List<MobEffectInstance> toClear = new ArrayList<>(player.getActiveEffects());
        for (MobEffectInstance effect : toClear) {
            if (effect.getEffect() != MobEffects.BLINDNESS) {
                player.removeEffect(effect.getEffect());
            }
        }
        // Freeze position
        player.setDeltaMovement(Vec3.ZERO);
    }

    private static void restrictMovement(Player player) {
        // log("Restricting movement for " + player.getName().getString());

        // Reset movement vectors
        player.setDeltaMovement(Vec3.ZERO);

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
        UUID uuid = player.getUUID();
        log("Restoring original state for: " + player.getName().getString());

        try {
            // Restore game mode and effects
            restoreOriginalPlayerState(player);

            // Clear authentication restrictions
            removeAuthenticationEffects(player);
            restorePlayerMovement(player);

            // Cleanup tracking data
            cleanupAuthenticationData(uuid);

            player.sendSystemMessage(Component.literal("Authentication successful!"));
            log("Full restoration complete for: " + player.getName().getString());
        } catch (Exception e) {
            log("Error restoring player state: " + e.getMessage(), 2);
            player.sendSystemMessage(Component.literal("Error restoring your state! Contact admin."));
        }
    }

    private static void restoreOriginalPlayerState(ServerPlayer player) {
        PlayerState state = originalStates.remove(player.getUUID());
        if (state == null) return;

        player.removeAllEffects();
        player.setGameMode(state.gameType());

        for (CompoundTag tag : state.effectTags()) {
            try {
                MobEffectInstance effect = MobEffectInstance.load(tag);
                if (effect == null) {
                    log("Skipped null potion effect tag for " + player.getName().getString());
                    continue;
                }

                // Avoid effects that might be corrupted or unloaded
                var mobEffect = effect.getEffect();
                if (mobEffect == null) {
                    log("Skipped effect with null MobEffect for " + player.getName().getString());
                    continue;
                }

                if (!mobEffect.is(MobEffects.BLINDNESS)) {
                    player.addEffect(effect);
                }
            } catch (Exception e) {
                log("Error restoring potion effect for " + player.getName().getString() + ": " + e.getMessage(), 2);
            }
        }
    }

    private static void removeAuthenticationEffects(ServerPlayer player) {
        log("Clearing authentication effects for: " + player.getName().getString());
        player.removeEffect(MobEffects.BLINDNESS);
    }

    private static void restorePlayerMovement(ServerPlayer player) {
        log("Restoring movement for: " + player.getName().getString());
        player.setDeltaMovement(Vec3.ZERO);
        player.getAbilities().invulnerable = false;
        player.onUpdateAbilities();
    }

    private static void restoreFullState(ServerPlayer player) {
        PlayerState state = originalStates.remove(player.getUUID());
        if (state == null) return;

        player.removeAllEffects();
        var ab = player.getAbilities();
        ab.mayfly = false;
        ab.flying = false;
        ab.invulnerable = false;
        ab.instabuild = false;
        player.onUpdateAbilities();

        player.setGameMode(state.gameType());

        for (CompoundTag tag : state.effectTags()) {
            MobEffectInstance effect = MobEffectInstance.load(tag);
            if (effect != null && !effect.getEffect().is(MobEffects.BLINDNESS)) {
                player.addEffect(effect);
            }
        }

        ab.mayfly = state.mayFly();
        ab.flying = state.isFlying();
        ab.invulnerable = state.invulnerable();
        ab.instabuild = state.instabuild();
        player.onUpdateAbilities();
        log("Fully restored state for " + player.getName().getString());
    }

    private static void cleanupAuthenticationData(UUID uuid) {
        lastValidPositions.remove(uuid);
        originalStates.remove(uuid); // Double cleanup for safety
        log("Cleared authentication tracking data for UUID: " + uuid);
    }
}