package com.larbaco.larbaco_auth.handlers;

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.commands.LoginCommand;
import com.larbaco.larbaco_auth.commands.RegisterCommand;
import com.larbaco.larbaco_auth.storage.DataManager;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.effect.MobEffects;
import net.minecraft.world.level.GameType;
import net.minecraft.world.phys.Vec3;
import net.neoforged.bus.api.EventPriority;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.event.CommandEvent;
import net.neoforged.neoforge.event.ServerChatEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.entity.player.PlayerInteractEvent;
import net.neoforged.neoforge.event.level.BlockEvent;
import net.neoforged.neoforge.event.tick.PlayerTickEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID)
public class PlayerActionHandler {
    private static final double POSITION_EPSILON = 1e-3;
    private static final int MAX_EFFECTS = 20;

    private static final Map<UUID, Vec3> lastPositions = new ConcurrentHashMap<>();
    private static final Map<UUID, PlayerState> originalStates = new ConcurrentHashMap<>();
    private static final Set<String> allowedCommands = Set.of("login", "register", "auth");

    @SubscribeEvent(priority = EventPriority.HIGH)
    public static void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
        if (!(event.getEntity() instanceof ServerPlayer player)) return;

        UUID uuid = player.getUUID();
        lastPositions.put(uuid, player.position());

        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            GameType storedMode = DataManager.getPlayerGameMode(uuid);
            if (storedMode != null) {
                player.setGameMode(storedMode);
            }
            return;
        }

        GameType currentMode = player.gameMode.getGameModeForPlayer();
        GameType storedMode = DataManager.getPlayerGameMode(uuid);

        if (storedMode != null) {
            player.setGameMode(storedMode);
            currentMode = storedMode;
        } else {
            DataManager.setPlayerGameMode(uuid, currentMode);
        }

        originalStates.put(uuid, captureState(player));
        promptForAuth(player);
        restrictPlayer(player);
    }

    @SubscribeEvent(priority = EventPriority.HIGH)
    public static void onPlayerLogout(PlayerEvent.PlayerLoggedOutEvent event) {
        if (!(event.getEntity() instanceof ServerPlayer player)) return;

        UUID uuid = player.getUUID();

        if (LarbacoAuthMain.isPlayerAuthenticated(uuid)) {
            DataManager.setPlayerGameMode(uuid, player.gameMode.getGameModeForPlayer());
        } else {
            PlayerState state = originalStates.get(uuid);
            if (state != null) {
                DataManager.setPlayerGameMode(uuid, state.gameType());
            }
        }

        AuthSessionManager.clearPendingOperation(uuid);
        clearSessionData(uuid);
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onPlayerTick(PlayerTickEvent.Pre event) {
        if (!(event.getEntity() instanceof ServerPlayer player)) return;
        if (LarbacoAuthMain.isPlayerAuthenticated(player.getUUID())) return;
        enforcePosition(player);
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onBlockBreak(BlockEvent.BreakEvent event) {
        if (event.getPlayer() instanceof ServerPlayer player) {
            cancelIfUnauthenticated(player, () -> event.setCanceled(true), "command.larbaco_auth.blocked.action");
        }
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onBlockInteract(PlayerInteractEvent.RightClickBlock event) {
        if (event.getEntity() instanceof ServerPlayer player) {
            cancelIfUnauthenticated(player, () -> event.setCanceled(true), "command.larbaco_auth.blocked.action");
        }
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onItemUse(PlayerInteractEvent.RightClickItem event) {
        if (event.getEntity() instanceof ServerPlayer player) {
            cancelIfUnauthenticated(player, () -> event.setCanceled(true), "command.larbaco_auth.blocked.action");
        }
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onChat(ServerChatEvent event) {
        cancelIfUnauthenticated(event.getPlayer(), () -> event.setCanceled(true), "command.larbaco_auth.blocked.chat");
    }

    @SubscribeEvent(priority = EventPriority.HIGHEST)
    public static void onCommand(CommandEvent event) {
        String command = event.getParseResults().getReader().getString();
        if (command.startsWith("/")) command = command.substring(1);
        command = command.split(" ")[0].toLowerCase();

        var source = event.getParseResults().getContext().getSource();
        if (!(source.getEntity() instanceof ServerPlayer player)) return;
        if (LarbacoAuthMain.isPlayerAuthenticated(player.getUUID())) return;
        if (allowedCommands.contains(command)) return;

        event.setCanceled(true);
        MessageHelper.sendError(player, "command.larbaco_auth.blocked");
    }

    public static void onAuthenticationSuccess(ServerPlayer player) {
        restorePlayerState(player);
        clearSessionData(player.getUUID());
    }

    private static PlayerState captureState(ServerPlayer player) {
        var abilities = player.getAbilities();
        List<CompoundTag> effects = new ArrayList<>();

        for (MobEffectInstance effect : player.getActiveEffects()) {
            if (effects.size() >= MAX_EFFECTS) break;
            CompoundTag tag = (CompoundTag) effect.save();
            effects.add(tag);
        }

        return new PlayerState(
                player.gameMode.getGameModeForPlayer(),
                effects,
                abilities.mayfly,
                abilities.flying,
                abilities.invulnerable,
                abilities.instabuild
        );
    }

    private static void restorePlayerState(ServerPlayer player) {
        UUID uuid = player.getUUID();
        PlayerState state = originalStates.get(uuid);

        if (state == null) {
            GameType mode = DataManager.getPlayerGameMode(uuid);
            if (mode == null) mode = GameType.SURVIVAL;
            player.setGameMode(mode);
            player.removeEffect(MobEffects.BLINDNESS);
            return;
        }

        player.removeAllEffects();
        player.setGameMode(state.gameType());

        for (CompoundTag tag : state.effectTags()) {
            MobEffectInstance effect = MobEffectInstance.load(tag);
            if (effect != null && !effect.getEffect().is(MobEffects.BLINDNESS)) {
                player.addEffect(effect);
            }
        }

        var abilities = player.getAbilities();
        abilities.mayfly = state.mayFly();
        abilities.flying = state.isFlying();
        abilities.invulnerable = state.invulnerable();
        abilities.instabuild = state.instabuild();
        player.onUpdateAbilities();

        DataManager.setPlayerGameMode(uuid, state.gameType());
    }

    private static void promptForAuth(ServerPlayer player) {
        String key = RegisterCommand.isRegistered(player.getUUID())
                ? "command.larbaco_auth.login.prompt"
                : "command.larbaco_auth.register.prompt";
        MessageHelper.sendInfo(player, key);
    }

    private static void restrictPlayer(ServerPlayer player) {
        player.setGameMode(GameType.SPECTATOR);
        player.addEffect(new MobEffectInstance(MobEffects.BLINDNESS, Integer.MAX_VALUE, 1, false, false));
        player.getActiveEffects().stream()
                .filter(e -> !e.getEffect().is(MobEffects.BLINDNESS))
                .toList()
                .forEach(e -> player.removeEffect(e.getEffect()));
        player.setDeltaMovement(Vec3.ZERO);
    }

    private static void enforcePosition(ServerPlayer player) {
        UUID uuid = player.getUUID();
        Vec3 lastPos = lastPositions.getOrDefault(uuid, player.position());

        player.setDeltaMovement(Vec3.ZERO);

        if (player.position().distanceToSqr(lastPos) >= POSITION_EPSILON * POSITION_EPSILON) {
            player.teleportTo(player.serverLevel(), lastPos.x, lastPos.y, lastPos.z,
                    player.getYRot(), player.getXRot());
        }

        lastPositions.put(uuid, player.position());
    }

    private static void cancelIfUnauthenticated(ServerPlayer player, Runnable action, String key) {
        if (!LarbacoAuthMain.isPlayerAuthenticated(player.getUUID())) {
            action.run();
            MessageHelper.sendError(player, key);
        }
    }

    private static void clearSessionData(UUID uuid) {
        lastPositions.remove(uuid);
        originalStates.remove(uuid);
        LoginCommand.cleanupPlayerData(uuid);
    }

    public static void clearAllPlayerData(UUID uuid) {
        clearSessionData(uuid);
        DataManager.removePlayerGameMode(uuid);
        LarbacoAuthMain.setAuthenticated(uuid, false);
    }

    public static void resetPlayerGameMode(UUID uuid, GameType gameType) {
        DataManager.setPlayerGameMode(uuid, gameType);
    }

    public static GameType getPersistentGameMode(UUID uuid) {
        return DataManager.getPlayerGameMode(uuid);
    }

    private static record PlayerState(
            GameType gameType,
            List<CompoundTag> effectTags,
            boolean mayFly,
            boolean isFlying,
            boolean invulnerable,
            boolean instabuild
    ) {}
}