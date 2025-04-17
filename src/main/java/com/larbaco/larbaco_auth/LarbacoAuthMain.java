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

package com.larbaco.larbaco_auth;

import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import org.slf4j.Logger;
import com.mojang.logging.LogUtils;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.fml.common.EventBusSubscriber;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Mod(LarbacoAuthMain.MODID)
public class LarbacoAuthMain {
    public static final String MODID = "larbaco_auth";
    public static final Logger LOGGER = LogUtils.getLogger();

    // Temporary authentication storage
    private static final Set<UUID> authenticatedPlayers = new HashSet<>();

    public static boolean isPlayerAuthenticated(UUID uuid) {
        return authenticatedPlayers.contains(uuid);
    }

    public static void setAuthenticated(UUID uuid, boolean status) {
        if(status) {
            authenticatedPlayers.add(uuid);
        } else {
            authenticatedPlayers.remove(uuid);
        }
    }

    public LarbacoAuthMain(IEventBus modEventBus, ModContainer modContainer) {
        // Register server config
        modContainer.registerConfig(ModConfig.Type.COMMON, Config.SPEC);

        LOGGER.info("Larbaco Auth initialized"); // Removed event bus registration
    }

    // Client-side stub
    @EventBusSubscriber(modid = MODID, bus = EventBusSubscriber.Bus.MOD, value = Dist.CLIENT)
    public static class ClientModEvents {
        @SubscribeEvent
        public static void onClientSetup(FMLClientSetupEvent event) {
            // Empty client setup
        }
    }
}