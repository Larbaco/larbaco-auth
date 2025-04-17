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

import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.config.ModConfigEvent;
import net.neoforged.neoforge.common.ModConfigSpec;

@EventBusSubscriber(modid = LarbacoAuthMain.MODID, bus = EventBusSubscriber.Bus.MOD)
public class Config {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    // Security Settings
    public static final ModConfigSpec.IntValue MAX_LOGIN_ATTEMPTS = BUILDER
            .comment("Maximum allowed failed login attempts before IP ban")
            .defineInRange("maxLoginAttempts", 3, 1, 10);

    public static final ModConfigSpec.IntValue SESSION_DURATION = BUILDER
            .comment("Session duration in minutes")
            .defineInRange("sessionDuration", 30, 5, 1440);

    public static final ModConfigSpec.BooleanValue REQUIRE_MIXED_CASE = BUILDER
            .comment("Require passwords to have mixed case letters")
            .define("requireMixedCase", true);

    public static final ModConfigSpec.BooleanValue REQUIRE_SPECIAL_CHAR = BUILDER
            .comment("Require passwords to contain special characters")
            .define("requireSpecialChar", true);

    static final ModConfigSpec SPEC = BUILDER.build();

    // Runtime values
    public static int maxLoginAttempts;
    public static int sessionDuration;
    public static boolean requireMixedCase;
    public static boolean requireSpecialChar;

    @SubscribeEvent
    static void onLoad(final ModConfigEvent event) {
        maxLoginAttempts = MAX_LOGIN_ATTEMPTS.get();
        sessionDuration = SESSION_DURATION.get();
        requireMixedCase = REQUIRE_MIXED_CASE.get();
        requireSpecialChar = REQUIRE_SPECIAL_CHAR.get();
    }
}