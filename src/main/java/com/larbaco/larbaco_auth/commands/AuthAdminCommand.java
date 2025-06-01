package com.larbaco.larbaco_auth.commands;

import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.handlers.AuthSessionManager;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.monitoring.SystemMonitor;
import com.larbaco.larbaco_auth.storage.DataManager;
import com.larbaco.larbaco_auth.utils.MessageHelper;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.arguments.EntityArgument;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.util.List;

/**
 * Administrative command system for LarbacoAuth
 * Provides system management, monitoring, and logging functionality
 */
public class AuthAdminCommand {
    private static final int REQUIRED_PERMISSION_LEVEL = 3; // Operator level

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("authman")
                .requires(source -> source.hasPermission(REQUIRED_PERMISSION_LEVEL))

                // System Management Commands
                .then(Commands.literal("reload")
                        .executes(AuthAdminCommand::reloadConfig))

                .then(Commands.literal("cleanup")
                        .executes(AuthAdminCommand::cleanupSessions))

                .then(Commands.literal("stats")
                        .executes(AuthAdminCommand::showStats))

                .then(Commands.literal("status")
                        .executes(AuthAdminCommand::showStatus))

                // Logging Commands
                .then(Commands.literal("logs")
                        .then(Commands.argument("player", EntityArgument.player())
                                .executes(AuthAdminCommand::showPlayerLogs)
                                .then(Commands.argument("lines", IntegerArgumentType.integer(1, 100))
                                        .executes(AuthAdminCommand::showPlayerLogsWithLimit)))
                        .executes(AuthAdminCommand::showRecentLogs))

                .then(Commands.literal("monitor")
                        .then(Commands.literal("start")
                                .executes(AuthAdminCommand::startMonitoring))
                        .then(Commands.literal("stop")
                                .executes(AuthAdminCommand::stopMonitoring))
                        .then(Commands.literal("report")
                                .executes(AuthAdminCommand::generateMonitoringReport)))

                // Database Management
                .then(Commands.literal("database")
                        .then(Commands.literal("backup")
                                .executes(AuthAdminCommand::backupDatabase))
                        .then(Commands.literal("optimize")
                                .executes(AuthAdminCommand::optimizeDatabase))
                        .then(Commands.literal("verify")
                                .executes(AuthAdminCommand::verifyDatabase)))

                // System Information
                .then(Commands.literal("info")
                        .executes(AuthAdminCommand::showSystemInfo))

                .then(Commands.literal("help")
                        .executes(AuthAdminCommand::showHelp))
        );
    }

    private static int reloadConfig(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            // Log the reload attempt
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";
            AuthLogger.logAdminAction(adminName, "CONFIG_RELOAD", "Attempting to reload configuration");

            // Reload configuration
            Config.reload();

            // Reload translations
            LarbacoAuthMain.loadTranslations();

            // Verify configuration
            boolean configValid = Config.validate();

            if (configValid) {
                source.sendSuccess(() -> Component.literal("§a✓ Configuration reloaded successfully"), true);
                AuthLogger.logAdminAction(adminName, "CONFIG_RELOAD", "Configuration reloaded successfully");

                // Show updated config values
                source.sendSuccess(() -> Component.literal("§7Current settings:"), false);
                source.sendSuccess(() -> Component.literal(String.format(
                        "§7- Max login attempts: §e%d", Config.maxLoginAttempts)), false);
                source.sendSuccess(() -> Component.literal(String.format(
                        "§7- Session duration: §e%d minutes", Config.sessionDuration)), false);
                source.sendSuccess(() -> Component.literal(String.format(
                        "§7- Require mixed case: §e%s", Config.requireMixedCase)), false);
                source.sendSuccess(() -> Component.literal(String.format(
                        "§7- Require special char: §e%s", Config.requireSpecialChar)), false);

                return Command.SINGLE_SUCCESS;
            } else {
                source.sendFailure(Component.literal("§c✗ Configuration reload failed - invalid values detected"));
                AuthLogger.logAdminAction(adminName, "CONFIG_RELOAD", "Configuration reload failed - validation error");
                return 0;
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error reloading configuration: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error reloading configuration: " + e.getMessage()));
            return 0;
        }
    }

    private static int cleanupSessions(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            AuthLogger.logAdminAction(adminName, "SESSION_CLEANUP", "Starting session cleanup");

            // Get stats before cleanup
            String beforeStats = AuthSessionManager.getSessionStats();

            // Perform cleanup
            int cleanedSessions = AuthSessionManager.forceCleanup();
            int cleanedOperations = AuthSessionManager.cleanupPendingOperations();

            // Log results
            String afterStats = AuthSessionManager.getSessionStats();

            source.sendSuccess(() -> Component.literal(String.format(
                    "§a✓ Session cleanup completed:\n" +
                            "§7- Expired sessions removed: §e%d\n" +
                            "§7- Pending operations cleared: §e%d\n" +
                            "§7- Before: %s\n" +
                            "§7- After: %s",
                    cleanedSessions, cleanedOperations, beforeStats, afterStats)), true);

            AuthLogger.logAdminAction(adminName, "SESSION_CLEANUP",
                    String.format("Cleanup completed: %d sessions, %d operations", cleanedSessions, cleanedOperations));

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during session cleanup: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error during cleanup: " + e.getMessage()));
            return 0;
        }
    }

    private static int showStats(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            // Gather comprehensive statistics
            var stats = SystemMonitor.getSystemStatistics();

            source.sendSuccess(() -> Component.literal("§6=== LarbacoAuth System Statistics ==="), false);
            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Authentication:\n" +
                            "§7- Registered players: §e%d\n" +
                            "§7- Currently authenticated: §e%d\n" +
                            "§7- Total login attempts (session): §e%d\n" +
                            "§7- Failed login attempts (session): §e%d\n" +
                            "§7- Success rate: §e%.1f%%",
                    stats.registeredPlayers(),
                    stats.authenticatedPlayers(),
                    stats.totalLoginAttempts(),
                    stats.failedLoginAttempts(),
                    stats.successRate())), false);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Sessions:\n" +
                            "§7- Active sessions: §e%d\n" +
                            "§7- Pending operations: §e%d\n" +
                            "§7- Sessions created (session): §e%d\n" +
                            "§7- Sessions expired (session): §e%d",
                    stats.activeSessions(),
                    stats.pendingOperations(),
                    stats.sessionsCreated(),
                    stats.sessionsExpired())), false);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Performance:\n" +
                            "§7- Average auth time: §e%.2fms\n" +
                            "§7- Database operations: §e%d\n" +
                            "§7- Memory usage: §e%.1fMB\n" +
                            "§7- Uptime: §e%s",
                    stats.averageAuthTime(),
                    stats.databaseOperations(),
                    stats.memoryUsageMB(),
                    stats.uptime())), false);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error generating statistics: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error generating statistics: " + e.getMessage()));
            return 0;
        }
    }

    private static int showStatus(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            // Check system health
            var healthCheck = SystemMonitor.performHealthCheck();

            source.sendSuccess(() -> Component.literal("§6=== LarbacoAuth System Status ==="), false);

            // Overall status
            String statusColor = healthCheck.isHealthy() ? "§a" : "§c";
            String statusText = healthCheck.isHealthy() ? "HEALTHY" : "UNHEALTHY";
            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Overall Status: %s%s", statusColor, statusText)), false);

            // Component status
            source.sendSuccess(() -> Component.literal("§7Component Status:"), false);
            for (var component : healthCheck.componentStatus().entrySet()) {
                String compColor = component.getValue() ? "§a✓" : "§c✗";
                source.sendSuccess(() -> Component.literal(String.format(
                        "§7- %s: %s", component.getKey(), compColor)), false);
            }

            // Warnings and errors
            if (!healthCheck.warnings().isEmpty()) {
                source.sendSuccess(() -> Component.literal("§6Warnings:"), false);
                for (String warning : healthCheck.warnings()) {
                    source.sendSuccess(() -> Component.literal("§6- " + warning), false);
                }
            }

            if (!healthCheck.errors().isEmpty()) {
                source.sendSuccess(() -> Component.literal("§cErrors:"), false);
                for (String error : healthCheck.errors()) {
                    source.sendSuccess(() -> Component.literal("§c- " + error), false);
                }
            }

            // Performance metrics
            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Performance: %s", healthCheck.performanceStatus())), false);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error checking system status: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error checking system status: " + e.getMessage()));
            return 0;
        }
    }

    private static int showPlayerLogs(CommandContext<CommandSourceStack> context) {
        return showPlayerLogsWithLimit(context, 10);
    }

    private static int showPlayerLogsWithLimit(CommandContext<CommandSourceStack> context) {
        try {
            ServerPlayer targetPlayer = EntityArgument.getPlayer(context, "player");
            int limit = context.getNodes().size() > 3 ?
                    IntegerArgumentType.getInteger(context, "lines") : 10;

            return showPlayerLogsWithLimit(context, limit, targetPlayer);

        } catch (Exception e) {
            context.getSource().sendFailure(Component.literal("§c✗ Error retrieving player logs: " + e.getMessage()));
            return 0;
        }
    }

    private static int showPlayerLogsWithLimit(CommandContext<CommandSourceStack> context, int limit) {
        try {
            ServerPlayer targetPlayer = EntityArgument.getPlayer(context, "player");
            return showPlayerLogsWithLimit(context, limit, targetPlayer);
        } catch (Exception e) {
            context.getSource().sendFailure(Component.literal("§c✗ Error retrieving player logs: " + e.getMessage()));
            return 0;
        }
    }

    private static int showPlayerLogsWithLimit(CommandContext<CommandSourceStack> context, int limit, ServerPlayer targetPlayer) {
        try {
            var source = context.getSource();

            List<AuthLogger.LogEntry> logs = AuthLogger.getPlayerLogs(targetPlayer.getUUID(), limit);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§6=== Authentication Logs for %s (Last %d entries) ===",
                    targetPlayer.getName().getString(), Math.min(logs.size(), limit))), false);

            if (logs.isEmpty()) {
                source.sendSuccess(() -> Component.literal("§7No authentication logs found for this player"), false);
                return Command.SINGLE_SUCCESS;
            }

            for (AuthLogger.LogEntry log : logs) {
                String typeColor = switch (log.type()) {
                    case "LOGIN_SUCCESS" -> "§a";
                    case "LOGIN_FAILED" -> "§c";
                    case "REGISTER_SUCCESS" -> "§b";
                    case "SESSION_CREATED" -> "§e";
                    case "ACCOUNT_LOCKED" -> "§4";
                    default -> "§7";
                };

                source.sendSuccess(() -> Component.literal(String.format(
                        "§7[%s] %s%s §7- %s",
                        log.formattedTimestamp(), typeColor, log.type(), log.details())), false);
            }

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error showing player logs: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error showing player logs: " + e.getMessage()));
            return 0;
        }
    }

    private static int showRecentLogs(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            List<AuthLogger.LogEntry> logs = AuthLogger.getRecentLogs(20);

            source.sendSuccess(() -> Component.literal("§6=== Recent Authentication Activity (Last 20 entries) ==="), false);

            if (logs.isEmpty()) {
                source.sendSuccess(() -> Component.literal("§7No recent authentication activity"), false);
                return Command.SINGLE_SUCCESS;
            }

            for (AuthLogger.LogEntry log : logs) {
                String typeColor = switch (log.type()) {
                    case "LOGIN_SUCCESS" -> "§a";
                    case "LOGIN_FAILED" -> "§c";
                    case "REGISTER_SUCCESS" -> "§b";
                    case "ADMIN_ACTION" -> "§d";
                    case "SYSTEM_EVENT" -> "§6";
                    default -> "§7";
                };

                source.sendSuccess(() -> Component.literal(String.format(
                        "§7[%s] %s%s §7- §f%s §7- %s",
                        log.formattedTimestamp(), typeColor, log.type(),
                        log.playerName(), log.details())), false);
            }

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error showing recent logs: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error showing recent logs: " + e.getMessage()));
            return 0;
        }
    }

    private static int startMonitoring(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            boolean started = SystemMonitor.startRealTimeMonitoring();

            if (started) {
                source.sendSuccess(() -> Component.literal("§a✓ Real-time monitoring started"), true);
                AuthLogger.logAdminAction(adminName, "MONITORING_START", "Real-time monitoring enabled");
            } else {
                source.sendSuccess(() -> Component.literal("§7Real-time monitoring was already running"), false);
            }

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error starting monitoring: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error starting monitoring: " + e.getMessage()));
            return 0;
        }
    }

    private static int stopMonitoring(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            boolean stopped = SystemMonitor.stopRealTimeMonitoring();

            if (stopped) {
                source.sendSuccess(() -> Component.literal("§a✓ Real-time monitoring stopped"), true);
                AuthLogger.logAdminAction(adminName, "MONITORING_STOP", "Real-time monitoring disabled");
            } else {
                source.sendSuccess(() -> Component.literal("§7Real-time monitoring was not running"), false);
            }

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error stopping monitoring: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error stopping monitoring: " + e.getMessage()));
            return 0;
        }
    }

    private static int generateMonitoringReport(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            String reportPath = SystemMonitor.generateDetailedReport();

            source.sendSuccess(() -> Component.literal(String.format(
                    "§a✓ Detailed monitoring report generated:\n§7%s", reportPath)), true);

            AuthLogger.logAdminAction(adminName, "REPORT_GENERATED", "Monitoring report: " + reportPath);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error generating monitoring report: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error generating report: " + e.getMessage()));
            return 0;
        }
    }

    private static int backupDatabase(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            String backupPath = DataManager.createBackup();

            source.sendSuccess(() -> Component.literal(String.format(
                    "§a✓ Database backup created:\n§7%s", backupPath)), true);

            AuthLogger.logAdminAction(adminName, "DATABASE_BACKUP", "Backup created: " + backupPath);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error creating database backup: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error creating backup: " + e.getMessage()));
            return 0;
        }
    }

    private static int optimizeDatabase(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();
            String adminName = source.getEntity() instanceof ServerPlayer player ?
                    player.getName().getString() : "CONSOLE";

            long beforeSize = DataManager.getDatabaseSize();
            DataManager.optimizeDatabase();
            long afterSize = DataManager.getDatabaseSize();

            long savedBytes = beforeSize - afterSize;
            String savedFormatted = String.format("%.2f KB", savedBytes / 1024.0);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§a✓ Database optimized\n§7Space saved: %s", savedFormatted)), true);

            AuthLogger.logAdminAction(adminName, "DATABASE_OPTIMIZE", "Space saved: " + savedFormatted);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error optimizing database: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error optimizing database: " + e.getMessage()));
            return 0;
        }
    }

    private static int verifyDatabase(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            var verification = DataManager.verifyIntegrity();

            source.sendSuccess(() -> Component.literal("§6=== Database Integrity Check ==="), false);

            String statusColor = verification.isValid() ? "§a" : "§c";
            String statusText = verification.isValid() ? "VALID" : "CORRUPTED";
            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Status: %s%s", statusColor, statusText)), false);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Total records: §e%d\n" +
                            "§7Valid records: §e%d\n" +
                            "§7Corrupted records: §e%d",
                    verification.totalRecords(),
                    verification.validRecords(),
                    verification.corruptedRecords())), false);

            if (!verification.issues().isEmpty()) {
                source.sendSuccess(() -> Component.literal("§cIssues found:"), false);
                for (String issue : verification.issues()) {
                    source.sendSuccess(() -> Component.literal("§c- " + issue), false);
                }
            }

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error verifying database: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error verifying database: " + e.getMessage()));
            return 0;
        }
    }

    private static int showSystemInfo(CommandContext<CommandSourceStack> context) {
        try {
            var source = context.getSource();

            source.sendSuccess(() -> Component.literal("§6=== LarbacoAuth System Information ==="), false);
            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Version: §e%s\n" +
                            "§7NeoForge Version: §e%s\n" +
                            "§7Minecraft Version: §e%s\n" +
                            "§7Initialized: §e%s\n" +
                            "§7Language: §e%s",
                    LarbacoAuthMain.getVersion(),
                    LarbacoAuthMain.getNeoForgeVersion(),
                    LarbacoAuthMain.getMinecraftVersion(),
                    LarbacoAuthMain.isInitialized() ? "Yes" : "No",
                    LarbacoAuthMain.getCurrentLanguage())), false);

            source.sendSuccess(() -> Component.literal(String.format(
                    "§7Configuration:\n" +
                            "§7- Config file: §e%s\n" +
                            "§7- Data directory: §e%s\n" +
                            "§7- Log level: §e%s",
                    Config.getConfigPath(),
                    DataManager.getDataDirectory(),
                    LarbacoAuthMain.getLogLevel())), false);

            return Command.SINGLE_SUCCESS;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error showing system info: {}", e.getMessage(), e);
            context.getSource().sendFailure(Component.literal("§c✗ Error showing system info: " + e.getMessage()));
            return 0;
        }
    }

    private static int showHelp(CommandContext<CommandSourceStack> context) {
        var source = context.getSource();

        source.sendSuccess(() -> Component.literal("§6=== LarbacoAuth Admin Commands ==="), false);
        source.sendSuccess(() -> Component.literal("§7System Management:"), false);
        source.sendSuccess(() -> Component.literal("§e/authman reload §7- Reload configuration"), false);
        source.sendSuccess(() -> Component.literal("§e/authman cleanup §7- Clean expired sessions"), false);
        source.sendSuccess(() -> Component.literal("§e/authman stats §7- Show system statistics"), false);
        source.sendSuccess(() -> Component.literal("§e/authman status §7- Show system health status"), false);

        source.sendSuccess(() -> Component.literal("§7Logging & Monitoring:"), false);
        source.sendSuccess(() -> Component.literal("§e/authman logs [player] [lines] §7- Show authentication logs"), false);
        source.sendSuccess(() -> Component.literal("§e/authman monitor start/stop §7- Control real-time monitoring"), false);
        source.sendSuccess(() -> Component.literal("§e/authman monitor report §7- Generate detailed report"), false);

        source.sendSuccess(() -> Component.literal("§7Database Management:"), false);
        source.sendSuccess(() -> Component.literal("§e/authman database backup §7- Create database backup"), false);
        source.sendSuccess(() -> Component.literal("§e/authman database optimize §7- Optimize database"), false);
        source.sendSuccess(() -> Component.literal("§e/authman database verify §7- Check database integrity"), false);

        source.sendSuccess(() -> Component.literal("§7Information:"), false);
        source.sendSuccess(() -> Component.literal("§e/authman info §7- Show system information"), false);
        source.sendSuccess(() -> Component.literal("§e/authman help §7- Show this help"), false);

        return Command.SINGLE_SUCCESS;
    }
}