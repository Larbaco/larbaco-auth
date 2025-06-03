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

package com.larbaco.larbaco_auth.handlers;

import com.larbaco.larbaco_auth.Config;
import com.larbaco.larbaco_auth.LarbacoAuthMain;
import com.larbaco.larbaco_auth.monitoring.AuthLogger;
import com.larbaco.larbaco_auth.monitoring.SystemMonitor;
import net.minecraft.server.level.ServerPlayer;
import org.apache.commons.lang3.RandomStringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class AuthSessionManager {

    private static final Map<String, SessionData> sessions = new ConcurrentHashMap<>();
    private static final Map<UUID, OperationType> pendingOperations = new ConcurrentHashMap<>();

    private static final Map<UUID, String> lastKnownIPs = new ConcurrentHashMap<>();
    private static final Map<String, Long> ipSuspiciousActivity = new ConcurrentHashMap<>();
    private static final Map<String, AtomicInteger> ipFailureCount = new ConcurrentHashMap<>();

    private static final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();

    private static final String SECRET_PASSPHRASE = "LarbacoAuth2025SecurePassphrase!";
    private static final byte[] SECRET_KEY = createFixedLengthKey(SECRET_PASSPHRASE);

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, r -> {
        Thread t = new Thread(r, "LarbacoAuth-SessionManager");
        t.setDaemon(true);
        t.setUncaughtExceptionHandler((thread, ex) ->
                LarbacoAuthMain.LOGGER.error("Uncaught exception in SessionManager thread: {}", ex.getMessage(), ex));
        return t;
    });

    private static final AtomicInteger totalSessionsCreated = new AtomicInteger(0);
    private static final AtomicInteger totalSessionsExpired = new AtomicInteger(0);
    private static final AtomicInteger totalSessionsValidated = new AtomicInteger(0);
    private static final AtomicInteger totalIPMismatchRejections = new AtomicInteger(0);
    private static final AtomicInteger totalIPValidationBypass = new AtomicInteger(0);
    private static final AtomicInteger totalSuspiciousIPBlocks = new AtomicInteger(0);

    private static volatile boolean initialized = false;

    private static int getMaxIPFailures() {
        return Config.ipFailureThreshold;
    }

    private static long getBlockDurationMs() {
        return Config.ipBlockDuration * 60000L;
    }

    static {
        initialize();
    }

    private static void initialize() {
        try {
            scheduler.scheduleAtFixedRate(AuthSessionManager::cleanExpiredSessions, 30, 30, TimeUnit.SECONDS);
            scheduler.scheduleAtFixedRate(AuthSessionManager::logStatistics, 5, 5, TimeUnit.MINUTES);
            scheduler.scheduleAtFixedRate(AuthSessionManager::cleanupIPTracking, 60, 60, TimeUnit.SECONDS);

            initialized = true;
            SystemMonitor.updateComponentHealth("SessionManager", true, null);

            LarbacoAuthMain.LOGGER.info("AuthSessionManager initialized with {}-bit AES encryption and configurable IP validation",
                    SECRET_KEY.length * 8);
            AuthLogger.logSystemEvent("SESSION_MANAGER_INIT",
                    "Session manager initialized with configuration-driven IP validation");

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to initialize AuthSessionManager: {}", e.getMessage(), e);
            throw new RuntimeException("SessionManager initialization failed", e);
        }
    }

    public static SessionData getSessionWithoutValidation(String token) {
        if (!initialized || token == null) return null;

        SessionData data = sessions.get(token);
        if (data == null) return null;

        if (data.isExpired()) {
            removeExpiredSession(token, data);
            return null;
        }

        LarbacoAuthMain.LOGGER.debug("Session found and valid for token: {}, IP-bound: {}",
                token.substring(0, Math.min(4, token.length())) + "...",
                data.getCreatorIP() != null ? "yes" : "no");
        return data;
    }

    public static String createSession(ServerPlayer player, String password, OperationType operation) {
        if (!initialized) {
            LarbacoAuthMain.LOGGER.error("Attempted to create session before initialization");
            return null;
        }

        UUID playerId = player.getUUID();
        String token = generateToken();

        try {
            String encryptedPassword = encryptPassword(password);
            String playerIP = extractAndValidatePlayerIP(player);

            if (playerIP != null && isIPSuspicious(playerIP)) {
                LarbacoAuthMain.LOGGER.warn("Blocking session creation from suspicious IP: {}", maskIP(playerIP));
                AuthLogger.logAuthEvent(playerId, player.getScoreboardName(), "SESSION_BLOCKED",
                        "Session creation blocked from suspicious IP: " + maskIP(playerIP));
                return null;
            }

            SessionData sessionData = new SessionData(playerId, encryptedPassword, operation, playerIP);
            sessions.put(token, sessionData);

            if (playerIP != null) {
                updatePlayerIPTracking(playerId, playerIP);
            }

            totalSessionsCreated.incrementAndGet();
            SystemMonitor.recordSessionCreated();

            logSessionCreation(player, token, operation, playerIP);

            return token;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error creating auth session for {}: {}",
                    player.getScoreboardName(), e.getMessage(), e);
            SystemMonitor.updateComponentHealth("SessionManager", false,
                    "Session creation failed: " + e.getMessage());
            return null;
        }
    }

    public static SessionData validateSession(String token) {
        if (!initialized || token == null) return null;

        SessionData data = sessions.get(token);
        if (data == null) return null;

        if (data.isExpired()) {
            removeExpiredSession(token, data);
            return null;
        }

        sessions.remove(token);
        totalSessionsValidated.incrementAndGet();

        LarbacoAuthMain.LOGGER.debug("Session validated and removed for token: {}",
                token.substring(0, 4) + "...");

        AuthLogger.logAuthEvent(data.getPlayerId(), "UNKNOWN", "SESSION_VALIDATED",
                String.format("Token: %s..., Age: %dms, IP-bound: %s, Security-level: %s",
                        token.substring(0, 4), data.getAge(),
                        data.getCreatorIP() != null ? "yes" : "no",
                        Config.enableSessionIPValidation ? "enhanced" : "basic"));

        return data;
    }

    public static SessionData validateSessionWithIP(String token, ServerPlayer player) {
        if (!initialized || token == null || player == null) return null;

        SessionData data = sessions.get(token);
        if (data == null || data.isExpired()) {
            if (data != null) removeExpiredSession(token, data);
            return null;
        }

        IPValidation.Result ipResult = performIPValidation(data, player);

        return switch (ipResult.status()) {
            case VALID -> consumeValidSession(token, data, player);
            case INVALID_MISMATCH -> {
                handleIPMismatch(data, player, ipResult.details());
                yield null;
            }
            case INVALID_SUSPICIOUS -> {
                handleSuspiciousIP(data, player, ipResult.details());
                yield null;
            }
            case BYPASS_ALLOWED -> {
                LarbacoAuthMain.LOGGER.info("IP validation bypassed for player {}: {}",
                        player.getScoreboardName(), ipResult.details());

                totalIPValidationBypass.incrementAndGet();
                AuthLogger.logAuthEvent(data.getPlayerId(), player.getScoreboardName(),
                        "SESSION_IP_BYPASS", ipResult.details());

                yield consumeValidSession(token, data, player);
            }
        };
    }

    public static void setPendingOperation(UUID playerId, OperationType operation) {
        pendingOperations.put(playerId, operation);
    }

    public static OperationType getPendingOperation(UUID playerId) {
        return pendingOperations.get(playerId);
    }

    public static void clearPendingOperation(UUID playerId) {
        pendingOperations.remove(playerId);
    }

    public static String getSessionStats() {
        return String.format("Active sessions: %d, Pending operations: %d, Created (total): %d, " +
                        "Expired (total): %d, Validated (total): %d, IP rejections: %d, " +
                        "IP bypasses: %d, Suspicious blocks: %d",
                sessions.size(), pendingOperations.size(), totalSessionsCreated.get(),
                totalSessionsExpired.get(), totalSessionsValidated.get(), totalIPMismatchRejections.get(),
                totalIPValidationBypass.get(), totalSuspiciousIPBlocks.get());
    }

    public static SessionStatistics getDetailedStatistics() {
        long oldestSessionAge = sessions.values().stream()
                .mapToLong(SessionData::getAge)
                .max()
                .orElse(0);

        Map<OperationType, Long> operationCounts = pendingOperations.values().stream()
                .collect(java.util.stream.Collectors.groupingBy(
                        op -> op,
                        java.util.stream.Collectors.counting()));

        long ipBoundSessions = sessions.values().stream()
                .filter(session -> session.getCreatorIP() != null)
                .count();

        ipLock.readLock().lock();
        int suspiciousIPs;
        int trackedIPs;
        try {
            suspiciousIPs = ipSuspiciousActivity.size();
            trackedIPs = lastKnownIPs.size();
        } finally {
            ipLock.readLock().unlock();
        }

        return new SessionStatistics(
                sessions.size(),
                pendingOperations.size(),
                totalSessionsCreated.get(),
                totalSessionsExpired.get(),
                totalSessionsValidated.get(),
                oldestSessionAge,
                operationCounts,
                ipBoundSessions,
                totalIPMismatchRejections.get(),
                totalIPValidationBypass.get(),
                totalSuspiciousIPBlocks.get(),
                suspiciousIPs,
                trackedIPs
        );
    }

    public static int forceCleanup() {
        int beforeCount = sessions.size();

        sessions.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().isExpired();
            if (expired) {
                totalSessionsExpired.incrementAndGet();
                SystemMonitor.recordSessionExpired();

                LarbacoAuthMain.LOGGER.debug("Force removing expired session: {}",
                        entry.getKey().substring(0, 4) + "...");
            }
            return expired;
        });

        int afterCount = sessions.size();
        int removed = beforeCount - afterCount;

        if (removed > 0) {
            LarbacoAuthMain.LOGGER.info("Force cleanup removed {} expired sessions", removed);
            AuthLogger.logSystemEvent("SESSION_FORCE_CLEANUP", "Removed " + removed + " expired sessions");
        }

        return removed;
    }

    public static int cleanupPendingOperations() {
        int beforeCount = pendingOperations.size();
        pendingOperations.clear();
        int removed = beforeCount;

        if (removed > 0) {
            LarbacoAuthMain.LOGGER.info("Force cleanup removed {} pending operations", removed);
            AuthLogger.logSystemEvent("PENDING_OPS_CLEANUP", "Removed " + removed + " pending operations");
        }

        return removed;
    }

    public static boolean isHealthy() {
        try {
            if (sessions.size() > 1000) {
                SystemMonitor.updateComponentHealth("SessionManager", false, "Too many active sessions: " + sessions.size());
                return false;
            }

            if (pendingOperations.size() > 500) {
                SystemMonitor.updateComponentHealth("SessionManager", false, "Too many pending operations: " + pendingOperations.size());
                return false;
            }

            if (Config.enableSessionIPValidation) {
                int totalValidations = totalSessionsValidated.get() + totalIPMismatchRejections.get();
                if (totalValidations > 100) {
                    double rejectionRate = (double) totalIPMismatchRejections.get() / totalValidations;
                    if (rejectionRate > 0.3) {
                        SystemMonitor.updateComponentHealth("SessionManager", false,
                                String.format("High IP rejection rate: %.1f%%", rejectionRate * 100));
                        return false;
                    }
                }

                ipLock.readLock().lock();
                try {
                    if (ipSuspiciousActivity.size() > 50) {
                        SystemMonitor.updateComponentHealth("SessionManager", false,
                                "Too many suspicious IPs: " + ipSuspiciousActivity.size());
                        return false;
                    }
                } finally {
                    ipLock.readLock().unlock();
                }
            }

            SystemMonitor.updateComponentHealth("SessionManager", true, null);
            return true;

        } catch (Exception e) {
            SystemMonitor.updateComponentHealth("SessionManager", false, "Health check failed: " + e.getMessage());
            return false;
        }
    }

    public static void shutdown() {
        try {
            int sessionCount = sessions.size();
            int pendingCount = pendingOperations.size();

            sessions.clear();
            pendingOperations.clear();

            ipLock.writeLock().lock();
            try {
                lastKnownIPs.clear();
                ipSuspiciousActivity.clear();
                ipFailureCount.clear();
            } finally {
                ipLock.writeLock().unlock();
            }

            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdown();
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            }

            initialized = false;

            LarbacoAuthMain.LOGGER.info("AuthSessionManager shutdown: cleared {} sessions and {} pending operations",
                    sessionCount, pendingCount);

            AuthLogger.logSystemEvent("SESSION_MANAGER_SHUTDOWN",
                    String.format("Cleared %d sessions and %d pending operations", sessionCount, pendingCount));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
        }
    }

    private static byte[] createFixedLengthKey(String passphrase) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(passphrase.getBytes(StandardCharsets.UTF_8));
            LarbacoAuthMain.LOGGER.debug("Generated AES key length: {} bytes", keyBytes.length);
            return keyBytes;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to generate AES key: {}", e.getMessage());
            byte[] fallbackKey = new byte[32];
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(passphraseBytes, 0, fallbackKey, 0, Math.min(passphraseBytes.length, 32));
            return fallbackKey;
        }
    }

    private static String generateToken() {
        return RandomStringUtils.randomAlphanumeric(12);
    }

    private static String encryptPassword(String password) throws Exception {
        try {
            Key key = new SecretKeySpec(SECRET_KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            String encoded = java.util.Base64.getEncoder().encodeToString(encrypted);

            LarbacoAuthMain.LOGGER.debug("Password encrypted successfully (length: {} chars)", encoded.length());
            return encoded;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Password encryption failed: {}", e.getMessage());
            throw new Exception("Encryption failed: " + e.getMessage(), e);
        }
    }

    private static IPValidation.Result performIPValidation(SessionData sessionData, ServerPlayer player) {
        if (!Config.enableSessionIPValidation) {
            return new IPValidation.Result(IPValidation.Status.VALID, "IP validation disabled");
        }

        String sessionIP = sessionData.getCreatorIP();
        if (sessionIP == null) {
            return new IPValidation.Result(IPValidation.Status.BYPASS_ALLOWED,
                    "Session was created without IP binding");
        }

        String currentIP = AuthLogger.extractIPFromConnection(player);
        if (currentIP == null) {
            return new IPValidation.Result(IPValidation.Status.INVALID_MISMATCH,
                    "Could not extract current IP for validation");
        }

        if (sessionIP.equals(currentIP)) {
            updateSuccessfulIPValidation(player.getUUID(), currentIP);
            return new IPValidation.Result(IPValidation.Status.VALID,
                    String.format("IP validation passed: %s", maskIP(currentIP)));
        }

        if (isIPSuspicious(currentIP)) {
            return new IPValidation.Result(IPValidation.Status.INVALID_SUSPICIOUS,
                    String.format("Current IP %s is flagged as suspicious", maskIP(currentIP)));
        }

        if (isLegitimateIPChange(sessionData.getPlayerId(), sessionIP, currentIP)) {
            updatePlayerIPTracking(sessionData.getPlayerId(), currentIP);
            return new IPValidation.Result(IPValidation.Status.BYPASS_ALLOWED,
                    String.format("Legitimate IP change detected: %s -> %s",
                            maskIP(sessionIP), maskIP(currentIP)));
        }

        return new IPValidation.Result(IPValidation.Status.INVALID_MISMATCH,
                String.format("IP mismatch: session from %s, request from %s",
                        maskIP(sessionIP), maskIP(currentIP)));
    }

    private static boolean isLegitimateIPChange(UUID playerId, String oldIP, String newIP) {
        try {
            if (Config.allowSubnetChanges) {
                String[] oldParts = oldIP.split("\\.");
                String[] newParts = newIP.split("\\.");

                if (oldParts.length == 4 && newParts.length == 4) {
                    boolean sameSubnet = oldParts[0].equals(newParts[0]) &&
                            oldParts[1].equals(newParts[1]) &&
                            oldParts[2].equals(newParts[2]);

                    LarbacoAuthMain.LOGGER.debug("IP change within same subnet for player {}: {} -> {}",
                            playerId, maskIP(oldIP), maskIP(newIP));
                    return true;
                }
            }

            String lastKnownIP = lastKnownIPs.get(playerId);
            if (lastKnownIP != null && !lastKnownIP.equals(oldIP)) {
                LarbacoAuthMain.LOGGER.debug("Player {} has history of IP changes, allowing: {} -> {}",
                        playerId, maskIP(oldIP), maskIP(newIP));
                return true;
            }

            return false;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.warn("Error checking IP change legitimacy: {}", e.getMessage());
            return false;
        }
    }

    private static void handleIPMismatch(SessionData sessionData, ServerPlayer player, String details) {
        UUID playerId = player.getUUID();
        String playerName = player.getScoreboardName();

        totalIPMismatchRejections.incrementAndGet();
        recordIPFailure(AuthLogger.extractIPFromConnection(player));

        LarbacoAuthMain.LOGGER.warn("IP mismatch for player {}: {}", playerName, details);

        AuthLogger.logAuthEvent(playerId, playerName, "SESSION_IP_MISMATCH",
                details + " - possible session hijacking attempt");
    }

    private static void handleSuspiciousIP(SessionData sessionData, ServerPlayer player, String details) {
        UUID playerId = player.getUUID();
        String playerName = player.getScoreboardName();
        String currentIP = AuthLogger.extractIPFromConnection(player);

        totalSuspiciousIPBlocks.incrementAndGet();

        LarbacoAuthMain.LOGGER.warn("Suspicious IP activity blocked for player {}: {}", playerName, details);

        AuthLogger.logAuthEvent(playerId, playerName, "SESSION_SUSPICIOUS_IP",
                details + " - IP: " + maskIP(currentIP));

        if (currentIP != null) {
            blockSuspiciousIP(currentIP);
        }
    }

    private static SessionData consumeValidSession(String token, SessionData data, ServerPlayer player) {
        sessions.remove(token);
        totalSessionsValidated.incrementAndGet();

        LarbacoAuthMain.LOGGER.debug("Session validated with enhanced IP check and removed for token: {}",
                token.substring(0, 4) + "...");

        AuthLogger.logAuthEvent(data.getPlayerId(), player.getScoreboardName(), "SESSION_VALIDATED",
                String.format("Token: %s..., Age: %dms, IP: %s, Enhanced-security: enabled",
                        token.substring(0, 4), data.getAge(),
                        data.getCreatorIP() != null ? maskIP(data.getCreatorIP()) : "none"));

        return data;
    }

    private static String extractAndValidatePlayerIP(ServerPlayer player) {
        if (!Config.enableSessionIPValidation) return null;

        try {
            String playerIP = AuthLogger.extractIPFromConnection(player);
            if (playerIP != null && isValidIP(playerIP)) {
                AuthLogger.storePlayerIP(player.getUUID(), playerIP);
                LarbacoAuthMain.LOGGER.debug("Captured and validated IP {} for session creation",
                        maskIP(playerIP));
                return playerIP;
            }

            LarbacoAuthMain.LOGGER.warn("Invalid or null IP extracted for player {} - session will work from any IP",
                    player.getScoreboardName());
            return null;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error extracting IP for player {}: {}",
                    player.getScoreboardName(), e.getMessage());
            return null;
        }
    }

    private static void updatePlayerIPTracking(UUID playerId, String ip) {
        ipLock.writeLock().lock();
        try {
            String previousIP = lastKnownIPs.put(playerId, ip);
            if (previousIP != null && !previousIP.equals(ip)) {
                LarbacoAuthMain.LOGGER.debug("Player {} IP changed: {} -> {}",
                        playerId, maskIP(previousIP), maskIP(ip));
            }
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    private static void updateSuccessfulIPValidation(UUID playerId, String ip) {
        updatePlayerIPTracking(playerId, ip);

        ipLock.writeLock().lock();
        try {
            ipFailureCount.remove(ip);
            ipSuspiciousActivity.remove(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    private static void recordIPFailure(String ip) {
        if (ip == null) return;

        ipLock.writeLock().lock();
        try {
            AtomicInteger count = ipFailureCount.computeIfAbsent(ip, k -> new AtomicInteger(0));
            int failures = count.incrementAndGet();

            if (failures >= getMaxIPFailures()) {
                blockSuspiciousIP(ip);
                LarbacoAuthMain.LOGGER.warn("IP {} blocked due to {} failures (threshold: {})",
                        maskIP(ip), failures, getMaxIPFailures());
            }
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    private static void blockSuspiciousIP(String ip) {
        ipLock.writeLock().lock();
        try {
            ipSuspiciousActivity.put(ip, System.currentTimeMillis() + getBlockDurationMs());
            AuthLogger.logSystemEvent("IP_BLOCKED",
                    String.format("IP %s blocked for suspicious activity for %d minutes",
                            maskIP(ip), Config.ipBlockDuration));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    private static boolean isIPSuspicious(String ip) {
        if (ip == null) return false;

        ipLock.readLock().lock();
        try {
            Long blockUntil = ipSuspiciousActivity.get(ip);
            return blockUntil != null && System.currentTimeMillis() < blockUntil;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    private static boolean isValidIP(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;

        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            try {
                for (String part : parts) {
                    int num = Integer.parseInt(part);
                    if (num < 0 || num > 255) return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return ip.contains(":") && ip.length() > 2;
    }

    private static void cleanupIPTracking() {
        try {
            long currentTime = System.currentTimeMillis();
            int removedSuspicious = 0;

            ipLock.writeLock().lock();
            try {
                var suspiciousIterator = ipSuspiciousActivity.entrySet().iterator();
                while (suspiciousIterator.hasNext()) {
                    var entry = suspiciousIterator.next();
                    if (currentTime > entry.getValue()) {
                        suspiciousIterator.remove();
                        removedSuspicious++;
                    }
                }

                if (ipFailureCount.size() > 100) {
                    ipFailureCount.clear();
                }

            } finally {
                ipLock.writeLock().unlock();
            }

            if (removedSuspicious > 0) {
                LarbacoAuthMain.LOGGER.debug("IP cleanup: removed {} suspicious entries", removedSuspicious);
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during IP tracking cleanup: {}", e.getMessage(), e);
        }
    }

    private static void logSessionCreation(ServerPlayer player, String token, OperationType operation, String playerIP) {
        LarbacoAuthMain.LOGGER.debug("Created session for player {} with operation {} and IP binding: {}",
                player.getScoreboardName(), operation, playerIP != null ? "enabled" : "disabled");

        String logDetails = String.format("Token: %s..., Operation: %s, IP: %s, Security: %s",
                token.substring(0, 4), operation,
                playerIP != null ? maskIP(playerIP) : "none",
                Config.enableSessionIPValidation ? "enhanced" : "basic");

        AuthLogger.logAuthEvent(player.getUUID(), player.getScoreboardName(), "SESSION_CREATED", logDetails);
    }

    private static void removeExpiredSession(String token, SessionData data) {
        sessions.remove(token);
        totalSessionsExpired.incrementAndGet();
        SystemMonitor.recordSessionExpired();

        LarbacoAuthMain.LOGGER.debug("Expired session removed for token: {}",
                token.substring(0, 4) + "...");

        AuthLogger.logAuthEvent(data.getPlayerId(), "UNKNOWN", "SESSION_EXPIRED",
                "Token: " + token.substring(0, 4) + "..., Age: " + data.getAge() + "ms");
    }

    private static String maskIP(String ip) {
        if (ip == null) return "null";

        String[] parts = ip.split("\\.");
        if (parts.length >= 4) {
            return parts[0] + "." + parts[1] + ".*.*";
        }

        return ip.substring(0, Math.min(ip.length() / 2, 8)) + "...";
    }

    private static void cleanExpiredSessions() {
        try {
            int beforeCount = sessions.size();

            sessions.entrySet().removeIf(entry -> {
                boolean expired = entry.getValue().isExpired();
                if (expired) {
                    totalSessionsExpired.incrementAndGet();
                    SystemMonitor.recordSessionExpired();

                    LarbacoAuthMain.LOGGER.debug("Removing expired session: {}",
                            entry.getKey().substring(0, 4) + "...");
                }
                return expired;
            });

            int afterCount = sessions.size();
            int removed = beforeCount - afterCount;

            if (removed > 0) {
                LarbacoAuthMain.LOGGER.debug("Cleaned up {} expired sessions", removed);
            }

            isHealthy();

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error during session cleanup: {}", e.getMessage(), e);
            SystemMonitor.updateComponentHealth("SessionManager", false, "Cleanup failed: " + e.getMessage());
        }
    }

    private static void logStatistics() {
        try {
            SessionStatistics stats = getDetailedStatistics();

            if (stats.activeSessions() > 0 || stats.pendingOperations() > 0) {
                LarbacoAuthMain.LOGGER.info("Session Stats - {}", stats.getSummary());
            }

            if (stats.activeSessions() > 100) {
                LarbacoAuthMain.LOGGER.warn("High number of active sessions: {}", stats.activeSessions());
            }

            if (stats.oldestSessionAge() > 60000) {
                LarbacoAuthMain.LOGGER.warn("Old session detected: {} ms age", stats.oldestSessionAge());
            }

            if (Config.enableSessionIPValidation && stats.ipRejections() > 10) {
                LarbacoAuthMain.LOGGER.warn("Multiple IP validation rejections detected: {}", stats.ipRejections());
            }

            if (stats.suspiciousBlocks() > 5) {
                LarbacoAuthMain.LOGGER.warn("Multiple suspicious IP blocks detected: {}", stats.suspiciousBlocks());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging session statistics: {}", e.getMessage());
        }
    }
}