package com.larbaco.larbaco_auth.handlers;

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
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AuthSessionManager {
    private static final Map<String, SessionData> sessions = new ConcurrentHashMap<>();
    private static final Map<UUID, OperationType> pendingOperations = new ConcurrentHashMap<>();

    private static final String SECRET_PASSPHRASE = "LarbacoAuth2025SecurePassphrase!";
    private static final byte[] SECRET_KEY = createFixedLengthKey(SECRET_PASSPHRASE);

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, r -> {
        Thread t = new Thread(r, "LarbacoAuth-SessionManager");
        t.setDaemon(true);
        return t;
    });

    private static final AtomicInteger totalSessionsCreated = new AtomicInteger(0);
    private static final AtomicInteger totalSessionsExpired = new AtomicInteger(0);
    private static final AtomicInteger totalSessionsValidated = new AtomicInteger(0);

    private static volatile boolean initialized = false;

    static {
        initialize();
    }

    private static void initialize() {
        try {
            scheduler.scheduleAtFixedRate(AuthSessionManager::cleanExpiredSessions, 30, 30, TimeUnit.SECONDS);
            scheduler.scheduleAtFixedRate(AuthSessionManager::logStatistics, 5, 5, TimeUnit.MINUTES);

            initialized = true;
            SystemMonitor.updateComponentHealth("SessionManager", true, null);

            LarbacoAuthMain.LOGGER.info("AuthSessionManager initialized with {}-bit AES encryption", SECRET_KEY.length * 8);
            AuthLogger.logSystemEvent("SESSION_MANAGER_INIT", "Session manager initialized successfully");

        } catch (Exception e) {
            SystemMonitor.updateComponentHealth("SessionManager", false, e.getMessage());
            LarbacoAuthMain.LOGGER.error("Failed to initialize AuthSessionManager: {}", e.getMessage(), e);
            throw new RuntimeException("AuthSessionManager initialization failed", e);
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

    public static String createSession(ServerPlayer player, String password, OperationType operation) {
        if (!initialized) {
            LarbacoAuthMain.LOGGER.error("Attempted to create session before initialization");
            return null;
        }

        UUID playerId = player.getUUID();
        String token = generateToken();

        try {
            String encryptedPassword = encryptPassword(password);
            sessions.put(token, new SessionData(playerId, encryptedPassword, operation));

            totalSessionsCreated.incrementAndGet();
            SystemMonitor.recordSessionCreated();

            LarbacoAuthMain.LOGGER.debug("Created session for player {} with operation {}",
                    player.getScoreboardName(), operation);

            AuthLogger.logAuthEvent(playerId, player.getScoreboardName(), "SESSION_CREATED",
                    "Token: " + token.substring(0, 4) + "..., Operation: " + operation);

            return token;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error creating auth session for {}: {}",
                    player.getScoreboardName(), e.getMessage(), e);
            SystemMonitor.updateComponentHealth("SessionManager", false, "Session creation failed: " + e.getMessage());
            return null;
        }
    }

    public static SessionData validateSession(String token) {
        if (!initialized) {
            return null;
        }

        SessionData data = sessions.get(token);
        if (data != null && !data.isExpired()) {
            sessions.remove(token);
            totalSessionsValidated.incrementAndGet();

            LarbacoAuthMain.LOGGER.debug("Session validated and removed for token: {}",
                    token.substring(0, 4) + "...");

            AuthLogger.logAuthEvent(data.getPlayerId(), "UNKNOWN", "SESSION_VALIDATED",
                    "Token: " + token.substring(0, 4) + "..., Age: " + data.getAge() + "ms");

            return data;
        }

        if (data != null && data.isExpired()) {
            sessions.remove(token);
            totalSessionsExpired.incrementAndGet();
            SystemMonitor.recordSessionExpired();

            LarbacoAuthMain.LOGGER.debug("Expired session removed for token: {}",
                    token.substring(0, 4) + "...");

            AuthLogger.logAuthEvent(data.getPlayerId(), "UNKNOWN", "SESSION_EXPIRED",
                    "Token: " + token.substring(0, 4) + "..., Age: " + data.getAge() + "ms");
        }

        return null;
    }

    public static void setPendingOperation(UUID playerId, OperationType operation) {
        pendingOperations.put(playerId, operation);
        LarbacoAuthMain.LOGGER.debug("Set pending operation {} for player {}", operation, playerId);
    }

    public static OperationType getPendingOperation(UUID playerId) {
        return pendingOperations.get(playerId);
    }

    public static void clearPendingOperation(UUID playerId) {
        OperationType removed = pendingOperations.remove(playerId);
        if (removed != null) {
            LarbacoAuthMain.LOGGER.debug("Cleared pending operation {} for player {}", removed, playerId);
        }
    }

    public static String getSessionStats() {
        return String.format("Active sessions: %d, Pending operations: %d, Created (total): %d, Expired (total): %d, Validated (total): %d",
                sessions.size(), pendingOperations.size(), totalSessionsCreated.get(), totalSessionsExpired.get(), totalSessionsValidated.get());
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

        return new SessionStatistics(
                sessions.size(),
                pendingOperations.size(),
                totalSessionsCreated.get(),
                totalSessionsExpired.get(),
                totalSessionsValidated.get(),
                oldestSessionAge,
                operationCounts
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

            if (scheduler.isShutdown()) {
                SystemMonitor.updateComponentHealth("SessionManager", false, "Scheduler is shutdown");
                return false;
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

    // Private helper methods

    private static String generateToken() {
        return RandomStringUtils.randomAlphanumeric(12);
    }

    private static String encryptPassword(String password) throws Exception {
        try {
            Key key = new SecretKeySpec(SECRET_KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            String encoded = Base64.getEncoder().encodeToString(encrypted);

            LarbacoAuthMain.LOGGER.debug("Password encrypted successfully (length: {} chars)", encoded.length());
            return encoded;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Password encryption failed: {}", e.getMessage());
            throw new Exception("Encryption failed: " + e.getMessage(), e);
        }
    }

    private static String decryptPassword(String encrypted) throws Exception {
        try {
            Key key = new SecretKeySpec(SECRET_KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            String password = new String(decrypted, StandardCharsets.UTF_8);

            LarbacoAuthMain.LOGGER.debug("Password decrypted successfully");
            return password;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Password decryption failed: {}", e.getMessage());
            throw new Exception("Decryption failed: " + e.getMessage(), e);
        }
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
                LarbacoAuthMain.LOGGER.info("Session Stats - Active: {}, Pending: {}, Created: {}, Expired: {}, Validated: {}",
                        stats.activeSessions(), stats.pendingOperations(),
                        stats.totalCreated(), stats.totalExpired(), stats.totalValidated());
            }

            if (stats.activeSessions() > 100) {
                LarbacoAuthMain.LOGGER.warn("High number of active sessions: {}", stats.activeSessions());
            }

            if (stats.oldestSessionAge() > 60000) {
                LarbacoAuthMain.LOGGER.warn("Old session detected: {} ms age", stats.oldestSessionAge());
            }

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error logging session statistics: {}", e.getMessage());
        }
    }

    public static class SessionData {
        private final UUID playerId;
        private final String encryptedPassword;
        private final OperationType operation;
        private final long creationTime;

        public SessionData(UUID playerId, String encryptedPassword, OperationType operation) {
            this.playerId = playerId;
            this.encryptedPassword = encryptedPassword;
            this.operation = operation;
            this.creationTime = System.currentTimeMillis();
        }

        public String getPassword() throws Exception {
            return decryptPassword(encryptedPassword);
        }

        public UUID getPlayerId() {
            return playerId;
        }

        public OperationType getOperation() {
            return operation;
        }

        public boolean isExpired() {
            return (System.currentTimeMillis() - creationTime) > 30000; // 30 seconds
        }

        public long getAge() {
            return System.currentTimeMillis() - creationTime;
        }

        public long getCreationTime() {
            return creationTime;
        }
    }

    public enum OperationType {
        LOGIN,
        REGISTER
    }

    public record SessionStatistics(
            int activeSessions,
            int pendingOperations,
            int totalCreated,
            int totalExpired,
            int totalValidated,
            long oldestSessionAge,
            Map<OperationType, Long> operationCounts
    ) {}
}