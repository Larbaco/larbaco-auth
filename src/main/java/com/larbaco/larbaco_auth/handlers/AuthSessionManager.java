package com.larbaco.larbaco_auth.handlers;

import com.larbaco.larbaco_auth.LarbacoAuthMain;
import net.minecraft.server.level.ServerPlayer;
import org.apache.commons.lang3.RandomStringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages secure authentication sessions with token-based password submission
 * Fixed AES key length issue
 */
public class AuthSessionManager {
    private static final Map<String, SessionData> sessions = new ConcurrentHashMap<>();
    private static final Map<UUID, OperationType> pendingOperations = new ConcurrentHashMap<>();

    // FIX: Use a 32-byte key (256-bit AES) for maximum security
    private static final String SECRET_PASSPHRASE = "LarbacoAuth2025SecurePassphrase!"; // 32 bytes exactly
    private static final byte[] SECRET_KEY = createFixedLengthKey(SECRET_PASSPHRASE);

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    static {
        // Cleanup expired sessions every minute
        scheduler.scheduleAtFixedRate(AuthSessionManager::cleanExpiredSessions, 1, 1, TimeUnit.MINUTES);

        // Log key initialization
        LarbacoAuthMain.LOGGER.info("AuthSessionManager initialized with {}-bit AES encryption", SECRET_KEY.length * 8);
    }

    /**
     * Create a fixed-length AES key from any string
     * This ensures we always have a valid 32-byte (256-bit) key
     */
    private static byte[] createFixedLengthKey(String passphrase) {
        try {
            // Use SHA-256 to create a 32-byte key from any input
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(passphrase.getBytes(StandardCharsets.UTF_8));

            // SHA-256 always produces 32 bytes, perfect for AES-256
            LarbacoAuthMain.LOGGER.debug("Generated AES key length: {} bytes", keyBytes.length);
            return keyBytes;

        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Failed to generate AES key: {}", e.getMessage());
            // Fallback: create a 32-byte key manually
            byte[] fallbackKey = new byte[32];
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(passphraseBytes, 0, fallbackKey, 0, Math.min(passphraseBytes.length, 32));
            return fallbackKey;
        }
    }

    public static String createSession(ServerPlayer player, String password, OperationType operation) {
        UUID playerId = player.getUUID();
        String token = generateToken();

        try {
            String encryptedPassword = encryptPassword(password);
            sessions.put(token, new SessionData(playerId, encryptedPassword, operation));

            LarbacoAuthMain.LOGGER.debug("Created session for player {} with operation {}",
                    player.getScoreboardName(), operation);

            return token;
        } catch (Exception e) {
            LarbacoAuthMain.LOGGER.error("Error creating auth session for {}: {}",
                    player.getScoreboardName(), e.getMessage(), e);
            return null;
        }
    }

    public static SessionData validateSession(String token) {
        SessionData data = sessions.get(token);
        if (data != null && !data.isExpired()) {
            sessions.remove(token);
            LarbacoAuthMain.LOGGER.debug("Session validated and removed for token: {}",
                    token.substring(0, 4) + "...");
            return data;
        }

        if (data != null && data.isExpired()) {
            sessions.remove(token);
            LarbacoAuthMain.LOGGER.debug("Expired session removed for token: {}",
                    token.substring(0, 4) + "...");
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

    private static String generateToken() {
        return RandomStringUtils.randomAlphanumeric(12);
    }

    /**
     * Encrypt password using AES-256
     */
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

    /**
     * Decrypt password using AES-256
     */
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

    /**
     * Clean up expired sessions
     */
    private static void cleanExpiredSessions() {
        int beforeCount = sessions.size();
        sessions.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().isExpired();
            if (expired) {
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
    }

    /**
     * Get session statistics for monitoring
     */
    public static String getSessionStats() {
        return String.format("Active sessions: %d, Pending operations: %d",
                sessions.size(), pendingOperations.size());
    }

    /**
     * Force cleanup of all sessions (for server shutdown)
     */
    public static void shutdown() {
        int sessionCount = sessions.size();
        int pendingCount = pendingOperations.size();

        sessions.clear();
        pendingOperations.clear();

        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
        }

        LarbacoAuthMain.LOGGER.info("AuthSessionManager shutdown: cleared {} sessions and {} pending operations",
                sessionCount, pendingCount);
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
    }

    public enum OperationType {
        LOGIN,
        REGISTER
    }
}