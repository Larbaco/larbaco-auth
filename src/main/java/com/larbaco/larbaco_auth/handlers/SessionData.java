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

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Represents an authentication session with encrypted password and IP tracking
 */
public class SessionData {
    private final UUID playerId;
    private final String encryptedPassword;
    private final OperationType operation;
    private final long creationTime;
    private final String creatorIP;

    // Static encryption key (same as AuthSessionManager)
    private static final String SECRET_PASSPHRASE = "LarbacoAuth2025SecurePassphrase!";
    private static final byte[] SECRET_KEY = createFixedLengthKey(SECRET_PASSPHRASE);

    public SessionData(UUID playerId, String encryptedPassword, OperationType operation) {
        this(playerId, encryptedPassword, operation, null);
    }

    public SessionData(UUID playerId, String encryptedPassword, OperationType operation, String creatorIP) {
        this.playerId = playerId;
        this.encryptedPassword = encryptedPassword;
        this.operation = operation;
        this.creationTime = System.currentTimeMillis();
        this.creatorIP = creatorIP;
    }

    /**
     * Decrypt and return the password
     */
    public String getPassword() throws Exception {
        return decryptPassword(encryptedPassword);
    }

    public UUID getPlayerId() {
        return playerId;
    }

    public OperationType getOperation() {
        return operation;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getCreatorIP() {
        return creatorIP;
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

    // Private encryption methods
    private static byte[] createFixedLengthKey(String passphrase) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(passphrase.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Fallback key generation
            byte[] fallbackKey = new byte[32];
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(passphraseBytes, 0, fallbackKey, 0, Math.min(passphraseBytes.length, 32));
            return fallbackKey;
        }
    }

    private static String decryptPassword(String encrypted) throws Exception {
        try {
            Key key = new SecretKeySpec(SECRET_KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] decrypted = cipher.doFinal(java.util.Base64.getDecoder().decode(encrypted));
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new Exception("Password decryption failed: " + e.getMessage(), e);
        }
    }
}