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

import java.util.Map;

/**
 * Statistics record for session management with enhanced IP tracking metrics
 */
public record SessionStatistics(
        int activeSessions,
        int pendingOperations,
        int totalCreated,
        int totalExpired,
        int totalValidated,
        long oldestSessionAge,
        Map<OperationType, Long> operationCounts,
        long ipBoundSessions,
        int ipRejections,
        int ipBypasses,
        int suspiciousBlocks,
        int suspiciousIPs,
        int trackedIPs
) {

    /**
     * Calculate success rate of session validations
     */
    public double getSuccessRate() {
        int total = totalValidated + ipRejections;
        return total > 0 ? (double) totalValidated / total * 100.0 : 0.0;
    }

    /**
     * Calculate IP rejection rate
     */
    public double getIPRejectionRate() {
        int totalIPValidations = totalValidated + ipRejections;
        return totalIPValidations > 0 ? (double) ipRejections / totalIPValidations * 100.0 : 0.0;
    }

    /**
     * Get percentage of sessions that are IP-bound
     */
    public double getIPBoundPercentage() {
        return activeSessions > 0 ? (double) ipBoundSessions / activeSessions * 100.0 : 0.0;
    }

    /**
     * Get a summary string of key metrics
     */
    public String getSummary() {
        return String.format(
                "Sessions: %d active, %d created, %d validated (%.1f%% success), " +
                        "IP: %d bound (%.1f%%), %d rejections (%.1f%%), %d suspicious",
                activeSessions, totalCreated, totalValidated, getSuccessRate(),
                ipBoundSessions, getIPBoundPercentage(), ipRejections, getIPRejectionRate(), suspiciousIPs
        );
    }
}