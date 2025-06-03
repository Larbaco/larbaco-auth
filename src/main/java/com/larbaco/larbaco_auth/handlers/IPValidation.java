package com.larbaco.larbaco_auth.handlers;

public class IPValidation {

    public enum Status {
        VALID,
        INVALID_MISMATCH,
        INVALID_SUSPICIOUS,
        BYPASS_ALLOWED
    }

    public static class Result {
        private final Status status;
        private final String details;

        public Result(Status status, String details) {
            this.status = status;
            this.details = details;
        }

        public Status status() {
            return status;
        }

        public String details() {
            return details;
        }

        @Override
        public String toString() {
            return String.format("IPValidation.Result{status=%s, details='%s'}", status, details);
        }
    }
}