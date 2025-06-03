package com.larbaco.larbaco_auth.handlers;

/**
 * Types of authentication operations that can be performed
 */
public enum OperationType {
    /**
     * Player login operation
     */
    LOGIN,

    /**
     * Player registration operation
     */
    REGISTER,

    /**
     * Password change operation
     */
    CHANGE_PASSWORD
}