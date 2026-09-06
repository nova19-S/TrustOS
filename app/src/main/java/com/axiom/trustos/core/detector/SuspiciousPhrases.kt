package com.axiom.trustos.core.detector

/**
 * Single source of truth for phrase lists used across the app.
 * Both TextRiskDetector (for scoring) and TrustAccessibilityService
 * (for building stable threat keys) pull from here, so the two
 * can never drift out of sync.
 */
object SuspiciousPhrases {

    val URGENCY = listOf(
        "urgent",
        "immediately",
        "right now",
        "act now",
        "act immediately",
        "respond immediately",
        "do this immediately",
        "last chance",
        "final warning",
        "expires today",
        "account expires",
        "within 24 hours",
        "within 1 hour",
        "within one hour",
        "within 30 minutes",
        "hurry"
    )

    val ACCOUNT_THREAT = listOf(
        "account will be blocked",
        "account suspended",
        "account locked",
        "account will be closed",
        "access will be revoked",
        "verify your account"
    )

    val CREDENTIAL = listOf(
        "password",
        "otp",
        "one time password",
        "pin",
        "cvv",
        "verification code",
        "login credentials",
        "share your otp",
        "send your otp",
        "enter your otp",
        "provide your otp",
        "share your pin",
        "enter your pin",
        "share your cvv",
        "enter your cvv",
        "share the verification code",
        "enter the verification code"
    )

    val FINANCIAL = listOf(
        "make a payment",
        "payment failed",
        "payment pending",
        "payment declined",
        "payment required",
        "confirm payment",
        "verify payment",
        "unauthorized transaction",
        "suspicious transaction",
        "transaction failed",
        "transaction pending",
        "refund pending",
        "claim your refund",
        "bank account",
        "bank details",
        "banking details",
        "upi payment",
        "upi transaction",
        "upi id",
        "card details",
        "debit card",
        "credit card"
    )

    val CALL_TO_ACTION = listOf(
        "click here",
        "click the link",
        "verify now",
        "update now",
        "confirm now",
        "tap here",
        "login here"
    )

    val IMPERSONATION = listOf(
        "customer support",
        "customer care",
        "security team",
        "security department",
        "bank officer",
        "bank representative",
        "official support",
        "account manager",
        "kyc department",
        "verification department",
        "fraud department",
        "rbi",
        "reserve bank of india",
        "income tax department",
        "government official"
    )

    /** Flat list of every phrase across all categories — used where a category
     * distinction doesn't matter (e.g. building a stable threat key). */
    val ALL: List<String> by lazy {
        URGENCY + ACCOUNT_THREAT + CREDENTIAL + FINANCIAL + CALL_TO_ACTION + IMPERSONATION
    }

    /** Shared phrase-matching logic — same rule TextRiskDetector and
     * TrustAccessibilityService both need: multi-word phrases match as
     * substrings, single words match as whole-word boundaries only. */
    fun containsPhrase(text: String, phrase: String): Boolean {
        return if (phrase.contains(' ')) {
            text.contains(phrase)
        } else {
            Regex("""\b${Regex.escape(phrase)}\b""").containsMatchIn(text)
        }
    }

    fun matchesAny(text: String, phrases: List<String>): Boolean {
        return phrases.any { phrase -> containsPhrase(text, phrase) }
    }
}