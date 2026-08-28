package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult

class TextRiskDetector {

    fun analyze(text: String): List<DetectionResult> {
        val normalized = text.trim().lowercase()
        if (normalized.isEmpty()) {
            return emptyList()
        }

        val findings = mutableListOf<DetectionResult>()

        if (matchesAny(normalized, URGENCY_PHRASES)) {
            findings += finding(
                reason = "Urgency language detected",
                riskContribution = 15,
                confidence = 0.50
            )
        }

        if (matchesAny(normalized, ACCOUNT_THREAT_PHRASES)) {
            findings += finding(
                reason = "Account threat or suspension language detected",
                riskContribution = 20,
                confidence = 0.70
            )
        }

        if (matchesAny(normalized, CREDENTIAL_PHRASES)) {
            findings += finding(
                reason = "Possible credential or authentication information request",
                riskContribution = 25,
                confidence = 0.75
            )
        }

        if (matchesAny(normalized, FINANCIAL_PHRASES)) {
            findings += finding(
                reason = "Financial or payment-related context detected",
                riskContribution = 10,
                confidence = 0.45
            )
        }

        if (matchesAny(normalized, CALL_TO_ACTION_PHRASES)) {
            findings += finding(
                reason = "Suspicious call-to-action detected",
                riskContribution = 15,
                confidence = 0.60
            )
        }

        if (matchesAny(normalized, IMPERSONATION_PHRASES)) {
            findings += finding(
                reason = "Possible authority or organization impersonation indicator",
                riskContribution = 15,
                confidence = 0.65
            )
        }

        return findings
    }

    private fun finding(
        reason: String,
        riskContribution: Int,
        confidence: Double
    ): DetectionResult {
        return DetectionResult(
            detectorName = DETECTOR_NAME,
            reason = reason,
            riskContribution = riskContribution,
            confidence = confidence
        )
    }

    private fun matchesAny(text: String, phrases: List<String>): Boolean {
        return phrases.any { phrase -> containsPhrase(text, phrase) }
    }

    private fun containsPhrase(text: String, phrase: String): Boolean {
        return if (phrase.contains(' ')) {
            text.contains(phrase)
        } else {
            Regex("""\b${Regex.escape(phrase)}\b""").containsMatchIn(text)
        }
    }

    companion object {
        private const val DETECTOR_NAME = "Text Detector"

        private val URGENCY_PHRASES = listOf(
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

        private val ACCOUNT_THREAT_PHRASES = listOf(
            "account will be blocked",
            "account suspended",
            "account locked",
            "account will be closed",
            "access will be revoked",
            "verify your account"
        )

        private val CREDENTIAL_PHRASES = listOf(
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

        private val FINANCIAL_PHRASES = listOf(
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

        private val CALL_TO_ACTION_PHRASES = listOf(
            "click here",
            "click the link",
            "verify now",
            "update now",
            "confirm now",
            "tap here",
            "login here"
        )

        private val IMPERSONATION_PHRASES = listOf(
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
    }
}
