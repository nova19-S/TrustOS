package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult

class TextRiskDetector {

    fun analyze(text: String): List<DetectionResult> {
        val normalized = text.trim().lowercase()
        if (normalized.isEmpty()) {
            return emptyList()
        }

        val findings = mutableListOf<DetectionResult>()

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.URGENCY)) {
            findings += finding(
                reason = "Urgency language detected",
                riskContribution = 15,
                confidence = 0.50
            )
        }

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.ACCOUNT_THREAT)) {
            findings += finding(
                reason = "Account threat or suspension language detected",
                riskContribution = 20,
                confidence = 0.70
            )
        }

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.CREDENTIAL)) {
            findings += finding(
                reason = "Possible credential or authentication information request",
                riskContribution = 25,
                confidence = 0.75
            )
        }

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.FINANCIAL)) {
            findings += finding(
                reason = "Financial or payment-related context detected",
                riskContribution = 10,
                confidence = 0.45
            )
        }

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.CALL_TO_ACTION)) {
            findings += finding(
                reason = "Suspicious call-to-action detected",
                riskContribution = 15,
                confidence = 0.60
            )
        }

        if (SuspiciousPhrases.matchesAny(normalized, SuspiciousPhrases.IMPERSONATION)) {
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

    companion object {
        private const val DETECTOR_NAME = "Text Detector"
    }
}