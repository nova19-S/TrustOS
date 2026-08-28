package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult
import org.junit.Assert.assertTrue
import org.junit.Test

class TextRiskDetectorTest {

    private val detector = TextRiskDetector()

    @Test
    fun analyze_blankText_returnsEmptyList() {
        assertTrue(detector.analyze("").isEmpty())
        assertTrue(detector.analyze("   ").isEmpty())
    }

    @Test
    fun analyze_normalMessage_returnsNoFindings() {
        val findings = detector.analyze("Hey, are we still meeting at 5 PM?")

        assertTrue(findings.isEmpty())
    }

    @Test
    fun analyze_urgency_returnsUrgencyFinding() {
        val findings = detector.analyze("URGENT! Act now.")

        assertTrue(hasReason(findings, URGENCY_REASON))
    }

    @Test
    fun analyze_accountThreat_returnsAccountThreatFinding() {
        val findings = detector.analyze("Your account will be blocked today.")

        assertTrue(hasReason(findings, ACCOUNT_THREAT_REASON))
    }

    @Test
    fun analyze_credentialRequest_returnsCredentialFinding() {
        val findings = detector.analyze("Please send your OTP and password.")

        assertTrue(hasReason(findings, CREDENTIAL_REASON))
    }

    @Test
    fun analyze_financialContext_returnsFinancialFinding() {
        val findings = detector.analyze("Your bank payment was received.")

        assertTrue(hasReason(findings, FINANCIAL_REASON))
    }

    @Test
    fun analyze_callToAction_returnsAppropriateFindings() {
        val findings = detector.analyze("Click here to verify your account.")

        assertTrue(hasReason(findings, CALL_TO_ACTION_REASON))
        assertTrue(hasReason(findings, ACCOUNT_THREAT_REASON))
    }

    @Test
    fun analyze_impersonation_returnsImpersonationFinding() {
        val findings = detector.analyze("This is the official bank security team.")

        assertTrue(hasReason(findings, IMPERSONATION_REASON))
    }

    @Test
    fun analyze_combinedSuspiciousMessage_returnsMultipleCategories() {
        val findings = detector.analyze(
            "URGENT! Your bank account will be blocked. Verify your password immediately by clicking here."
        )

        assertTrue(findings.size > 1)
        assertTrue(hasReason(findings, URGENCY_REASON))
        assertTrue(hasReason(findings, ACCOUNT_THREAT_REASON))
        assertTrue(hasReason(findings, CREDENTIAL_REASON))
        assertTrue(hasReason(findings, FINANCIAL_REASON))
    }

    @Test
    fun analyze_normalFinancialMessage_doesNotClaimMessageIsMalicious() {
        val findings = detector.analyze("Your bank statement is available.")

        assertTrue(
            findings.all { it.reason == FINANCIAL_REASON }
        )
        assertTrue(
            findings.none { finding ->
                finding.reason.contains("fraud", ignoreCase = true) ||
                    finding.reason.contains("malicious", ignoreCase = true)
            }
        )
    }

    private fun hasReason(
        findings: List<DetectionResult>,
        reason: String
    ): Boolean {
        return findings.any { it.reason == reason }
    }

    companion object {
        private const val URGENCY_REASON = "Urgency language detected"
        private const val ACCOUNT_THREAT_REASON =
            "Account threat or suspension language detected"
        private const val CREDENTIAL_REASON =
            "Possible credential or authentication information request"
        private const val FINANCIAL_REASON =
            "Financial or payment-related context detected"
        private const val CALL_TO_ACTION_REASON =
            "Suspicious call-to-action detected"
        private const val IMPERSONATION_REASON =
            "Possible authority or organization impersonation indicator"
    }
}
