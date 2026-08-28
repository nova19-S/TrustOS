package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlRiskDetectorTest {

    private val detector = UrlRiskDetector()

    @Test
    fun analyze_blankUrl_returnsEmptyList() {
        assertTrue(detector.analyze("").isEmpty())
        assertTrue(detector.analyze("   ").isEmpty())
    }

    @Test
    fun analyze_normalHttpsUrl_returnsNoFindings() {
        val findings = detector.analyze("https://example.com")

        assertTrue(findings.isEmpty())
    }

    @Test
    fun analyze_httpUrl_returnsHttpsFinding() {
        val findings = detector.analyze("http://example.com")

        assertTrue(hasReason(findings, "URL does not use HTTPS"))
    }

    @Test
    fun analyze_ipAddressUrl_returnsIpFinding() {
        val findings = detector.analyze("http://192.168.1.10/login")

        assertTrue(
            hasReason(findings, "URL uses an IP address instead of a domain")
        )
    }

    @Test
    fun analyze_suspiciousKeyword_returnsKeywordFinding() {
        val findings = detector.analyze("https://example.com/verify-account")

        assertTrue(
            hasReason(
                findings,
                "Contains suspicious security/account-related keywords"
            )
        )
    }

    @Test
    fun analyze_atSymbol_returnsAtSymbolFinding() {
        val findings = detector.analyze("https://example.com@evil.com")

        assertTrue(
            hasReason(
                findings,
                "URL contains an @ symbol that may obscure the actual destination"
            )
        )
    }

    @Test
    fun analyze_longUrl_returnsLongUrlFinding() {
        val longPath = "a".repeat(90)
        val url = "https://example.com/$longPath"
        assertTrue(url.length > 100)

        val findings = detector.analyze(url)

        assertTrue(hasReason(findings, "Unusually long URL"))
    }

    @Test
    fun analyze_multipleIndicators_returnsMultipleFindings() {
        val findings = detector.analyze("http://192.168.1.10/login?password=123")

        assertTrue(findings.size > 1)
        assertTrue(hasReason(findings, "URL does not use HTTPS"))
        assertTrue(hasReason(findings, "URL uses an IP address instead of a domain"))
        assertTrue(
            hasReason(
                findings,
                "Contains suspicious security/account-related keywords"
            )
        )
    }

    @Test
    fun analyze_legitimateGoogleUrl_returnsNoFindings() {
        val findings = detector.analyze("https://www.google.com")

        assertTrue(findings.isEmpty())
    }

    private fun hasReason(
        findings: List<DetectionResult>,
        reason: String
    ): Boolean {
        return findings.any { it.reason == reason }
    }
}
