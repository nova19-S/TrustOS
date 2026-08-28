package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult
import java.net.URI

class UrlRiskDetector {

    fun analyze(url: String): List<DetectionResult> {
        val normalized = normalize(url)
        if (normalized.isEmpty()) {
            return emptyList()
        }

        val findings = mutableListOf<DetectionResult>()
        val host = extractHost(normalized)

        if (host != null && hasDeceptiveDomainPattern(host)) {
            findings += finding(
                reason = "Domain contains a suspicious brand-like or deceptive pattern",
                riskContribution = 20,
                confidence = 0.70
            )
        }

        if (host != null && isUrlShortener(host)) {
            findings += finding(
                reason = "URL uses a shortened link that hides the final destination",
                riskContribution = 20,
                confidence = 0.80
            )
        }

        if (usesPlainHttp(normalized)) {
            findings += finding(
                reason = "URL does not use HTTPS",
                riskContribution = 15,
                confidence = 0.85
            )
        }

        if (host != null && isIpAddress(host)) {
            findings += finding(
                reason = "URL uses an IP address instead of a domain",
                riskContribution = 25,
                confidence = 0.90
            )
        }

        if (host != null && !isIpAddress(host) && hasExcessiveSubdomains(host)) {
            findings += finding(
                reason = "Unusually deep subdomain structure",
                riskContribution = 15,
                confidence = 0.70
            )
        }

        if (host != null && hasExcessiveHyphens(host)) {
            findings += finding(
                reason = "Domain contains an unusually high number of hyphens",
                riskContribution = 10,
                confidence = 0.55
            )
        }

        if (containsSuspiciousKeyword(normalized)) {
            findings += finding(
                reason = "Contains suspicious security/account-related keywords",
                riskContribution = 15,
                confidence = 0.55
            )
        }

        if (normalized.contains('@')) {
            findings += finding(
                reason = "URL contains an @ symbol that may obscure the actual destination",
                riskContribution = 25,
                confidence = 0.90
            )
        }

        if (normalized.length > 100) {
            findings += finding(
                reason = "Unusually long URL",
                riskContribution = 10,
                confidence = 0.60
            )
        }

        if (host != null && !isIpAddress(host) && hasRandomLookingHostname(host)) {
            findings += finding(
                reason = "Hostname looks unusually long or random",
                riskContribution = 15,
                confidence = 0.65
            )
        }

        return findings
    }

    private fun normalize(url: String): String = url.trim()

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

    private fun usesPlainHttp(url: String): Boolean {
        val lower = url.lowercase()
        return lower.startsWith("http://") && !lower.startsWith("https://")
    }

    private fun extractHost(url: String): String? {
        return try {
            val withScheme = if ("://" in url) url else "https://$url"
            URI(withScheme).host?.lowercase()?.trim('.')
        } catch (_: Exception) {
            null
        }
    }

    private fun isIpAddress(host: String): Boolean {
        val value = host.removePrefix("[").removeSuffix("]")
        if (IPV4_PATTERN.matches(value)) {
            return value.split('.').all { part ->
                part.toIntOrNull()?.let { it in 0..255 } == true
            }
        }
        return value.contains(':') && IPV6_CHAR_PATTERN.matches(value)
    }

    private fun hasExcessiveSubdomains(host: String): Boolean {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) {
            return false
        }
        val subdomainCount = labels.size - 2
        return subdomainCount >= 3
    }

    private fun isUrlShortener(host: String): Boolean {
        return SHORTENER_DOMAINS.any { domain ->
            host == domain || host.endsWith(".$domain")
        }
    }

    private fun hasDeceptiveDomainPattern(host: String): Boolean {
        val lower = host.lowercase()

        val suspiciousPatterns = listOf(
            "paypal-login",
            "paypal-verify",
            "google-login",
            "google-verify",
            "microsoft-login",
            "apple-login",
            "amazon-login",
            "bank-login",
            "bank-verify",
            "secure-login",
            "account-verify"
        )

        return suspiciousPatterns.any { lower.contains(it) }
    }

    private fun hasExcessiveHyphens(host: String): Boolean {
        return host.count { it == '-' } >= 3
    }

    private fun containsSuspiciousKeyword(url: String): Boolean {
        val lower = url.lowercase()
        return SUSPICIOUS_KEYWORDS.any { keyword -> lower.contains(keyword) }
    }

    private fun hasRandomLookingHostname(host: String): Boolean {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) {
            return false
        }
        val labelsToInspect = labels.dropLast(2)
        if (labelsToInspect.isEmpty()) {
            return false
        }
        return labelsToInspect.any { looksRandomOrExcessivelyLong(it) }
    }

    private fun looksRandomOrExcessivelyLong(label: String): Boolean {
        if (label.length < 16) {
            return false
        }

        val letters = label.filter { it.isLetter() }
        val digitCount = label.count { it.isDigit() }
        val vowelCount = letters.count { it.lowercaseChar() in VOWELS }

        val vowelRatio = if (letters.isEmpty()) {
            0.0
        } else {
            vowelCount.toDouble() / letters.length
        }

        return label.length >= 20 ||
                (label.length > 16 && vowelRatio < 0.15) ||
                (label.length > 16 && digitCount >= 6)
    }

    companion object {
        private const val DETECTOR_NAME = "URL Detector"
        private val VOWELS = setOf('a', 'e', 'i', 'o', 'u')
        private val IPV4_PATTERN = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
        private val IPV6_CHAR_PATTERN = Regex("""^[0-9a-f:]+$""", RegexOption.IGNORE_CASE)
        private val SUSPICIOUS_KEYWORDS = listOf(
            "login",
            "verify",
            "account",
            "secure",
            "update",
            "password",
            "wallet",
            "bank",
            "payment",
            "claim",
            "urgent",
            "suspend"
        )
        private val SHORTENER_DOMAINS = setOf(
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "ow.ly",
            "cutt.ly"
        )
    }
}
