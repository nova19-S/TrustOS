package com.axiom.trustos.core.intel

import com.axiom.trustos.core.model.DetectionResult
import java.security.MessageDigest

/**
 * A coarse, privacy-safe category for a detected threat — never raw text,
 * never a raw URL. This is what gets "shared" with the mock network.
 */
enum class ThreatCategory {
    SUSPICIOUS_URL,
    CREDENTIAL_PHISHING,
    FINANCIAL_SCAM,
    ACCOUNT_THREAT,
    IMPERSONATION,
    GENERIC_SUSPICIOUS
}

/**
 * A privacy-safe fingerprint: just a category, never the original content.
 * In a real system this would be a cryptographic hash of bucketed features;
 * for the mock layer the category itself IS the bucket.
 */
data class ThreatFingerprint(
    val category: ThreatCategory
)

/**
 * What the mock "network" reports back for a given fingerprint.
 *
 * @param isTrending Whether this category has been reported unusually
 *   often recently (across the simulated network).
 * @param trendBoost Extra points (0-100 scale, same units as risk score)
 *   to add to the local score because of network trend data.
 * @param reportCount How many times this category has been "reported"
 *   recently — shown in the UI for transparency.
 */
data class NetworkIntelResult(
    val isTrending: Boolean,
    val trendBoost: Int,
    val reportCount: Int
)

/**
 * Maps a detector's reason string to a coarse ThreatCategory.
 * This is intentionally lossy — many different specific reasons collapse
 * into the same category, because the network should only ever see
 * broad categories, never the original reasons or content.
 */
fun categoryForReason(reason: String): ThreatCategory {
    val lower = reason.lowercase()

    return when {
        lower.contains("url") -> ThreatCategory.SUSPICIOUS_URL
        lower.contains("credential") || lower.contains("authentication") -> ThreatCategory.CREDENTIAL_PHISHING
        lower.contains("payment") || lower.contains("financial") -> ThreatCategory.FINANCIAL_SCAM
        lower.contains("account threat") || lower.contains("suspension") -> ThreatCategory.ACCOUNT_THREAT
        lower.contains("impersonation") || lower.contains("authority") || lower.contains("organization") -> ThreatCategory.IMPERSONATION
        else -> ThreatCategory.GENERIC_SUSPICIOUS
    }
}

/**
 * Picks the single most relevant category for a whole set of reasons,
 * so a batch of detector findings reports as ONE fingerprint category,
 * not one per reason. Priority order matters here — e.g. credential
 * phishing is more specific/important than a generic suspicious URL.
 */
fun primaryCategoryForReasons(reasons: List<String>): ThreatCategory {
    if (reasons.isEmpty()) {
        return ThreatCategory.GENERIC_SUSPICIOUS
    }

    val categories = reasons.map { categoryForReason(it) }.toSet()

    val priorityOrder = listOf(
        ThreatCategory.CREDENTIAL_PHISHING,
        ThreatCategory.FINANCIAL_SCAM,
        ThreatCategory.IMPERSONATION,
        ThreatCategory.ACCOUNT_THREAT,
        ThreatCategory.SUSPICIOUS_URL,
        ThreatCategory.GENERIC_SUSPICIOUS
    )

    return priorityOrder.first { it in categories }
}

/**
 * Computes a deterministic privacy-preserving fingerprint for a threat bundle.
 *
 * This function intentionally does NOT hash or include raw message text,
 * URLs, domains, or detector payload details. It only derives coarse,
 * bucketed structural features: the ThreatCategory, a bucketed count of
 * distinct reason strings, whether any URL-related indicator was present,
 * and a coarse risk bucket based on the summed riskContribution before any
 * confidence weighting.
 *
 * The tuple is serialized to a canonical string and then hashed with SHA-256,
 * producing a stable hex fingerprint. The same category and same bucketed
 * feature values always produce the same fingerprint, which allows similar
 * threat patterns to be recognized without exposing the underlying content.
 */
fun computeFingerprint(results: List<DetectionResult>, category: ThreatCategory): String {
    val distinctReasonCount = results
        .map { it.reason }
        .filter { it.isNotBlank() }
        .distinct()
        .size

    val hasUrl = results.any { result ->
        val reasonText = result.reason.lowercase()
        val detectorText = result.detectorName.lowercase()
        reasonText.contains("url") || detectorText.contains("url")
    }

    val totalRiskContribution = results.sumOf { it.riskContribution }

    val reasonBucket = when {
        distinctReasonCount == 0 -> "0"
        distinctReasonCount <= 2 -> "1-2"
        distinctReasonCount <= 4 -> "3-4"
        else -> "5+"
    }

    val riskBucket = when {
        totalRiskContribution < 30 -> "LOW"
        totalRiskContribution < 70 -> "MEDIUM"
        else -> "HIGH"
    }

    val canonical = "${category.name}|reasons:$reasonBucket|hasUrl:$hasUrl|riskBucket:$riskBucket"
    return sha256Hex(canonical)
}

private fun sha256Hex(input: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
    return bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

/**
 * How much weight a single report carries, based on how trustworthy the
 * reporting device/account is considered. This is what prevents a burst
 * of fake/new accounts from instantly manufacturing a fake trend — new
 * or unverified reporters count for less until they build reputation.
 */
enum class ReporterTrustLevel(val weight: Double) {
    NEW(0.3),
    ESTABLISHED(1.0),
    HIGHLY_TRUSTED(1.5)
}