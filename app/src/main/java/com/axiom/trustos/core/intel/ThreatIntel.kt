package com.axiom.trustos.core.intel

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