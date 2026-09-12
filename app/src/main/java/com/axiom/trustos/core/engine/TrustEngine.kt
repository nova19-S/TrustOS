package com.axiom.trustos.core.engine

import com.axiom.trustos.core.intel.NetworkIntelRepository
import com.axiom.trustos.core.intel.ThreatCategory
import com.axiom.trustos.core.intel.computeFingerprint
import com.axiom.trustos.core.intel.primaryCategoryForReasons
import com.axiom.trustos.core.model.DetectionResult
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.model.RiskLevel

class TrustEngine(
    private val networkIntelRepository: NetworkIntelRepository? = null
) {

    fun assess(results: List<DetectionResult>): RiskAssessment {

        if (results.isEmpty()) {
            return RiskAssessment(
                score = 0,
                confidence = 0.0,
                level = RiskLevel.LOW,
                reasons = emptyList()
            )
        }

        val weightedScore = results.sumOf { result ->
            result.riskContribution * result.confidence
        }

        val localScore = weightedScore
            .roundToInt()
            .coerceIn(0, 100)

        val reasons = results
            .map { it.reason }
            .distinct()

        val category = primaryCategoryForReasons(reasons)
        val fingerprint = computeFingerprint(results, category)

        android.util.Log.d(
            "TrustOSFingerprint",
            "category=$category fingerprint=$fingerprint reasonsDistinct=${results.map { it.reason }.filter { it.isNotBlank() }.distinct().size} riskSum=${results.sumOf { it.riskContribution }}"
        )

        // Record this as "last seen" regardless of trending status, so
        // demo tooling and the dashboard always know the most recent
        // detection's category, from ANY source (real screen detection
        // or manual scan).
        networkIntelRepository?.recordLastSeenCategory(category)

        val intelOutcome = applyNetworkIntel(localScore, reasons, category)

        val confidence = results
            .map { it.confidence }
            .average()
            .coerceIn(0.0, 1.0)

        return RiskAssessment(
            score = intelOutcome.finalScore,
            confidence = confidence,
            level = riskLevelFor(intelOutcome.finalScore),
            reasons = intelOutcome.reasons,
            isTrending = intelOutcome.isTrending,
            trendReportCount = intelOutcome.reportCount,
            category = category.name
        )
    }

    private data class IntelOutcome(
        val finalScore: Int,
        val reasons: List<String>,
        val isTrending: Boolean,
        val reportCount: Int
    )

    private fun applyNetworkIntel(
        localScore: Int,
        reasons: List<String>,
        category: ThreatCategory
    ): IntelOutcome {

        val repository = networkIntelRepository
            ?: return IntelOutcome(localScore, reasons, isTrending = false, reportCount = 0)

        val intel = repository.checkIntel(category)

        android.util.Log.d(
            "TrustOSIntel",
            "category=$category reportCount=${intel.reportCount} isTrending=${intel.isTrending} trendBoost=${intel.trendBoost} localScore=$localScore"
        )

        if (!intel.isTrending) {
            return IntelOutcome(localScore, reasons, isTrending = false, reportCount = intel.reportCount)
        }

        val boostedScore = (localScore + intel.trendBoost).coerceIn(0, 100)

        android.util.Log.d(
            "TrustOSIntel",
            "BOOSTED: localScore=$localScore + trendBoost=${intel.trendBoost} = finalScore=$boostedScore"
        )

        return IntelOutcome(
            finalScore = boostedScore,
            reasons = reasons,
            isTrending = true,
            reportCount = intel.reportCount
        )
    }

    private fun riskLevelFor(score: Int): RiskLevel {
        return when (score) {
            in 0..24 -> RiskLevel.LOW
            in 25..49 -> RiskLevel.MEDIUM
            in 50..74 -> RiskLevel.HIGH
            else -> RiskLevel.CRITICAL
        }
    }

    private fun Double.roundToInt(): Int {
        return kotlin.math.round(this).toInt()
    }
}