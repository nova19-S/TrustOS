package com.axiom.trustos.core.engine

import com.axiom.trustos.core.intel.NetworkIntelRepository
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

        /*
         * Each finding contributes according to:
         *
         * risk contribution × confidence
         *
         * This prevents a low-confidence finding from having
         * the same influence as a highly reliable finding.
         */
        val weightedScore = results.sumOf { result ->
            result.riskContribution * result.confidence
        }

        val localScore = weightedScore
            .roundToInt()
            .coerceIn(0, 100)

        val reasons = results
            .map { it.reason }
            .distinct()

        val intelOutcome = applyNetworkIntel(localScore, reasons)

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
            trendReportCount = intelOutcome.reportCount
        )
    }

    /**
     * Reports this finding's category to the network and checks whether
     * that category is currently trending. If it is, boosts the score
     * and adds a reason explaining why — so the "why flagged" UI is
     * always honest about what contributed to the number.
     *
     * If no repository was provided (e.g. a quick local-only preview),
     * this is a no-op and returns the local score unchanged.
     */
    private data class IntelOutcome(
        val finalScore: Int,
        val reasons: List<String>,
        val isTrending: Boolean,
        val reportCount: Int
    )

    private fun applyNetworkIntel(
        localScore: Int,
        reasons: List<String>
    ): IntelOutcome {

        val repository = networkIntelRepository
            ?: return IntelOutcome(localScore, reasons, isTrending = false, reportCount = 0)

        val category = primaryCategoryForReasons(reasons)

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