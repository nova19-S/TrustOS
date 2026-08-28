package com.axiom.trustos.core.engine

import com.axiom.trustos.core.model.DetectionResult
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.model.RiskLevel

class TrustEngine {

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

        val score = weightedScore
            .roundToInt()
            .coerceIn(0, 100)

        val confidence = results
            .map { it.confidence }
            .average()
            .coerceIn(0.0, 1.0)

        return RiskAssessment(
            score = score,
            confidence = confidence,
            level = riskLevelFor(score),
            reasons = results
                .map { it.reason }
                .distinct()
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