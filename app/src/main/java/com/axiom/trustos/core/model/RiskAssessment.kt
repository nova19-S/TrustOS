package com.axiom.trustos.core.model

/**
 * Combined TrustOS risk assessment.
 *
 * @param score Final risk score from 0 to 100.
 * @param confidence Certainty of the assessment, from 0.0 to 1.0.
 * @param level Mapped [RiskLevel] for this score.
 * @param reasons Human-readable explanations for the assessment.
 */
data class RiskAssessment(
    val score: Int,
    val confidence: Double,
    val level: RiskLevel,
    val reasons: List<String>
)
