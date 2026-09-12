package com.axiom.trustos.core.model

import com.axiom.trustos.core.intel.ThreatCategory

/**
 * Combined TrustOS risk assessment.
 *
 * @param score Final risk score from 0 to 100 (includes any network trend boost).
 * @param confidence Certainty of the assessment, from 0.0 to 1.0.
 * @param level Mapped [RiskLevel] for this score.
 * @param reasons Human-readable explanations for the assessment (local detection only).
 * @param isTrending Whether the network layer found this threat category trending.
 * @param trendReportCount How many (weighted) recent reports contributed to trending status.
 */
data class RiskAssessment(
    val score: Int,
    val confidence: Double,
    val level: RiskLevel,
    val reasons: List<String>,
    val isTrending: Boolean = false,
    val trendReportCount: Int = 0,
    val category: String = "GENERIC_SUSPICIOUS"
)