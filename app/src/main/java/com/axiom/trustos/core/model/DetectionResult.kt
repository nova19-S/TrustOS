package com.axiom.trustos.core.model

/**
 * Result from a single detector.
 *
 * @param detectorName Identifier of the detector that produced this result.
 * @param reason Human-readable explanation of the finding.
 * @param riskContribution Score from 0 to 100 contributed toward overall risk.
 * @param confidence Certainty of the finding, from 0.0 to 1.0.
 */
data class DetectionResult(
    val detectorName: String,
    val reason: String,
    val riskContribution: Int,
    val confidence: Double
)
