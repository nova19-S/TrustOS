package com.axiom.trustos.core.engine

import com.axiom.trustos.core.model.DetectionResult
import com.axiom.trustos.core.model.RiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustEngineTest {

    private val engine = TrustEngine()

    @Test
    fun assess_emptyResults_returnsZeroRiskLowLevel() {
        val assessment = engine.assess(emptyList())

        assertEquals(0, assessment.score)
        assertEquals(0.0, assessment.confidence, 0.0)
        assertEquals(RiskLevel.LOW, assessment.level)
        assertTrue(assessment.reasons.isEmpty())
    }

    @Test
    fun assess_singleLowRiskDetection_returnsScore20AndLow() {
        val results = listOf(
            DetectionResult(
                detectorName = "Test Detector",
                reason = "Minor concern",
                riskContribution = 20,
                confidence = 0.8
            )
        )

        val assessment = engine.assess(results)

        assertEquals(20, assessment.score)
        assertEquals(RiskLevel.LOW, assessment.level)
    }

    @Test
    fun assess_multipleDetections_sumsScoreAndAveragesConfidence() {
        val results = listOf(
            DetectionResult(
                detectorName = "URL Detector",
                reason = "Suspicious URL",
                riskContribution = 35,
                confidence = 0.9
            ),
            DetectionResult(
                detectorName = "NLP Detector",
                reason = "Urgent language",
                riskContribution = 25,
                confidence = 0.8
            )
        )

        val assessment = engine.assess(results)

        assertEquals(60, assessment.score)
        assertEquals(RiskLevel.HIGH, assessment.level)
        assertEquals(0.85, assessment.confidence, 0.0001)
        assertEquals(2, assessment.reasons.size)
        assertEquals("Suspicious URL", assessment.reasons[0])
        assertEquals("Urgent language", assessment.reasons[1])
    }

    @Test
    fun assess_scoreAbove100_clampsTo100AndCritical() {
        val results = listOf(
            DetectionResult(
                detectorName = "Detector A",
                reason = "High risk finding A",
                riskContribution = 80,
                confidence = 0.9
            ),
            DetectionResult(
                detectorName = "Detector B",
                reason = "High risk finding B",
                riskContribution = 40,
                confidence = 0.9
            )
        )

        val assessment = engine.assess(results)

        assertEquals(100, assessment.score)
        assertEquals(RiskLevel.CRITICAL, assessment.level)
    }

    @Test
    fun assess_confidenceValues_returnsAverage() {
        val results = listOf(
            DetectionResult(
                detectorName = "Detector A",
                reason = "Finding A",
                riskContribution = 10,
                confidence = 0.6
            ),
            DetectionResult(
                detectorName = "Detector B",
                reason = "Finding B",
                riskContribution = 10,
                confidence = 1.0
            )
        )

        val assessment = engine.assess(results)

        assertEquals(0.8, assessment.confidence, 0.0001)
    }
}
