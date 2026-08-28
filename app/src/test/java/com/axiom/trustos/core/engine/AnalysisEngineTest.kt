package com.axiom.trustos.core.engine

import com.axiom.trustos.core.detector.TextRiskDetector
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.model.RiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalysisEngineTest {

    private val urlRiskDetector = UrlRiskDetector()
    private val textRiskDetector = TextRiskDetector()
    private val trustEngine = TrustEngine()
    private val analysisEngine = AnalysisEngine(
        urlRiskDetector = urlRiskDetector,
        textRiskDetector = textRiskDetector,
        trustEngine = trustEngine
    )

    @Test
    fun analyze_emptyInput_returnsZeroRiskLowLevel() {
        val assessment = analysisEngine.analyze()

        assertEquals(0, assessment.score)
        assertEquals(RiskLevel.LOW, assessment.level)
        assertTrue(assessment.reasons.isEmpty())
    }

    @Test
    fun analyze_textOnly_returnsNonZeroScoreFromTrustEngine() {
        val text =
            "URGENT! Your account will be blocked. Verify your password immediately."
        val textFindings = textRiskDetector.analyze(text)
        val expected = trustEngine.assess(textFindings)

        val assessment = analysisEngine.analyze(text = text)

        assertTrue(textFindings.isNotEmpty())
        assertTrue(assessment.score > 0)
        assertEquals(expected, assessment)
    }

    @Test
    fun analyze_urlOnly_returnsNonZeroScore() {
        val url = "http://192.168.1.10/login"
        val urlFindings = urlRiskDetector.analyze(url)
        val expected = trustEngine.assess(urlFindings)

        val assessment = analysisEngine.analyze(url = url)

        assertTrue(urlFindings.isNotEmpty())
        assertTrue(assessment.score > 0)
        assertEquals(expected, assessment)
    }

    @Test
    fun analyze_textAndUrl_combinesBothDetectors() {
        val text =
            "URGENT! Your bank account will be blocked. Verify your password immediately."
        val url = "http://192.168.1.10/login"

        val textFindings = textRiskDetector.analyze(text)
        val urlFindings = urlRiskDetector.analyze(url)
        val expected = trustEngine.assess(textFindings + urlFindings)

        val assessment = analysisEngine.analyze(text = text, url = url)

        assertTrue(textFindings.isNotEmpty())
        assertTrue(urlFindings.isNotEmpty())
        assertEquals(expected, assessment)
        assertEquals(expected.score, assessment.score)
        assertTrue(assessment.reasons.containsAll(textFindings.map { it.reason }))
        assertTrue(assessment.reasons.containsAll(urlFindings.map { it.reason }))
    }

    @Test
    fun analyze_blankTextWithValidUrl_usesOnlyUrlDetector() {
        val url = "http://192.168.1.10/login"
        val urlOnly = trustEngine.assess(urlRiskDetector.analyze(url))

        val assessment = analysisEngine.analyze(text = "   ", url = url)

        assertEquals(urlOnly, assessment)
        assertTrue(assessment.reasons.isNotEmpty())
        assertTrue(
            assessment.reasons.none { reason ->
                reason == "Urgency language detected" ||
                    reason == "Account threat or suspension language detected"
            }
        )
    }

    @Test
    fun analyze_validTextWithBlankUrl_usesOnlyTextDetector() {
        val text =
            "URGENT! Your account will be blocked. Verify your password immediately."
        val textOnly = trustEngine.assess(textRiskDetector.analyze(text))

        val assessment = analysisEngine.analyze(text = text, url = "   ")

        assertEquals(textOnly, assessment)
        assertTrue(assessment.reasons.isNotEmpty())
        assertTrue(
            assessment.reasons.none { reason ->
                reason == "URL does not use HTTPS" ||
                    reason == "URL uses an IP address instead of a domain"
            }
        )
    }
}
