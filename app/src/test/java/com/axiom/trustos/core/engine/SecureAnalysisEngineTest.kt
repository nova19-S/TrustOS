package com.axiom.trustos.core.engine

import com.axiom.trustos.core.detector.TextRiskDetector
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.model.RiskLevel
import com.axiom.trustos.core.privacy.AppContext
import com.axiom.trustos.core.privacy.PrivacyController
import com.axiom.trustos.core.privacy.PrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureAnalysisEngineTest {

    private val analysisEngine = AnalysisEngine(
        urlRiskDetector = UrlRiskDetector(),
        textRiskDetector = TextRiskDetector(),
        trustEngine = TrustEngine()
    )
    private val secureAnalysisEngine = SecureAnalysisEngine(
        privacyController = PrivacyController(),
        analysisEngine = analysisEngine
    )

    @Test
    fun analyze_browser_scansAndReturnsRiskAssessment() {
        val text = "URGENT! Verify your account immediately."
        val url = "http://192.168.1.10/login"
        val expectedAssessment = analysisEngine.analyze(text = text, url = url)

        val result = secureAnalysisEngine.analyze(
            context = AppContext.BROWSER,
            text = text,
            url = url
        )

        assertEquals(PrivacyMode.SCAN, result.privacyDecision.mode)
        assertNotNull(result.riskAssessment)
        assertEquals(expectedAssessment, result.riskAssessment)
        assertTrue(result.riskAssessment!!.score > 0)
    }

    @Test
    fun analyze_gallery_pausesAndDoesNotAnalyze() {
        val result = secureAnalysisEngine.analyze(
            context = AppContext.GALLERY,
            text = "URGENT! Verify your account.",
            url = "http://192.168.1.10/login"
        )

        assertEquals(PrivacyMode.PAUSE, result.privacyDecision.mode)
        assertNull(result.riskAssessment)
    }

    @Test
    fun analyze_payment_restrictsAndDoesNotAnalyze() {
        val result = secureAnalysisEngine.analyze(
            context = AppContext.PAYMENT,
            text = "URGENT! Verify your account.",
            url = "http://192.168.1.10/login"
        )

        assertEquals(PrivacyMode.RESTRICT, result.privacyDecision.mode)
        assertNull(result.riskAssessment)
    }

    @Test
    fun analyze_banking_restrictsAndDoesNotAnalyze() {
        val result = secureAnalysisEngine.analyze(
            context = AppContext.BANKING,
            text = "URGENT! Verify your account.",
            url = "http://192.168.1.10/login"
        )

        assertEquals(PrivacyMode.RESTRICT, result.privacyDecision.mode)
        assertNull(result.riskAssessment)
    }

    @Test
    fun analyze_passwordEntry_restrictsAndDoesNotAnalyze() {
        val result = secureAnalysisEngine.analyze(
            context = AppContext.PASSWORD_ENTRY,
            text = "URGENT! Verify your account.",
            url = "http://192.168.1.10/login"
        )

        assertEquals(PrivacyMode.RESTRICT, result.privacyDecision.mode)
        assertNull(result.riskAssessment)
    }

    @Test
    fun analyze_unknown_pausesAndDoesNotAnalyze() {
        val result = secureAnalysisEngine.analyze(
            context = AppContext.UNKNOWN,
            text = "URGENT! Verify your account.",
            url = "http://192.168.1.10/login"
        )

        assertEquals(PrivacyMode.PAUSE, result.privacyDecision.mode)
        assertNull(result.riskAssessment)
    }

    @Test
    fun analyze_browserWithBlankInput_returnsZeroRiskAssessment() {
        val expectedAssessment = analysisEngine.analyze(text = "", url = "")

        val result = secureAnalysisEngine.analyze(
            context = AppContext.BROWSER,
            text = "",
            url = ""
        )

        assertEquals(PrivacyMode.SCAN, result.privacyDecision.mode)
        assertNotNull(result.riskAssessment)
        assertEquals(expectedAssessment, result.riskAssessment)
        assertEquals(0, result.riskAssessment!!.score)
        assertEquals(RiskLevel.LOW, result.riskAssessment!!.level)
        assertTrue(result.riskAssessment!!.reasons.isEmpty())
    }
}
