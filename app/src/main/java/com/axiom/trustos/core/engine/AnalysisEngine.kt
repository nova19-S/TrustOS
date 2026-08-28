package com.axiom.trustos.core.engine

import com.axiom.trustos.core.detector.TextRiskDetector
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.model.RiskAssessment

class AnalysisEngine(
    private val urlRiskDetector: UrlRiskDetector,
    private val textRiskDetector: TextRiskDetector,
    private val trustEngine: TrustEngine
) {

    fun analyze(
        text: String? = null,
        url: String? = null
    ): RiskAssessment {

        val detections = mutableListOf<com.axiom.trustos.core.model.DetectionResult>()

        if (!text.isNullOrBlank()) {
            detections += textRiskDetector.analyze(text)
        }

        if (!url.isNullOrBlank()) {
            detections += urlRiskDetector.analyze(url)
        }

        return trustEngine.assess(detections)
    }
}