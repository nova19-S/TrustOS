package com.axiom.trustos.core.engine

import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.privacy.AppContext
import com.axiom.trustos.core.privacy.PrivacyController
import com.axiom.trustos.core.privacy.PrivacyDecision
import com.axiom.trustos.core.privacy.PrivacyMode

data class SecureAnalysisResult(
    val privacyDecision: PrivacyDecision,
    val riskAssessment: RiskAssessment?
)

class SecureAnalysisEngine(
    private val privacyController: PrivacyController,
    private val analysisEngine: AnalysisEngine
) {

    fun analyze(
        context: AppContext,
        text: String? = null,
        url: String? = null
    ): SecureAnalysisResult {
        val decision = privacyController.evaluate(context)

        val assessment = if (decision.mode == PrivacyMode.SCAN) {
            analysisEngine.analyze(text = text, url = url)
        } else {
            null
        }

        return SecureAnalysisResult(
            privacyDecision = decision,
            riskAssessment = assessment
        )
    }
}
