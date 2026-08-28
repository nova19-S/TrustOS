package com.axiom.trustos.core

import com.axiom.trustos.core.model.RiskLevel
import com.axiom.trustos.ui.WarningOverlay
import android.util.Patterns
import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.axiom.trustos.core.context.ContextDetector
import com.axiom.trustos.core.detector.TextRiskDetector
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.engine.AnalysisEngine
import com.axiom.trustos.core.engine.SecureAnalysisEngine
import com.axiom.trustos.core.engine.TrustEngine
import com.axiom.trustos.core.privacy.PrivacyController


class TrustAccessibilityService : AccessibilityService() {

    private val contextDetector = ContextDetector()

    private lateinit var warningOverlay: WarningOverlay

    private val secureAnalysisEngine = SecureAnalysisEngine(
        privacyController = PrivacyController(),
        analysisEngine = AnalysisEngine(
            urlRiskDetector = UrlRiskDetector(),
            textRiskDetector = TextRiskDetector(),
            trustEngine = TrustEngine()
        )
    )

    private var suppressedScreenKey: Int? = null

    private var lastPackageName: String? = null

    private var lastAnalyzedKey: Int? = null

    override fun onServiceConnected() {
        super.onServiceConnected()

        warningOverlay = WarningOverlay(this)

        android.util.Log.d(
            TAG,
            "TrustOS Accessibility Service connected"
        )
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {

        if (event == null) {
            return
        }

        val packageName = event.packageName?.toString() ?: return

        // Ignore TrustOS' own accessibility events.
        if (packageName == this.packageName) {
            return
        }

        // If the foreground application changed, allow a fresh analysis.
        if (lastPackageName != packageName) {
            lastPackageName = packageName
            lastAnalyzedKey = null
            suppressedScreenKey = null
        }

        val rootNode = rootInActiveWindow ?: return

        val visibleText = extractVisibleText(rootNode)

        if (visibleText.isBlank()) {
            return
        }

        val normalizedText = visibleText
            .replace(Regex("\\s+"), " ")
            .trim()

        val analysisKey =
            "$packageName|$normalizedText".hashCode()

        /*
         * Do not analyze the exact same screen repeatedly.
         */
        if (analysisKey == lastAnalyzedKey) {
            return
        }

        /*
         * User already dismissed this exact screen.
         * Do not show the warning again until the screen/content changes.
         */
        if (analysisKey == suppressedScreenKey) {
            return
        }

        val detectedUrl = extractUrl(visibleText)

        val appContext =
            contextDetector.classifyPackage(packageName)

        val result = secureAnalysisEngine.analyze(
            context = appContext,
            text = visibleText,
            url = detectedUrl
        )

        if (
            result.privacyDecision.mode !=
            com.axiom.trustos.core.privacy.PrivacyMode.SCAN
        ) {

            android.util.Log.d(
                TAG,
                "🛡️ TrustOS Privacy Protection Active"
            )

            android.util.Log.d(
                TAG,
                "Context: $appContext"
            )

            android.util.Log.d(
                TAG,
                "Mode: ${result.privacyDecision.mode}"
            )

            android.util.Log.d(
                TAG,
                "Reason: ${result.privacyDecision.reason}"
            )

            lastAnalyzedKey = analysisKey
            return
        }

        lastAnalyzedKey = analysisKey

        val assessment = result.riskAssessment

        if (
            assessment != null &&
            (
                    assessment.level == RiskLevel.HIGH ||
                            assessment.level == RiskLevel.CRITICAL
                    )
        ) {

            android.util.Log.d(
                TAG,
                "⚠️ HIGH/CRITICAL detected. Showing warning overlay."
            )

            /*
             * IMPORTANT:
             * Remember that the user has already been warned
             * about this exact screen.
             */
            suppressedScreenKey = analysisKey

            warningOverlay.show(assessment)
        }

        android.util.Log.d(
            TAG,
            "--------------------------------"
        )

        android.util.Log.d(
            TAG,
            "Foreground package: $packageName"
        )

        android.util.Log.d(
            TAG,
            "Detected context: $appContext"
        )

        android.util.Log.d(
            TAG,
            "Privacy mode: ${result.privacyDecision.mode}"
        )

        if (assessment == null) {

            android.util.Log.d(
                TAG,
                "TrustOS analysis skipped because of privacy mode."
            )

        } else {

            android.util.Log.d(
                TAG,
                "Risk score: ${assessment.score}/100"
            )

            android.util.Log.d(
                TAG,
                "Risk level: ${assessment.level}"
            )

            android.util.Log.d(
                TAG,
                "Confidence: ${assessment.confidence}"
            )

            android.util.Log.d(
                TAG,
                "Reasons: ${assessment.reasons}"
            )
        }

        android.util.Log.d(
            TAG,
            "--------------------------------"
        )
    }

    override fun onInterrupt() {
        android.util.Log.d(
            TAG,
            "TrustOS Accessibility Service interrupted"
        )
    }

    private fun extractUrl(text: String): String? {
        val matcher = Patterns.WEB_URL.matcher(text)

        return if (matcher.find()) {
            matcher.group()
        } else {
            null
        }
    }

    private fun extractVisibleText(
        node: AccessibilityNodeInfo?
    ): String {
        if (node == null) {
            return ""
        }

        val textBuilder = StringBuilder()

        collectText(node, textBuilder)

        return textBuilder
            .toString()
            .trim()
    }

    private fun collectText(
        node: AccessibilityNodeInfo,
        textBuilder: StringBuilder
    ) {
        node.text?.toString()?.let { text ->
            if (text.isNotBlank()) {
                textBuilder.append(text).append('\n')
            }
        }

        node.contentDescription?.toString()?.let { description ->
            if (description.isNotBlank()) {
                textBuilder.append(description).append('\n')
            }
        }

        for (index in 0 until node.childCount) {
            node.getChild(index)?.let { child ->
                collectText(child, textBuilder)
            }
        }
    }

    companion object {
        private const val TAG = "TrustOS"
    }
}