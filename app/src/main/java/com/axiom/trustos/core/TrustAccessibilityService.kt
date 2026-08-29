package com.axiom.trustos.core

import android.accessibilityservice.AccessibilityService
import android.util.Patterns
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.axiom.trustos.core.context.ContextDetector
import com.axiom.trustos.core.detector.TextRiskDetector
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.engine.AnalysisEngine
import com.axiom.trustos.core.engine.SecureAnalysisEngine
import com.axiom.trustos.core.engine.TrustEngine
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.model.RiskLevel
import com.axiom.trustos.core.ocr.OcrEngine
import com.axiom.trustos.core.privacy.PrivacyController
import com.axiom.trustos.core.privacy.PrivacyMode
import com.axiom.trustos.ui.WarningOverlay

class TrustAccessibilityService : AccessibilityService() {

    private val contextDetector = ContextDetector()

    private lateinit var warningOverlay: WarningOverlay
    private lateinit var ocrEngine: OcrEngine
    private lateinit var screenCaptureHelper: ScreenCaptureHelper

    private val secureAnalysisEngine =
        SecureAnalysisEngine(
            privacyController = PrivacyController(),
            analysisEngine = AnalysisEngine(
                urlRiskDetector = UrlRiskDetector(),
                textRiskDetector = TextRiskDetector(),
                trustEngine = TrustEngine()
            )
        )

    private val dismissedThreats = mutableSetOf<String>()
    private var activeThreatKey: String? = null
    private var lastPackageName: String? = null
    private var lastAnalyzedKey: String? = null

    override fun onServiceConnected() {
        super.onServiceConnected()

        warningOverlay = WarningOverlay(
            context = this,
            onIgnore = { threatKey ->
                rememberDismissedThreat(threatKey)
                activeThreatKey = threatKey
            }
        )

        ocrEngine = OcrEngine()
        screenCaptureHelper = ScreenCaptureHelper(this)

        loadDismissedThreats()

        android.util.Log.d(TAG, "TrustOS Accessibility Service connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {

        if (event == null) return

        val packageName = event.packageName?.toString() ?: return

        if (packageName == this.packageName) return

        if (lastPackageName != packageName) {
            lastPackageName = packageName
            lastAnalyzedKey = null
            activeThreatKey = null
        }

        val rootNode = rootInActiveWindow ?: return

        val visibleText = extractVisibleText(rootNode)

        if (visibleText.isBlank()) return

        val normalizedText = normalizeText(visibleText)
        val analysisKey = "$packageName|$normalizedText"

        if (analysisKey == lastAnalyzedKey) return

        val detectedUrl = extractUrl(visibleText)

        val appContext =
            contextDetector.classifyPackage(packageName)

        val result =
            secureAnalysisEngine.analyze(
                context = appContext,
                text = visibleText,
                url = detectedUrl
            )

        if (result.privacyDecision.mode != PrivacyMode.SCAN) {
            lastAnalyzedKey = analysisKey
            return
        }

        lastAnalyzedKey = analysisKey

        val assessment = result.riskAssessment

        android.util.Log.d(
            TAG,
            "Risk: ${assessment?.score} Level: ${assessment?.level} Confidence: ${assessment?.confidence}"
        )

        if (
            assessment != null &&
            (
                    assessment.level == RiskLevel.HIGH ||
                            assessment.level == RiskLevel.CRITICAL
                    )
        ) {
            handleThreat(
                packageName,
                visibleText,
                detectedUrl,
                assessment
            )
        }
    }

    override fun onInterrupt() {
        android.util.Log.d(
            TAG,
            "TrustOS Accessibility Service interrupted"
        )
    }

    private fun handleThreat(
        packageName: String,
        text: String,
        url: String?,
        assessment: RiskAssessment
    ) {

        val threatKey =
            createThreatKey(
                packageName,
                text,
                url,
                assessment
            )

        android.util.Log.d(
            TAG,
            "THREAT KEY: $threatKey"
        )

        if (dismissedThreats.contains(threatKey)) {
            android.util.Log.d(
                TAG,
                "Threat dismissed"
            )
            return
        }

        if (activeThreatKey == threatKey) {
            android.util.Log.d(
                TAG,
                "Same threat already handled"
            )
            return
        }

        activeThreatKey = threatKey

        warningOverlay.show(
            assessment = assessment,
            threatKey = threatKey
        )
    }

    private fun rememberDismissedThreat(
        threatKey: String
    ) {

        if (threatKey.isBlank()) return

        dismissedThreats.add(threatKey)

        getSharedPreferences(
            PREFS_NAME,
            MODE_PRIVATE
        )
            .edit()
            .putStringSet(
                DISMISSED_THREATS_KEY,
                dismissedThreats.toSet()
            )
            .apply()
    }

    private fun loadDismissedThreats() {

        val saved =
            getSharedPreferences(
                PREFS_NAME,
                MODE_PRIVATE
            )
                .getStringSet(
                    DISMISSED_THREATS_KEY,
                    emptySet()
                )
                ?.toSet()
                ?: emptySet()

        dismissedThreats.clear()
        dismissedThreats.addAll(saved)
    }

    private fun createThreatKey(
        packageName: String,
        text: String,
        url: String?,
        assessment: RiskAssessment
    ): String {

        if (!url.isNullOrBlank()) {
            return "$packageName|URL|${normalizeUrl(url)}"
        }

        val normalized = normalizeText(text)

        val evidence =
            SUSPICIOUS_PHRASES
                .filter {
                    containsPhrase(normalized, it)
                }
                .distinct()
                .sorted()

        if (evidence.isNotEmpty()) {
            return "$packageName|TEXT|${evidence.joinToString("|")}"
        }

        val reasons =
            assessment.reasons
                .map { it.lowercase().trim() }
                .distinct()
                .sorted()

        return "$packageName|REASON|${reasons.joinToString("|")}"
    }

    private fun containsPhrase(
        text: String,
        phrase: String
    ): Boolean {

        return if (phrase.contains(" ")) {
            text.contains(phrase)
        } else {
            Regex(
                """\b${Regex.escape(phrase)}\b"""
            ).containsMatchIn(text)
        }
    }

    private fun normalizeText(text: String): String {
        return text
            .lowercase()
            .replace(Regex("\\d{1,2}:\\d{2}"), "")
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private fun normalizeUrl(url: String): String {
        return url
            .lowercase()
            .trim()
            .removeSuffix("/")
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

        if (node == null) return ""

        val builder = StringBuilder()

        collectText(node, builder)

        return builder.toString().trim()
    }

    private fun collectText(
        node: AccessibilityNodeInfo,
        builder: StringBuilder
    ) {

        node.text?.toString()?.let {
            if (it.isNotBlank()) {
                builder.append(it).append('\n')
            }
        }

        node.contentDescription?.toString()?.let {
            if (it.isNotBlank()) {
                builder.append(it).append('\n')
            }
        }

        for (i in 0 until node.childCount) {
            node.getChild(i)?.let {
                collectText(it, builder)
            }
        }
    }

    companion object {

        private const val TAG = "TrustOS"

        private const val PREFS_NAME =
            "trustos_preferences"

        private const val DISMISSED_THREATS_KEY =
            "dismissed_threats"

        private val SUSPICIOUS_PHRASES =
            listOf(
                "urgent",
                "immediately",
                "right now",
                "act now",
                "act immediately",
                "respond immediately",
                "last chance",
                "final warning",
                "expires today",
                "account expires",
                "within 24 hours",
                "within 1 hour",
                "within one hour",
                "within 30 minutes",
                "hurry",
                "account will be blocked",
                "account suspended",
                "account locked",
                "account will be closed",
                "access will be revoked",
                "verify your account",
                "password",
                "otp",
                "one time password",
                "pin",
                "cvv",
                "verification code",
                "login credentials",
                "share your otp",
                "send your otp",
                "enter your otp",
                "provide your otp",
                "share your pin",
                "enter your pin",
                "share your cvv",
                "enter your cvv",
                "make a payment",
                "payment failed",
                "payment pending",
                "payment declined",
                "payment required",
                "confirm payment",
                "verify payment",
                "unauthorized transaction",
                "suspicious transaction",
                "transaction failed",
                "transaction pending",
                "refund pending",
                "claim your refund",
                "bank account",
                "bank details",
                "banking details",
                "upi payment",
                "upi transaction",
                "upi id",
                "card details",
                "debit card",
                "credit card",
                "click here",
                "click the link",
                "verify now",
                "update now",
                "confirm now",
                "tap here",
                "login here",
                "customer support",
                "customer care",
                "security team",
                "security department",
                "bank officer",
                "bank representative",
                "official support",
                "account manager",
                "kyc department",
                "verification department",
                "fraud department",
                "rbi",
                "reserve bank of india",
                "income tax department",
                "government official"
            )
    }
}