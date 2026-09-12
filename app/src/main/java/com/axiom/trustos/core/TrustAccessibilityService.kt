package com.axiom.trustos.core

import com.axiom.trustos.core.threat.ThreatRecord
import com.axiom.trustos.core.threat.ThreatVaultRepository
import android.accessibilityservice.AccessibilityService
import android.graphics.Bitmap
import android.util.Patterns
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.axiom.trustos.core.context.ContextDetector
import com.axiom.trustos.core.detector.NlpRiskDetector
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

    private val TAG = "TrustOS"
    private val contextDetector = ContextDetector()

    private lateinit var warningOverlay: WarningOverlay
    private lateinit var ocrEngine: OcrEngine
    private lateinit var screenCaptureHelper: ScreenCaptureHelper
    private lateinit var secureAnalysisEngine: SecureAnalysisEngine

    private lateinit var nlpRiskDetector: com.axiom.trustos.core.detector.NlpRiskDetector

    private lateinit var networkIntelRepository: com.axiom.trustos.core.intel.NetworkIntelRepository

    private lateinit var threatVaultRepository: ThreatVaultRepository

    private var pendingThreatRecord: ThreatRecord? = null

    private var lastPackageName: String? = null
    private var lastWindowId = -1
    private var lastAnalyzedKey: String? = null
    private var activeThreatKey: String? = null
    private var ocrInProgressKey: String? = null

    private var lastOcrCaptureTimeMs: Long = 0L
    private val ocrMinIntervalMs = 2000L

    private val dismissedOnCurrentScreen = mutableSetOf<String>()

    override fun onServiceConnected() {
        super.onServiceConnected()

        networkIntelRepository =
            com.axiom.trustos.core.intel.NetworkIntelRepository(this)

        secureAnalysisEngine =
            SecureAnalysisEngine(
                privacyController = PrivacyController(this),
                analysisEngine = AnalysisEngine(
                    urlRiskDetector = UrlRiskDetector(),
                    textRiskDetector = TextRiskDetector(),
                    trustEngine = TrustEngine(
                        networkIntelRepository = networkIntelRepository
                    )
                )
            )

        threatVaultRepository = ThreatVaultRepository(this)

        warningOverlay = WarningOverlay(
            context = this,

            onIgnore = { threatKey ->
                dismissCurrentThreat(threatKey)
            },

            onBlockAndSave = { threatKey ->

                val record =
                    pendingThreatRecord

                if (
                    record != null &&
                    record.threatKey == threatKey
                ) {

                    val alreadyReportedBefore =
                        threatVaultRepository.containsThreat(threatKey)

                    threatVaultRepository.saveThreat(record)

                    android.util.Log.d(
                        TAG,
                        "THREAT SAVED TO VAULT: $threatKey"
                    )

                    if (!alreadyReportedBefore) {

                        val category =
                            com.axiom.trustos.core.intel.primaryCategoryForReasons(record.reasons)

                        networkIntelRepository.reportThreat(category)

                        android.util.Log.d(
                            TAG,
                            "REPORTED TO NETWORK (user-confirmed, new): category=$category"
                        )

                    } else {

                        android.util.Log.d(
                            TAG,
                            "SKIPPED NETWORK REPORT — already reported this exact threat previously: $threatKey"
                        )
                    }

                    pendingThreatRecord = null
                }
            }
        )

        ocrEngine = OcrEngine()
        screenCaptureHelper = ScreenCaptureHelper(this)

        nlpRiskDetector = com.axiom.trustos.core.detector.NlpRiskDetector()
        nlpRiskDetector.prepareModel(
            onReady = {
                android.util.Log.d(TAG, "NLP model ready")
            },
            onFailure = { exception ->
                android.util.Log.e(TAG, "NLP model download failed", exception)
            }
        )

        android.util.Log.d(TAG, "================================")
        android.util.Log.d(TAG, "TrustOS Accessibility Service READY")
        android.util.Log.d(TAG, "================================")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val packageName = event.packageName?.toString() ?: return

        if (packageName == this.packageName) return

        val windowChanged =
            event.windowId != lastWindowId

        val packageChanged =
            packageName != lastPackageName

        if (packageChanged || windowChanged) {
            android.util.Log.d(
                TAG,
                "SCREEN CHANGE | package=$packageName window=${event.windowId}"
            )

            lastPackageName = packageName
            lastWindowId = event.windowId
            lastAnalyzedKey = null
            activeThreatKey = null
            ocrInProgressKey = null
            dismissedOnCurrentScreen.clear()

            warningOverlay.hide()
        }

        val rootNode = rootInActiveWindow

        if (rootNode == null) {
            android.util.Log.d(
                TAG,
                "No root node available"
            )
            return
        }

        val visibleText =
            extractVisibleText(rootNode)


        if (visibleText.isBlank()) {
            android.util.Log.d(
                TAG,
                "No visible text, trying OCR"
            )

            captureAndAnalyzeWithOcr(
                packageName = packageName,
                windowId = event.windowId,
                appContext = if (containsPasswordField(rootNode)) {
                    com.axiom.trustos.core.privacy.AppContext.PASSWORD_ENTRY
                } else {
                    contextDetector.classifyPackage(packageName)
                }
            )

            return
        }

        if (visibleText.length < 80) {
            android.util.Log.d(
                TAG,
                "Insufficient visible text, trying OCR"
            )

            captureAndAnalyzeWithOcr(
                packageName = packageName,
                windowId = event.windowId,
                appContext = if (containsPasswordField(rootNode)) {
                    com.axiom.trustos.core.privacy.AppContext.PASSWORD_ENTRY
                } else {
                    contextDetector.classifyPackage(packageName)
                }
            )

            return
        }

        val baseContext =
            contextDetector.classifyPackage(packageName)

        val appContext =
            if (containsPasswordField(rootNode)) {
                com.axiom.trustos.core.privacy.AppContext.PASSWORD_ENTRY
            } else {
                baseContext
            }

        analyzeText(
            packageName = packageName,
            windowId = event.windowId,
            appContext = appContext,
            text = visibleText
        )
    }

    private fun captureAndAnalyzeWithOcr(
        packageName: String,
        windowId: Int,
        appContext: com.axiom.trustos.core.privacy.AppContext
    ) {

        val ocrKey =
            "$packageName|$windowId|OCR"

        if (ocrInProgressKey == ocrKey) {
            android.util.Log.d(
                TAG,
                "OCR already running for current screen"
            )
            return
        }

        if (lastAnalyzedKey == ocrKey) {
            return
        }

        val now = System.currentTimeMillis()
        val timeSinceLastCapture = now - lastOcrCaptureTimeMs

        if (timeSinceLastCapture < ocrMinIntervalMs) {
            android.util.Log.d(
                TAG,
                "OCR throttled — only ${timeSinceLastCapture}ms since last capture"
            )
            return
        }

        lastOcrCaptureTimeMs = now

        ocrInProgressKey = ocrKey

        android.util.Log.d(
            TAG,
            "--------------------------------"
        )

        android.util.Log.d(
            TAG,
            "OCR CAPTURE START"
        )

        android.util.Log.d(
            TAG,
            "Package: $packageName"
        )

        android.util.Log.d(
            TAG,
            "Window: $windowId"
        )

        screenCaptureHelper.capture(
            onSuccess = { bitmap ->

                android.util.Log.d(
                    TAG,
                    "SCREENSHOT CAPTURED"
                )

                ocrEngine.recognizeText(
                    bitmap = bitmap,
                    onSuccess = { ocrText ->

                        ocrInProgressKey = null

                        if (
                            packageName != lastPackageName ||
                            windowId != lastWindowId
                        ) {
                            android.util.Log.d(
                                TAG,
                                "OCR result ignored because screen changed"
                            )
                            return@recognizeText
                        }

                        android.util.Log.d(
                            TAG,
                            "OCR TEXT: ${ocrText.take(500)}"
                        )

                        if (ocrText.isBlank()) {
                            android.util.Log.d(
                                TAG,
                                "OCR found no text"
                            )

                            lastAnalyzedKey = ocrKey
                            return@recognizeText
                        }

                        lastAnalyzedKey = ocrKey

                        analyzeText(
                            packageName = packageName,
                            windowId = windowId,
                            appContext = appContext,
                            text = ocrText
                        )
                    },
                    onFailure = { exception ->

                        ocrInProgressKey = null

                        android.util.Log.e(
                            TAG,
                            "OCR FAILED",
                            exception
                        )
                    }
                )
            },
            onFailure = { errorCode ->

                ocrInProgressKey = null

                android.util.Log.e(
                    TAG,
                    "SCREENSHOT FAILED | error=$errorCode"
                )
            }
        )
    }

    private fun analyzeText(
        packageName: String,
        windowId: Int,
        appContext: com.axiom.trustos.core.privacy.AppContext,
        text: String
    ) {

        val normalizedText =
            normalizeText(text)

        val detectedUrl =
            extractUrl(text)

        val analysisKey =
            "$packageName|$windowId|$normalizedText"

        if (analysisKey == lastAnalyzedKey) {
            return
        }

        lastAnalyzedKey = analysisKey

        android.util.Log.d(
            TAG,
            "--------------------------------"
        )

        android.util.Log.d(
            TAG,
            "SCREEN ANALYSIS"
        )

        android.util.Log.d(
            TAG,
            "Package: $packageName"
        )

        android.util.Log.d(
            TAG,
            "Window: $windowId"
        )

        android.util.Log.d(
            TAG,
            "Context: $appContext"
        )

        android.util.Log.d(
            TAG,
            "URL: ${detectedUrl ?: "NONE"}"
        )

        android.util.Log.d(
            TAG,
            "Text: ${text.take(300)}"
        )

        val result =
            secureAnalysisEngine.analyze(
                context = appContext,
                packageName = packageName,
                text = text,
                url = detectedUrl
            )

        android.util.Log.d(
            TAG,
            "Privacy Mode: ${result.privacyDecision.mode}"
        )

        if (result.privacyDecision.mode != PrivacyMode.SCAN) {
            android.util.Log.d(
                TAG,
                "SCAN PAUSED"
            )
            return
        }

        android.util.Log.d(
            TAG,
            "SCAN CONTINUING"
        )

        val assessment =
            result.riskAssessment

        if (assessment == null) {
            android.util.Log.d(
                TAG,
                "No risk assessment"
            )
            return
        }

        android.util.Log.d(
            TAG,
            "Risk: ${assessment.score}"
        )

        android.util.Log.d(
            TAG,
            "Level: ${assessment.level}"
        )

        android.util.Log.d(
            TAG,
            "Confidence: ${assessment.confidence}"
        )

        android.util.Log.d(
            TAG,
            "Reasons: ${assessment.reasons}"
        )

        val dangerous =
            assessment.level == RiskLevel.HIGH ||
                    assessment.level == RiskLevel.CRITICAL

        if (dangerous) {
            handleThreat(
                packageName = packageName,
                text = text,
                url = detectedUrl,
                assessment = assessment
            )
            return
        }

        android.util.Log.d(
            TAG,
            "No warning required from keyword-based detection — checking NLP in parallel"
        )

        // NLP runs independently, even when the keyword-based detector
        // found nothing dangerous. This is where phrasing that evades
        // exact keyword matches can still be caught.
        nlpRiskDetector.analyze(text) { nlpFindings ->

            if (nlpFindings.isEmpty()) {
                android.util.Log.d(TAG, "NLP found no additional signal")
                return@analyze
            }

            android.util.Log.d(
                TAG,
                "NLP found ${nlpFindings.size} additional finding(s): " +
                        nlpFindings.joinToString { it.reason }
            )

            val nlpOnlyAssessment = com.axiom.trustos.core.engine.TrustEngine()
                .assess(nlpFindings)

            val nlpDangerous =
                nlpOnlyAssessment.level == RiskLevel.HIGH ||
                        nlpOnlyAssessment.level == RiskLevel.CRITICAL

            if (nlpDangerous) {

                android.util.Log.d(
                    TAG,
                    "NLP-ONLY DETECTION crossed threshold — showing warning based on NLP signal"
                )

                handleThreat(
                    packageName = packageName,
                    text = text,
                    url = detectedUrl,
                    assessment = nlpOnlyAssessment
                )
            }
        }
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

        if (dismissedOnCurrentScreen.contains(threatKey)) {
            android.util.Log.d(
                TAG,
                "Threat suppressed on current screen"
            )
            return
        }

        if (activeThreatKey == threatKey) {
            android.util.Log.d(
                TAG,
                "Same threat already active"
            )
            return
        }

        pendingThreatRecord =
            ThreatRecord(
                threatKey = threatKey,
                packageName = packageName,
                indicator = url?.let {
                    normalizeUrl(it)
                },
                threatType = if (url != null) {
                    "SUSPICIOUS_URL"
                } else {
                    "SUSPICIOUS_CONTENT"
                },
                riskScore = assessment.score,
                confidence = assessment.confidence,
                reasons = assessment.reasons,
                createdAt = System.currentTimeMillis()
            )

        activeThreatKey = threatKey

        val alreadySaved =
            threatVaultRepository.containsThreat(threatKey)

        val category =
            com.axiom.trustos.core.intel.primaryCategoryForReasons(assessment.reasons)

        val currentIntel =
            networkIntelRepository.checkIntel(category)

        android.util.Log.d(
            TAG,
            "SHOWING WARNING OVERLAY (alreadySaved=$alreadySaved, reportCount=${currentIntel.reportCount})"
        )

        warningOverlay.show(
            assessment = assessment,
            threatKey = threatKey,
            alreadySaved = alreadySaved,
            similarReportCount = currentIntel.reportCount
        )
    }


    private fun dismissCurrentThreat(
        threatKey: String
    ) {

        if (threatKey.isBlank()) return

        dismissedOnCurrentScreen.add(threatKey)
        activeThreatKey = threatKey

        android.util.Log.d(
            TAG,
            "Threat dismissed for current screen: $threatKey"
        )
    }

    override fun onInterrupt() {
        android.util.Log.d(
            TAG,
            "Accessibility Service interrupted"
        )
    }

    override fun onDestroy() {
        ocrEngine.close()
        nlpRiskDetector.close()
        warningOverlay.hide()
        super.onDestroy()
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

        val normalized =
            normalizeText(text)

        val evidence =
            com.axiom.trustos.core.detector.SuspiciousPhrases.ALL
                .filter {
                    com.axiom.trustos.core.detector.SuspiciousPhrases.containsPhrase(normalized, it)
                }
                .distinct()
                .sorted()

        if (evidence.isNotEmpty()) {
            return "$packageName|TEXT|${evidence.joinToString("|")}"
        }

        val reasons =
            assessment.reasons
                .map {
                    it.lowercase().trim()
                }
                .distinct()
                .sorted()

        return "$packageName|REASON|${reasons.joinToString("|")}"
    }

    private fun normalizeText(
        text: String
    ): String {

        return text
            .lowercase()
            .replace(
                Regex("\\d{1,2}:\\d{2}"),
                ""
            )
            .replace(
                Regex("\\s+"),
                " "
            )
            .trim()
    }

    private fun normalizeUrl(
        url: String
    ): String {

        return url
            .lowercase()
            .trim()
            .removeSuffix("/")
    }

    private fun extractUrl(
        text: String
    ): String? {

        val cleaned = cleanOcrUrlSpacing(text)

        // Try the cleaned text first — this is where a garbled OCR URL
        // like "http:  / / bit . ly / xyz" gets reconstructed properly.
        val fromCleaned = bestUrlCandidate(cleaned)
        if (fromCleaned != null) {
            return fromCleaned
        }

        // Fall back to the raw text in case cleaning wasn't needed/helpful.
        return bestUrlCandidate(text)
    }

    /**
     * Finds every URL-shaped match in the text and returns the most
     * plausible one, instead of blindly taking the first match.
     *
     * OCR text often contains accidental "word.Word" patterns from line
     * wraps (e.g. "activity.\nBank Security" becomes "activity.Bank"),
     * which look domain-shaped but aren't real URLs. We deprioritize
     * those in favor of matches that have a real scheme (http/https) or
     * look like a proper lowercase domain.
     */
    private fun bestUrlCandidate(text: String): String? {

        val matcher = Patterns.WEB_URL.matcher(text)
        val candidates = mutableListOf<String>()

        while (matcher.find()) {
            candidates.add(matcher.group())
        }

        if (candidates.isEmpty()) {
            return null
        }

        return candidates
            .filter { isPlausibleUrl(it) }
            .maxByOrNull { it.length }
            ?: candidates.maxByOrNull { it.length }
    }

    /**
     * Rejects matches that are very likely OCR line-wrap accidents rather
     * than real URLs: no scheme/www, AND an uppercase letter appears right
     * after a dot (a strong signal of "sentence.Sentence" rather than a
     * real domain, since real URLs are essentially always lowercase).
     */
    private fun isPlausibleUrl(candidate: String): Boolean {

        val hasScheme =
            candidate.startsWith("http://", ignoreCase = true) ||
                    candidate.startsWith("https://", ignoreCase = true) ||
                    candidate.startsWith("www.", ignoreCase = true)

        if (hasScheme) {
            return true
        }

        val hasUppercaseAfterDot =
            Regex("""\.[A-Z]""").containsMatchIn(candidate)

        return !hasUppercaseAfterDot
    }

    private fun cleanOcrUrlSpacing(text: String): String {
        return text
            // "https : //" -> "https://"
            .replace(Regex("""(https?)\s*:\s*/\s*/"""), "$1://")
            // "bit . ly" -> "bit.ly", "example . com / path" -> "example.com/path"
            .replace(Regex("""\s*\.\s*(?=[a-zA-Z]{2,})"""), ".")
            // "domain.com / path" -> "domain.com/path"
            .replace(Regex("""(?<=\w)\s+/\s*"""), "/")
    }

    private fun extractVisibleText(
        node: AccessibilityNodeInfo?
    ): String {

        if (node == null) return ""

        val builder =
            StringBuilder()

        collectText(
            node,
            builder
        )

        return builder
            .toString()
            .trim()
    }

    private fun containsPasswordField(
        node: AccessibilityNodeInfo?
    ): Boolean {

        if (node == null) return false

        if (node.isPassword) {
            return true
        }

        for (i in 0 until node.childCount) {
            if (containsPasswordField(node.getChild(i))) {
                return true
            }
        }

        return false
    }

    private fun collectText(
        node: AccessibilityNodeInfo,
        builder: StringBuilder
    ) {

        node.text?.toString()?.let {
            if (it.isNotBlank()) {
                builder
                    .append(it)
                    .append('\n')
            }
        }

        node.contentDescription?.toString()?.let {
            if (it.isNotBlank()) {
                builder
                    .append(it)
                    .append('\n')
            }
        }

        for (i in 0 until node.childCount) {
            node.getChild(i)?.let {
                collectText(
                    it,
                    builder
                )
            }
        }
    }

    companion object {

        private const val TAG = "TrustOS"
    }
}