package com.axiom.trustos.core.detector

import com.axiom.trustos.core.model.DetectionResult
import com.google.mlkit.nl.entityextraction.Entity
import com.google.mlkit.nl.entityextraction.EntityExtraction
import com.google.mlkit.nl.entityextraction.EntityExtractionParams
import com.google.mlkit.nl.entityextraction.EntityExtractor
import com.google.mlkit.nl.entityextraction.EntityExtractorOptions

/**
 * On-device NLP-based detector using ML Kit's Entity Extraction API.
 * This is a SEPARATE, additive signal alongside TextRiskDetector's
 * keyword/pattern matching — it does not replace it. The goal is to
 * catch scam patterns that survive rephrasing (e.g. "verify ur account
 * immediatly") by recognizing structural entities (money, phone numbers,
 * URLs) rather than exact phrases.
 *
 * Entity extraction is asynchronous and requires a one-time on-device
 * model download before first use.
 */
class NlpRiskDetector {

    private val entityExtractor: EntityExtractor =
        EntityExtraction.getClient(
            EntityExtractorOptions.Builder(EntityExtractorOptions.ENGLISH).build()
        )

    private var modelReady = false

    /**
     * Call this once, early (e.g. when the service starts), so the model
     * is downloaded and ready before real-time detection needs it.
     */
    fun prepareModel(onReady: () -> Unit, onFailure: (Exception) -> Unit) {
        entityExtractor.downloadModelIfNeeded()
            .addOnSuccessListener {
                modelReady = true
                onReady()
            }
            .addOnFailureListener { exception ->
                modelReady = false
                onFailure(exception)
            }
    }

    /**
     * Analyzes text for NLP-detected entity patterns. Calls onResult with
     * an empty list if the model isn't ready yet or extraction fails —
     * this is intentionally "best effort," never blocking the rest of
     * the detection pipeline.
     */
    fun analyze(text: String, onResult: (List<DetectionResult>) -> Unit) {

        if (!modelReady) {
            onResult(emptyList())
            return
        }

        val params = EntityExtractionParams.Builder(text).build()

        entityExtractor.annotate(params)
            .addOnSuccessListener { entityAnnotations ->

                val entityTypes = entityAnnotations
                    .flatMap { annotation -> annotation.entities }
                    .map { entity -> entity.type }
                    .toSet()

                val findings = mutableListOf<DetectionResult>()

                val hasMoney = entityTypes.contains(Entity.TYPE_MONEY)
                val hasUrl = entityTypes.contains(Entity.TYPE_URL)
                val hasPhone = entityTypes.contains(Entity.TYPE_PHONE)

                if (hasMoney && hasUrl) {
                    findings += DetectionResult(
                        detectorName = "NLP Detector",
                        reason = "NLP: Financial entity combined with URL in message",
                        riskContribution = 75,
                        confidence = 0.75
                    )
                }

                if (hasPhone && text.length < 200) {
                    findings += DetectionResult(
                        detectorName = "NLP Detector",
                        reason = "NLP: Phone number in a short, urgent-style message",
                        riskContribution = 15,
                        confidence = 0.5
                    )
                }

                onResult(findings)
            }
            .addOnFailureListener {
                onResult(emptyList())
            }
    }

    fun close() {
        entityExtractor.close()
    }
}