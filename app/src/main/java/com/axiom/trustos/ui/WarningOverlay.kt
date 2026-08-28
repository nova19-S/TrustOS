package com.axiom.trustos.ui

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.model.RiskLevel

class WarningOverlay(
    private val context: Context
) {

    private val windowManager =
        context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

    private var overlayView: View? = null

    fun show(assessment: RiskAssessment) {

        if (overlayView != null) {
            return
        }

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 40, 50, 40)
            setBackgroundColor(Color.WHITE)
        }

        val title = TextView(context).apply {
            text = "🛡️ TrustOS"
            textSize = 24f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.BLACK)
        }

        val warning = TextView(context).apply {
            text = "Potential Risk Detected"
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.RED)
            setPadding(0, 20, 0, 20)
        }

        val score = TextView(context).apply {
            text = "Risk Score: ${assessment.score}/100"
            textSize = 18f
            setTextColor(Color.DKGRAY)
        }

        val level = TextView(context).apply {
            text = "Risk Level: ${assessment.level}"
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setTextColor(
                when (assessment.level) {
                    RiskLevel.CRITICAL -> Color.RED
                    RiskLevel.HIGH -> Color.rgb(220, 120, 0)
                    else -> Color.DKGRAY
                }
            )
            setPadding(0, 10, 0, 10)
        }

        val confidencePercent =
            (assessment.confidence * 100).toInt()

        val confidence = TextView(context).apply {
            text = "Confidence: $confidencePercent%"
            textSize = 17f
            setTextColor(Color.DKGRAY)
            setPadding(0, 5, 0, 15)
        }

        val reasons = TextView(context).apply {
            text = if (assessment.reasons.isEmpty()) {
                "⚠ Suspicious activity detected."
            } else {
                assessment.reasons.joinToString(
                    separator = "\n"
                ) { reason ->
                    "⚠ $reason"
                }
            }

            textSize = 16f
            setTextColor(Color.DKGRAY)
            setPadding(0, 10, 0, 20)
        }

        val detailsButton = Button(context).apply {
            text = "View Details"

            setOnClickListener {
                showDetails(assessment)
            }
        }

        val closeButton = Button(context).apply {
            text = "Ignore"

            setOnClickListener {
                hide()
            }
        }

        container.addView(title)
        container.addView(warning)
        container.addView(score)
        container.addView(level)
        container.addView(confidence)
        container.addView(reasons)
        container.addView(detailsButton)
        container.addView(closeButton)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }

        windowManager.addView(container, params)

        overlayView = container
    }

    private fun showDetails(assessment: RiskAssessment) {

        val detailsContainer = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 40, 50, 40)
            setBackgroundColor(Color.WHITE)
        }

        val title = TextView(context).apply {
            text = "🛡️ Why TrustOS warned you"
            textSize = 22f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.BLACK)
        }

        val confidencePercent =
            (assessment.confidence * 100).toInt()

        val explanation = TextView(context).apply {
            text = buildString {
                append("Risk Score: ${assessment.score}/100\n")
                append("Risk Level: ${assessment.level}\n")
                append("Confidence: $confidencePercent%\n\n")
                append("TrustOS detected:\n\n")

                if (assessment.reasons.isEmpty()) {
                    append("No specific reasons available.")
                } else {
                    assessment.reasons.forEach {
                        append("⚠ $it\n")
                    }
                }
            }

            textSize = 16f
            setTextColor(Color.DKGRAY)
            setPadding(0, 20, 0, 20)
        }

        val backButton = Button(context).apply {
            text = "Close"

            setOnClickListener {
                hide()
            }
        }

        detailsContainer.addView(title)
        detailsContainer.addView(explanation)
        detailsContainer.addView(backButton)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }

        overlayView?.let {
            windowManager.removeView(it)
        }

        windowManager.addView(detailsContainer, params)

        overlayView = detailsContainer
    }

    fun hide() {

        overlayView?.let {
            windowManager.removeView(it)
        }

        overlayView = null
    }
}