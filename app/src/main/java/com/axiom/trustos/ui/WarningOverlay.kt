package com.axiom.trustos.ui

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.core.model.RiskLevel

class WarningOverlay(
    private val context: Context,
    private val onIgnore: (String) -> Unit,
    private val onBlockAndSave: (String) -> Unit,
) {

    private val windowManager =
        context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

    private val mainHandler =
        Handler(Looper.getMainLooper())

    private var overlayView: View? = null
    private var currentThreatKey: String? = null

    fun show(
        assessment: RiskAssessment,
        threatKey: String,
        alreadySaved: Boolean = false
    ) {
        mainHandler.post {

            android.util.Log.d(
                "TrustOSOverlay",
                "SHOW REQUESTED: $threatKey"
            )

            if (overlayView != null) {
                android.util.Log.d(
                    "TrustOSOverlay",
                    "OVERLAY ALREADY VISIBLE"
                )
                return@post
            }

            currentThreatKey = threatKey

            val container = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(24), dp(22), dp(24), dp(22))
                background = GradientDrawable().apply {
                    setColor(Color.WHITE)
                    cornerRadius = dp(18).toFloat()
                    setStroke(dp(2), Color.RED)
                }
                elevation = dp(12).toFloat()
            }

            val title = TextView(context).apply {
                text = "🛡️ TrustOS"
                textSize = 25f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.BLACK)
            }

            val warning = TextView(context).apply {
                text = "⚠️ Potential Risk Detected"
                textSize = 19f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.RED)
                setPadding(0, dp(14), 0, dp(14))
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
                setPadding(0, dp(8), 0, dp(8))
            }

            val confidencePercent =
                (assessment.confidence * 100).toInt()

            val confidence = TextView(context).apply {
                text = "Confidence: $confidencePercent%"
                textSize = 17f
                setTextColor(Color.DKGRAY)
                setPadding(0, dp(4), 0, dp(18))
            }

            val detailsButton = Button(context).apply {
                text = "View Details"
                setOnClickListener {
                    showDetails(assessment, alreadySaved)
                }
            }

            val ignoreButton = Button(context).apply {
                text = "Ignore"
                setOnClickListener {

                    val key = currentThreatKey

                    android.util.Log.d(
                        "TrustOSOverlay",
                        "IGNORE CLICKED: $key"
                    )

                    if (!key.isNullOrBlank()) {
                        onIgnore(key)
                    }

                    hide()
                }
            }

            container.addView(title)
            container.addView(warning)
            container.addView(score)
            container.addView(level)
            container.addView(confidence)
            container.addView(detailsButton)
            container.addView(ignoreButton)

            addOverlay(container)
        }
    }

    private fun showDetails(
        assessment: RiskAssessment,
        alreadySaved: Boolean
    ) {
        mainHandler.post {

            val container = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(24), dp(22), dp(24), dp(22))
                background = GradientDrawable().apply {
                    setColor(Color.WHITE)
                    cornerRadius = dp(18).toFloat()
                    setStroke(dp(2), Color.DKGRAY)
                }
                elevation = dp(12).toFloat()
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

                    append(
                        "Risk Score: ${assessment.score}/100\n"
                    )

                    append(
                        "Risk Level: ${assessment.level}\n"
                    )

                    append(
                        "Confidence: $confidencePercent%\n\n"
                    )

                    append(
                        "TrustOS detected:\n\n"
                    )

                    if (assessment.reasons.isEmpty()) {

                        append(
                            "No specific reasons available."
                        )

                    } else {

                        assessment.reasons.forEach { reason ->
                            append("⚠ $reason\n")
                        }
                    }

                    if (assessment.isTrending) {
                        append(
                            "\n🌐 NETWORK ALERT: This threat type is trending " +
                                    "across TrustOS users (${assessment.trendReportCount} " +
                                    "recent verified reports).\n"
                        )
                    }
                }

                textSize = 16f
                setTextColor(Color.DKGRAY)
                setPadding(0, dp(18), 0, dp(18))
            }

            val closeButton = Button(context).apply {
                text = "Close"
                setOnClickListener {
                    hide()
                }
            }

            container.addView(title)
            container.addView(explanation)

            if (alreadySaved) {

                val alreadyReportedNote = TextView(context).apply {
                    text = "✔ Already reported to TrustOS network"
                    textSize = 14f
                    setTextColor(Color.DKGRAY)
                    setPadding(0, dp(4), 0, dp(14))
                }

                container.addView(alreadyReportedNote)

            } else {

                val blockAndSaveButton = Button(context).apply {
                    text = "Block & Save"
                    setOnClickListener {

                        val key = currentThreatKey

                        android.util.Log.d(
                            "TrustOSOverlay",
                            "BLOCK & SAVE CLICKED FROM DETAILS: $key"
                        )

                        if (!key.isNullOrBlank()) {
                            onBlockAndSave(key)
                        }

                        hide()
                    }
                }

                container.addView(blockAndSaveButton)
            }

            container.addView(closeButton)

            removeCurrentOverlay()
            addOverlay(container)
        }
    }

    private fun addOverlay(
        view: View
    ) {

        val params = WindowManager.LayoutParams(
            dp(340),
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }

        try {

            windowManager.addView(
                view,
                params
            )

            overlayView = view

            android.util.Log.d(
                "TrustOSOverlay",
                "OVERLAY ADDED SUCCESSFULLY"
            )

        } catch (e: Exception) {

            android.util.Log.e(
                "TrustOSOverlay",
                "OVERLAY FAILED",
                e
            )

            overlayView = null
            currentThreatKey = null
        }
    }

    private fun removeCurrentOverlay() {

        overlayView?.let { view ->

            try {
                windowManager.removeView(view)
            } catch (e: Exception) {
                android.util.Log.e(
                    "TrustOSOverlay",
                    "REMOVE OVERLAY FAILED",
                    e
                )
            }
        }

        overlayView = null
    }

    fun hide() {

        mainHandler.post {

            android.util.Log.d(
                "TrustOSOverlay",
                "HIDE"
            )

            removeCurrentOverlay()
            currentThreatKey = null
        }
    }

    private fun dp(value: Int): Int {
        return (
                value *
                        context.resources.displayMetrics.density
                ).toInt()
    }
}