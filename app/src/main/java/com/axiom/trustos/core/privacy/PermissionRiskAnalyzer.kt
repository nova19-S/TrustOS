package com.axiom.trustos.core.privacy

import android.content.Context
import android.content.pm.PackageManager

/**
 * Lightweight metadata-based risk signal: flags apps whose DECLARED
 * permission combinations are commonly associated with malicious or
 * overly invasive behavior (e.g. an app that wants to read SMS, draw
 * over other apps, AND use Accessibility Service together has little
 * legitimate reason to need all three at once).
 *
 * This is NOT malware/Trojan detection — it does not analyze app code,
 * behavior, or intent. It only reads permission metadata already
 * declared in the app's manifest via PackageManager, and flags
 * combinations worth a user's attention. A real messaging or security
 * app may legitimately need some of these permissions — this is a
 * signal to review, not a verdict.
 */
class PermissionRiskAnalyzer(
    private val context: Context
) {

    private val packageManager = context.packageManager

    fun analyze(packageName: String): PermissionRiskResult {

        val declaredPermissions = getDeclaredPermissions(packageName)

        val findings = mutableListOf<String>()

        val hasAccessibility =
            declaredPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

        val hasOverlay =
            declaredPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")

        val hasSms =
            declaredPermissions.any {
                it == "android.permission.READ_SMS" ||
                        it == "android.permission.RECEIVE_SMS" ||
                        it == "android.permission.SEND_SMS"
            }

        val hasContacts =
            declaredPermissions.contains("android.permission.READ_CONTACTS")

        val hasCallLog =
            declaredPermissions.any {
                it == "android.permission.READ_CALL_LOG" ||
                        it == "android.permission.PROCESS_OUTGOING_CALLS"
            }

        val hasAccessibilityAndOverlay =
            hasAccessibility && hasOverlay

        val hasSmsAndContacts =
            hasSms && hasContacts

        val hasBroadSurveillanceCombo =
            hasAccessibility && hasSms && hasCallLog

        if (hasAccessibilityAndOverlay) {
            findings += "Uses Accessibility Service together with draw-over-other-apps permission"
        }

        if (hasSmsAndContacts) {
            findings += "Can read SMS messages and contacts together"
        }

        if (hasBroadSurveillanceCombo) {
            findings += "Combines Accessibility Service, SMS access, and call log access"
        }

        return PermissionRiskResult(
            findings = findings,
            isNotable = findings.isNotEmpty()
        )
    }

    private fun getDeclaredPermissions(packageName: String): List<String> {
        return try {
            val info = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS
            )
            info.requestedPermissions?.toList() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }
}

data class PermissionRiskResult(
    val findings: List<String>,
    val isNotable: Boolean
)