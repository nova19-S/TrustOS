package com.axiom.trustos.core.privacy

data class PrivacyApp(
    val packageName: String,
    val appName: String,
    val permissionRisk: PermissionRiskResult = PermissionRiskResult(
        findings = emptyList(),
        isNotable = false
    )
)