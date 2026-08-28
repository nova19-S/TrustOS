package com.axiom.trustos.core.privacy

/**
 * Result of a privacy-mode choice.
 *
 * @param mode Selected [PrivacyMode].
 * @param reason Human-readable explanation for why this mode was selected.
 */
data class PrivacyDecision(
    val mode: PrivacyMode,
    val reason: String
)
