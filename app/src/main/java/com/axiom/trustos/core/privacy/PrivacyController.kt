package com.axiom.trustos.core.privacy

import android.content.Context

class PrivacyController(
    context: Context
) {

    private val settingsRepository =
        PrivacySettingsRepository(context)

    fun evaluate(
        context: AppContext,
        packageName: String
    ): PrivacyDecision {

        val profile =
            settingsRepository.getProfile()

        if (
            profile == PrivacyProfile.ENHANCED &&
            settingsRepository
                .getAdditionalApps()
                .contains(packageName)
        ) {
            return PrivacyDecision(
                mode = PrivacyMode.PAUSE,
                reason = "Enhanced Privacy: user-selected app"
            )
        }

        return when (context) {

            AppContext.BROWSER ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "Browser context"
                )

            AppContext.MESSAGING ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "Messaging context"
                )

            AppContext.SMS ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "SMS context"
                )

            AppContext.EMAIL ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "Email context"
                )

            AppContext.SOCIAL_MEDIA ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "Social media context"
                )

            AppContext.GALLERY ->
                PrivacyDecision(
                    mode = PrivacyMode.PAUSE,
                    reason = "Gallery context is privacy-sensitive"
                )

            AppContext.PAYMENT ->
                PrivacyDecision(
                    mode = PrivacyMode.RESTRICT,
                    reason = "Payment context is sensitive"
                )

            AppContext.BANKING ->
                PrivacyDecision(
                    mode = PrivacyMode.RESTRICT,
                    reason = "Banking context is sensitive"
                )

            AppContext.PASSWORD_ENTRY ->
                PrivacyDecision(
                    mode = PrivacyMode.RESTRICT,
                    reason = "Password entry is highly sensitive"
                )

            AppContext.UNKNOWN ->
                PrivacyDecision(
                    mode = PrivacyMode.PAUSE,
                    reason = "Unknown context, privacy-first default"
                )

            AppContext.OTHER ->
                PrivacyDecision(
                    mode = PrivacyMode.SCAN,
                    reason = "General app context — scanning permitted"
                )
        }
    }
}