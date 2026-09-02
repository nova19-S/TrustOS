package com.axiom.trustos.core.privacy

import android.content.Context

class PrivacySettingsRepository(
    context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    fun getProfile(): PrivacyProfile {
        val savedProfile =
            preferences.getString(
                PROFILE_KEY,
                PrivacyProfile.STANDARD.name
            )

        return try {
            PrivacyProfile.valueOf(savedProfile ?: PrivacyProfile.STANDARD.name)
        } catch (_: IllegalArgumentException) {
            PrivacyProfile.STANDARD
        }
    }

    fun setProfile(profile: PrivacyProfile) {
        preferences.edit()
            .putString(
                PROFILE_KEY,
                profile.name
            )
            .apply()
    }

    fun getAdditionalApps(): Set<String> {
        return preferences.getStringSet(
            ADDITIONAL_APPS_KEY,
            emptySet()
        )?.toSet() ?: emptySet()
    }

    fun setAdditionalApps(packageNames: Set<String>) {
        preferences.edit()
            .putStringSet(
                ADDITIONAL_APPS_KEY,
                packageNames.toSet()
            )
            .apply()
    }

    companion object {
        private const val PREFS_NAME =
            "trustos_privacy_settings"

        private const val PROFILE_KEY =
            "privacy_profile"

        private const val ADDITIONAL_APPS_KEY =
            "additional_apps"
    }
}