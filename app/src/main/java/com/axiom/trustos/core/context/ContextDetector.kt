package com.axiom.trustos.core.context

import com.axiom.trustos.core.privacy.AppContext

class ContextDetector {

    fun classifyPackage(packageName: String): AppContext {
        val normalized = packageName.trim()
        if (normalized.isEmpty()) {
            return AppContext.UNKNOWN
        }
        // Known packages map to a specific context. Any ordinary app that is
        // not explicitly listed is classified as OTHER so that the privacy
        // controller can allow scanning rather than silently skipping it.
        return PACKAGE_TO_CONTEXT[normalized] ?: AppContext.OTHER
    }

    companion object {
        private val PACKAGE_TO_CONTEXT: Map<String, AppContext> = mapOf(
            // Browsers
            "com.android.chrome" to AppContext.BROWSER,
            "org.mozilla.firefox" to AppContext.BROWSER,

            // Messaging
            "com.whatsapp" to AppContext.MESSAGING,
            "org.telegram.messenger" to AppContext.MESSAGING,
            "com.axiom.fakechat" to AppContext.MESSAGING,

            // SMS
            "com.google.android.apps.messaging" to AppContext.SMS,

            // Email
            "com.google.android.gm" to AppContext.EMAIL,

            // Social media
            "com.instagram.android" to AppContext.SOCIAL_MEDIA,
            "com.facebook.katana" to AppContext.SOCIAL_MEDIA,

            // Gallery
            "com.google.android.apps.photos" to AppContext.GALLERY,
            "com.google.android.gallery3d" to AppContext.GALLERY,
            "com.sec.android.gallery3d" to AppContext.GALLERY,
            "com.miui.gallery" to AppContext.GALLERY,

            // Common banking / payment apps
            "com.google.android.apps.nbu.paisa.user" to AppContext.PAYMENT,
            "net.one97.paytm" to AppContext.PAYMENT,
            "com.phonepe.app" to AppContext.PAYMENT,

            // Common banking apps
            "com.sbi.lotusintouch" to AppContext.BANKING,
            "com.csam.icici.bank.imobile" to AppContext.BANKING,
            "com.axis.mobile" to AppContext.BANKING
        )
    }
}
