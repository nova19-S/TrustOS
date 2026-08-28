package com.axiom.trustos.core.context

import com.axiom.trustos.core.privacy.AppContext
import org.junit.Assert.assertEquals
import org.junit.Test

class ContextDetectorTest {

    private val detector = ContextDetector()

    @Test
    fun classifyPackage_chrome_isBrowser() {
        assertEquals(
            AppContext.BROWSER,
            detector.classifyPackage("com.android.chrome")
        )
    }

    @Test
    fun classifyPackage_firefox_isBrowser() {
        assertEquals(
            AppContext.BROWSER,
            detector.classifyPackage("org.mozilla.firefox")
        )
    }

    @Test
    fun classifyPackage_whatsapp_isMessaging() {
        assertEquals(
            AppContext.MESSAGING,
            detector.classifyPackage("com.whatsapp")
        )
    }

    @Test
    fun classifyPackage_telegram_isMessaging() {
        assertEquals(
            AppContext.MESSAGING,
            detector.classifyPackage("org.telegram.messenger")
        )
    }

    @Test
    fun classifyPackage_googleMessages_isSms() {
        assertEquals(
            AppContext.SMS,
            detector.classifyPackage("com.google.android.apps.messaging")
        )
    }

    @Test
    fun classifyPackage_gmail_isEmail() {
        assertEquals(
            AppContext.EMAIL,
            detector.classifyPackage("com.google.android.gm")
        )
    }

    @Test
    fun classifyPackage_instagram_isSocialMedia() {
        assertEquals(
            AppContext.SOCIAL_MEDIA,
            detector.classifyPackage("com.instagram.android")
        )
    }

    @Test
    fun classifyPackage_facebook_isSocialMedia() {
        assertEquals(
            AppContext.SOCIAL_MEDIA,
            detector.classifyPackage("com.facebook.katana")
        )
    }

    @Test
    fun classifyPackage_unknownPackage_isOther() {
        assertEquals(
            AppContext.OTHER,
            detector.classifyPackage("unknown.package.example")
        )
    }

    @Test
    fun classifyPackage_blankPackage_isUnknown() {
        assertEquals(AppContext.UNKNOWN, detector.classifyPackage(""))
        assertEquals(AppContext.UNKNOWN, detector.classifyPackage("   "))
    }
}
