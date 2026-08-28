package com.axiom.trustos.core.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyControllerTest {

    private val controller = PrivacyController()

    @Test
    fun evaluate_browser_isScan() {
        assertMode(AppContext.BROWSER, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_messaging_isScan() {
        assertMode(AppContext.MESSAGING, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_sms_isScan() {
        assertMode(AppContext.SMS, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_email_isScan() {
        assertMode(AppContext.EMAIL, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_socialMedia_isScan() {
        assertMode(AppContext.SOCIAL_MEDIA, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_gallery_isPause() {
        assertMode(AppContext.GALLERY, PrivacyMode.PAUSE)
    }

    @Test
    fun evaluate_payment_isRestrict() {
        assertMode(AppContext.PAYMENT, PrivacyMode.RESTRICT)
    }

    @Test
    fun evaluate_banking_isRestrict() {
        assertMode(AppContext.BANKING, PrivacyMode.RESTRICT)
    }

    @Test
    fun evaluate_passwordEntry_isRestrict() {
        assertMode(AppContext.PASSWORD_ENTRY, PrivacyMode.RESTRICT)
    }

    @Test
    fun evaluate_unknown_isPause() {
        assertMode(AppContext.UNKNOWN, PrivacyMode.PAUSE)
    }

    @Test
    fun evaluate_other_isScan() {
        assertMode(AppContext.OTHER, PrivacyMode.SCAN)
    }

    @Test
    fun evaluate_everyContext_hasNonEmptyReason() {
        enumValues<AppContext>().forEach { context ->
            val decision = controller.evaluate(context)
            assertTrue(
                "Expected a non-empty reason for $context",
                decision.reason.isNotBlank()
            )
        }
    }

    private fun assertMode(context: AppContext, expectedMode: PrivacyMode) {
        val decision = controller.evaluate(context)
        assertEquals(expectedMode, decision.mode)
        assertTrue(decision.reason.isNotBlank())
    }
}
