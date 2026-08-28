package com.axiom.trustos.core.privacy

/**
 * How TrustOS may process content in the current context.
 *
 * This is a data model only; it does not start monitoring or collect content.
 */
enum class PrivacyMode {
    /** Normal security analysis is allowed. */
    SCAN,

    /** Temporarily stop content analysis; the context is privacy-sensitive. */
    PAUSE,

    /** Limited/safe processing only; avoid collecting sensitive content. */
    RESTRICT
}
