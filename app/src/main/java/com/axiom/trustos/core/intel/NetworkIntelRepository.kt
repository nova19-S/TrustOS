package com.axiom.trustos.core.intel

import android.content.Context
import org.json.JSONObject
import kotlin.math.roundToInt

/**
 * Simulates a decentralized threat-intelligence network.
 *
 * In the real architecture, this is where a fingerprint would be checked
 * against a blockchain/shared network to see if the category is currently
 * trending. For the prototype, this is a local, self-contained stand-in:
 * every time a threat category is reported, we record it with a trust
 * weight (so not every report counts equally — see ReporterTrustLevel),
 * with older reports decaying in influence over time. Categories with a
 * lot of recent, trustworthy reports are considered "trending" and get a
 * score boost.
 *
 * This class is intentionally the ONLY place that knows this is fake —
 * everything that calls it (TrustEngine, etc.) just sees a normal
 * "check fingerprint, get intel back" API, so replacing this with a real
 * network call later requires no changes anywhere else.
 */
class NetworkIntelRepository(
    context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    /**
     * Call this whenever a threat is detected and user-confirmed —
     * this is the "report" step (equivalent to publishing a fingerprint
     * to the network). The report's influence is scaled by how
     * trustworthy the reporter is considered.
     */
    fun reportThreat(
        category: ThreatCategory,
        trustLevel: ReporterTrustLevel = ReporterTrustLevel.ESTABLISHED
    ) {
        val counts = loadCounts()

        val existing = counts[category.name] ?: CategoryWeight(0.0, System.currentTimeMillis())
        val decayedWeight = decayedValue(existing)

        counts[category.name] = CategoryWeight(
            weight = decayedWeight + trustLevel.weight,
            lastUpdatedMs = System.currentTimeMillis()
        )

        saveCounts(counts)
    }

    /**
     * Call this to check whether a category is currently trending, and
     * how much that should boost the risk score.
     */
    fun checkIntel(category: ThreatCategory): NetworkIntelResult {
        val counts = loadCounts()
        val existing = counts[category.name]

        if (existing == null) {
            return NetworkIntelResult(
                isTrending = false,
                trendBoost = 0,
                reportCount = 0
            )
        }

        val currentWeight = decayedValue(existing)

        val isTrending = currentWeight >= TRENDING_THRESHOLD

        val trendBoost = if (isTrending) {
            // More weighted reports = more boost, capped so it can't
            // dominate the score.
            (currentWeight * BOOST_PER_REPORT)
                .roundToInt()
                .coerceAtMost(MAX_TREND_BOOST)
        } else {
            0
        }

        return NetworkIntelResult(
            isTrending = isTrending,
            trendBoost = trendBoost,
            // Shown in the UI for transparency — rounded to a whole
            // number since "2.7 reports" would be a confusing thing
            // to show a user.
            reportCount = currentWeight.roundToInt()
        )
    }

    /**
     * DEMO/TESTING ONLY. Simulates multiple independent devices reporting
     * the same category, so trending behavior can be demonstrated without
     * needing real separate devices. This is clearly separated from
     * reportThreat() (the real single-report path) so it's obvious in
     * code review that this is a stand-in, not production logic.
     */
    fun simulateExternalReports(
        category: ThreatCategory,
        count: Int,
        trustLevel: ReporterTrustLevel = ReporterTrustLevel.ESTABLISHED
    ) {
        repeat(count) {
            reportThreat(category, trustLevel)
        }
    }

    /**
     * DEMO/TESTING ONLY. Clears all stored report weights so trending
     * behavior can be demonstrated from a clean, predictable state.
     */
    fun resetAll() {
        preferences.edit().clear().apply()
    }

    /**
     * Applies exponential-ish decay based on how long ago the category
     * was last reported, so old spikes fade out instead of accumulating
     * forever.
     */
    private fun decayedValue(entry: CategoryWeight): Double {
        val elapsedMs = System.currentTimeMillis() - entry.lastUpdatedMs
        val elapsedHalfLives = elapsedMs.toDouble() / DECAY_HALF_LIFE_MS

        if (elapsedHalfLives <= 0.0) {
            return entry.weight
        }

        return entry.weight * Math.pow(0.5, elapsedHalfLives)
    }

    private fun loadCounts(): MutableMap<String, CategoryWeight> {
        val raw = preferences.getString(COUNTS_KEY, null) ?: return mutableMapOf()

        return try {
            val json = JSONObject(raw)
            val result = mutableMapOf<String, CategoryWeight>()

            json.keys().forEach { key ->
                val entry = json.getJSONObject(key)
                result[key] = CategoryWeight(
                    weight = entry.getDouble("weight"),
                    lastUpdatedMs = entry.getLong("lastUpdatedMs")
                )
            }

            result
        } catch (_: Exception) {
            mutableMapOf()
        }
    }

    private fun saveCounts(counts: Map<String, CategoryWeight>) {
        val json = JSONObject()

        counts.forEach { (key, value) ->
            val entry = JSONObject()
            entry.put("weight", value.weight)
            entry.put("lastUpdatedMs", value.lastUpdatedMs)
            json.put(key, entry)
        }

        preferences.edit()
            .putString(COUNTS_KEY, json.toString())
            .apply()
    }

    private data class CategoryWeight(
        val weight: Double,
        val lastUpdatedMs: Long
    )

    companion object {
        private const val PREFS_NAME = "trustos_network_intel"
        private const val COUNTS_KEY = "category_counts"

        // How much decayed weight counts as "trending".
        private const val TRENDING_THRESHOLD = 3.0

        // Points added to risk score per unit of decayed weight, once trending.
        private const val BOOST_PER_REPORT = 4

        // Hard ceiling so network trend can never dominate the local score.
        private const val MAX_TREND_BOOST = 20

        // Reports lose half their weight every 72 hours (3 days),
        // matched to typical multi-day scam campaign duration.
        private const val DECAY_HALF_LIFE_MS = 72 * 60 * 60 * 1000L
    }
}