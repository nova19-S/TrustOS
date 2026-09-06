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
 * every time a threat category is detected, we record a "report" for it,
 * with older reports decaying in influence over time. Categories with a lot
 * of recent reports are considered "trending" and get a score boost.
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
     * Call this whenever a threat is detected locally, BEFORE checking
     * trend status — this is the "report" step (equivalent to publishing
     * a fingerprint to the network).
     */
    fun reportThreat(category: ThreatCategory) {
        val counts = loadCounts()

        val existing = counts[category.name] ?: CategoryCount(0, System.currentTimeMillis())
        val decayedCount = decayedValue(existing)

        counts[category.name] = CategoryCount(
            count = decayedCount + 1,
            lastUpdatedMs = System.currentTimeMillis()
        )

        saveCounts(counts)
    }

    /**
     * DEMO/TESTING ONLY. Clears all stored report counts so trending
     * behavior can be demonstrated from a clean, predictable state.
     */
    fun resetAll() {
        preferences.edit().clear().apply()
    }

    /**
     * DEMO/TESTING ONLY. Simulates multiple independent devices reporting
     * the same category, so trending behavior can be demonstrated without
     * needing real separate devices. This is clearly separated from
     * reportThreat() (the real single-report path) so it's obvious in
     * code review that this is a stand-in, not production logic.
     */
    fun simulateExternalReports(category: ThreatCategory, count: Int) {
        repeat(count) {
            reportThreat(category)
        }
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

        val currentCount = decayedValue(existing)

        val isTrending = currentCount >= TRENDING_THRESHOLD

        val trendBoost = if (isTrending) {
            // More reports = more boost, capped so it can't dominate the score.
            (currentCount * BOOST_PER_REPORT).coerceAtMost(MAX_TREND_BOOST)
        } else {
            0
        }

        return NetworkIntelResult(
            isTrending = isTrending,
            trendBoost = trendBoost,
            reportCount = currentCount
        )
    }

    /**
     * Applies exponential-ish decay based on how long ago the category
     * was last reported, so old spikes fade out instead of accumulating
     * forever.
     */
    private fun decayedValue(entry: CategoryCount): Int {
        val elapsedMs = System.currentTimeMillis() - entry.lastUpdatedMs
        val elapsedHalfLives = elapsedMs.toDouble() / DECAY_HALF_LIFE_MS

        if (elapsedHalfLives <= 0.0) {
            return entry.count
        }

        val decayed = entry.count * Math.pow(0.5, elapsedHalfLives)
        return decayed.roundToInt()
    }

    private fun loadCounts(): MutableMap<String, CategoryCount> {
        val raw = preferences.getString(COUNTS_KEY, null) ?: return mutableMapOf()

        return try {
            val json = JSONObject(raw)
            val result = mutableMapOf<String, CategoryCount>()

            json.keys().forEach { key ->
                val entry = json.getJSONObject(key)
                result[key] = CategoryCount(
                    count = entry.getInt("count"),
                    lastUpdatedMs = entry.getLong("lastUpdatedMs")
                )
            }

            result
        } catch (_: Exception) {
            mutableMapOf()
        }
    }

    private fun saveCounts(counts: Map<String, CategoryCount>) {
        val json = JSONObject()

        counts.forEach { (key, value) ->
            val entry = JSONObject()
            entry.put("count", value.count)
            entry.put("lastUpdatedMs", value.lastUpdatedMs)
            json.put(key, entry)
        }

        preferences.edit()
            .putString(COUNTS_KEY, json.toString())
            .apply()
    }

    private data class CategoryCount(
        val count: Int,
        val lastUpdatedMs: Long
    )

    companion object {
        private const val PREFS_NAME = "trustos_network_intel"
        private const val COUNTS_KEY = "category_counts"

        // How many recent reports (after decay) count as "trending".
        private const val TRENDING_THRESHOLD = 3

        // Points added to risk score per decayed report, once trending.
        private const val BOOST_PER_REPORT = 4

        // Hard ceiling so network trend can never dominate the local score.
        private const val MAX_TREND_BOOST = 20

        // Reports lose half their weight every 6 hours.
        private const val DECAY_HALF_LIFE_MS = 6 * 60 * 60 * 1000L
    }
}