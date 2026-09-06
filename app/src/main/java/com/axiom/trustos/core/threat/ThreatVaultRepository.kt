package com.axiom.trustos.core.threat

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class ThreatVaultRepository(
    context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    fun saveThreat(record: ThreatRecord) {

        val threats = getThreats().toMutableList()

        threats.removeAll {
            it.threatKey == record.threatKey
        }

        threats.add(record)

        val jsonArray = JSONArray()

        threats.forEach { threat ->

            val jsonObject = JSONObject().apply {
                put("threatKey", threat.threatKey)
                put("packageName", threat.packageName)
                put("indicator", threat.indicator)
                put("threatType", threat.threatType)
                put("riskScore", threat.riskScore)
                put("confidence", threat.confidence)
                put("createdAt", threat.createdAt)

                val reasonsArray = JSONArray()

                threat.reasons.forEach { reason ->
                    reasonsArray.put(reason)
                }

                put("reasons", reasonsArray)
            }

            jsonArray.put(jsonObject)
        }

        preferences.edit()
            .putString(
                THREATS_KEY,
                jsonArray.toString()
            )
            .apply()
    }

    fun getThreats(): List<ThreatRecord> {

        val storedData =
            preferences.getString(
                THREATS_KEY,
                null
            ) ?: return emptyList()

        return try {

            val jsonArray =
                JSONArray(storedData)

            val threats =
                mutableListOf<ThreatRecord>()

            for (i in 0 until jsonArray.length()) {

                val jsonObject =
                    jsonArray.getJSONObject(i)

                val reasonsArray =
                    jsonObject.optJSONArray("reasons")

                val reasons =
                    mutableListOf<String>()

                if (reasonsArray != null) {
                    for (j in 0 until reasonsArray.length()) {
                        reasons.add(
                            reasonsArray.getString(j)
                        )
                    }
                }

                threats.add(
                    ThreatRecord(
                        threatKey =
                            jsonObject.getString("threatKey"),

                        packageName =
                            jsonObject.getString("packageName"),

                        indicator =
                            jsonObject.optString(
                                "indicator",
                                null
                            ),

                        threatType =
                            jsonObject.getString("threatType"),

                        riskScore =
                            jsonObject.getInt("riskScore"),

                        confidence =
                            jsonObject.getDouble("confidence"),

                        reasons = reasons,

                        createdAt =
                            jsonObject.getLong("createdAt")
                    )
                )
            }

            threats

        } catch (_: Exception) {
            emptyList()
        }
    }

    fun containsThreat(threatKey: String): Boolean {
        return getThreats().any {
            it.threatKey == threatKey
        }
    }

    fun findThreat(threatKey: String): ThreatRecord? {
        return getThreats().firstOrNull {
            it.threatKey == threatKey
        }
    }

    companion object {

        private const val PREFS_NAME =
            "trustos_threat_vault"

        private const val THREATS_KEY =
            "stored_threats"
    }
}

