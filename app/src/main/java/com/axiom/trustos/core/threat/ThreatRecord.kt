package com.axiom.trustos.core.threat

data class ThreatRecord(
    val threatKey: String,
    val packageName: String,
    val indicator: String?,
    val threatType: String,
    val riskScore: Int,
    val confidence: Double,
    val reasons: List<String>,
    val createdAt: Long
)

