package com.axiom.trustos

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.axiom.trustos.core.detector.UrlRiskDetector
import com.axiom.trustos.core.engine.TrustEngine
import com.axiom.trustos.core.model.RiskAssessment
import com.axiom.trustos.ui.theme.TrustOSTheme
import kotlin.math.roundToInt
import android.content.Intent
import android.net.Uri
import android.provider.Settings
class MainActivity : ComponentActivity() {

    private var protectionEnabled by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            TrustOSTheme {
                TrustOSDashboard(
                    protectionEnabled = protectionEnabled,
                    onEnableOverlay = {
                            openProtectionSettings()
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        protectionEnabled = isAccessibilityServiceEnabled()
    }

    private fun openOverlayPermissionSettings() {
        if (!Settings.canDrawOverlays(this)) {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            )
            startActivity(intent)
        }
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false

        return enabledServices.contains(
            "${packageName}/com.axiom.trustos.core.TrustAccessibilityService"
        )
    }

    private fun openProtectionSettings() {

        if (!isAccessibilityServiceEnabled()) {

            val intent = Intent(
                Settings.ACTION_ACCESSIBILITY_SETTINGS
            )

            startActivity(intent)

            return
        }

        if (!Settings.canDrawOverlays(this)) {

            openOverlayPermissionSettings()

            return
        }
    }

}

private sealed class UrlScanUiState {
    data object Idle : UrlScanUiState()
    data object BlankInput : UrlScanUiState()
    data class Scanned(val assessment: RiskAssessment) : UrlScanUiState()
}

@Composable
fun TrustOSDashboard(
    protectionEnabled: Boolean,
    onEnableOverlay: () -> Unit
) {
    val trustEngine = remember { TrustEngine() }
    val urlRiskDetector = remember { UrlRiskDetector() }

    var urlInput by remember { mutableStateOf("") }
    var scanState by remember { mutableStateOf<UrlScanUiState>(UrlScanUiState.Idle) }

    Scaffold(
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "🛡️",
                fontSize = 52.sp
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "TrustOS",
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Your intelligent security layer",
                fontSize = 16.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(20.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = if (protectionEnabled) {
                            "🟢 PROTECTION ACTIVE"
                        } else {
                            "🔴 PROTECTION INACTIVE"
                        },
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = if (protectionEnabled) {
                            "TrustOS is monitoring supported screen content."
                        } else {
                            "Enable Screen Protection to activate background monitoring."
                        },
                        textAlign = TextAlign.Center,
                        fontSize = 14.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                label = { Text("Enter a URL to scan") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    if (urlInput.isBlank()) {
                        scanState = UrlScanUiState.BlankInput
                    } else {
                        val detections = urlRiskDetector.analyze(urlInput)
                        scanState = UrlScanUiState.Scanned(
                            assessment = trustEngine.assess(detections)
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = "Scan URL")
            }

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = onEnableOverlay,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = "Enable TrustOS Protection")
            }

            Spacer(modifier = Modifier.height(24.dp))

            when (val currentState = scanState) {
                UrlScanUiState.Idle -> NeutralScanState()
                UrlScanUiState.BlankInput -> MessageCard("Please enter a URL")
                is UrlScanUiState.Scanned -> ScanResultState(
                    assessment = currentState.assessment
                )
            }
        }
    }
}

@Composable
private fun NeutralScanState() {
    MessageCard("No URL scanned yet")
}

@Composable
private fun MessageCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = message,
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun ScanResultState(assessment: RiskAssessment) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = "Risk Score: ${assessment.score} / 100",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "Risk Level: ${assessment.level.name}",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Confidence: ${(assessment.confidence * 100).roundToInt()}%",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = "Why?",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(12.dp))
            if (assessment.reasons.isEmpty()) {
                Text(
                    text = "No suspicious indicators detected",
                    fontSize = 16.sp
                )
            } else {
                assessment.reasons.forEach { reason ->
                    Text(
                        text = "• $reason",
                        fontSize = 16.sp,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }
            }
        }
    }
}
