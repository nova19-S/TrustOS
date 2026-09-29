package com.axiom.trustos

import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.History
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.foundation.combinedClickable
import androidx.compose.material3.Checkbox
import androidx.compose.ui.platform.LocalContext
import com.axiom.trustos.core.privacy.InstalledAppsProvider
import com.axiom.trustos.core.privacy.PrivacyProfile
import com.axiom.trustos.core.privacy.PrivacySettingsRepository
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
    private var showPrivacySettings by mutableStateOf(false)
    private var privacyProfile by mutableStateOf(PrivacyProfile.STANDARD)

    private var showThreatHistory by mutableStateOf(false)

    private lateinit var privacySettingsRepository: PrivacySettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)

        privacySettingsRepository =
            PrivacySettingsRepository(applicationContext)

        privacyProfile =
            privacySettingsRepository.getProfile()

        enableEdgeToEdge()

        setContent {
            TrustOSTheme {

                if (showPrivacySettings) {

                    PrivacySettingsScreen(
                        currentProfile = privacyProfile,
                        onProfileSelected = { profile ->
                            privacyProfile = profile

                            privacySettingsRepository
                                .setProfile(profile)
                        },
                        onBack = {
                            showPrivacySettings = false
                        }
                    )

                } else if (showThreatHistory) {

                    ThreatHistoryScreen(
                        onBack = {
                            showThreatHistory = false
                        }
                    )

                } else {

                    TrustOSDashboard(
                        protectionEnabled = protectionEnabled,
                        onEnableOverlay = {
                            openProtectionSettings()
                        },
                        onOpenPrivacySettings = {
                            showPrivacySettings = true
                        },
                        onOpenThreatHistory = {
                            showThreatHistory = true
                        }
                    )
                }
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
private fun GradientActionButton(
    text: String,
    leadingIcon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    val gradient = androidx.compose.ui.graphics.Brush.horizontalGradient(
        colors = listOf(
            androidx.compose.ui.graphics.Color(0xFF1E3A8A),
            androidx.compose.ui.graphics.Color(0xFF0EA5A4)
        )
    )

    androidx.compose.foundation.layout.Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .background(gradient)
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 16.dp)
    ) {
        androidx.compose.foundation.layout.Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            androidx.compose.material3.Icon(
                imageVector = leadingIcon,
                contentDescription = null,
                tint = androidx.compose.ui.graphics.Color.White,
                modifier = Modifier.size(20.dp)
            )

            Spacer(modifier = Modifier.width(12.dp))

            Text(
                text = text,
                color = androidx.compose.ui.graphics.Color.White,
                fontWeight = FontWeight.SemiBold,
                fontSize = 16.sp,
                modifier = Modifier.weight(1f)
            )

            androidx.compose.material3.Icon(
                imageVector = androidx.compose.material.icons.Icons.Default.ArrowForward,
                contentDescription = null,
                tint = androidx.compose.ui.graphics.Color.White,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
fun TrustOSDashboard(
    protectionEnabled: Boolean,
    onEnableOverlay: () -> Unit,
    onOpenPrivacySettings: () -> Unit,
    onOpenThreatHistory: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val networkIntelRepository = remember {
        com.axiom.trustos.core.intel.NetworkIntelRepository(context.applicationContext)
    }
    val threatVaultRepository = remember {
        com.axiom.trustos.core.threat.ThreatVaultRepository(context.applicationContext)
    }
    val trustEngine = remember { TrustEngine(networkIntelRepository = networkIntelRepository) }
    val urlRiskDetector = remember { UrlRiskDetector() }

    var urlInput by remember { mutableStateOf("") }
    var scanState by remember { mutableStateOf<UrlScanUiState>(UrlScanUiState.Idle) }
    var showDemoControls by remember { mutableStateOf(false) }

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

            androidx.compose.foundation.Image(
                painter = androidx.compose.ui.res.painterResource(id = R.mipmap.ic_launcher_foreground),
                contentDescription = "TrustOS Logo",
                modifier = Modifier.size(90.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "TrustOS",
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.combinedClickable(
                    onClick = {},
                    onLongClick = { showDemoControls = !showDemoControls }
                )
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
                leadingIcon = {
                    androidx.compose.material3.Icon(
                        imageVector = androidx.compose.material.icons.Icons.Default.Link,
                        contentDescription = null
                    )
                },
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            GradientActionButton(
                text = "Scan URL",
                leadingIcon = androidx.compose.material.icons.Icons.Default.Link,
                onClick = {
                    if (urlInput.isBlank()) {
                        scanState = UrlScanUiState.BlankInput
                    } else {
                        val detections = urlRiskDetector.analyze(urlInput)
                        scanState = UrlScanUiState.Scanned(
                            assessment = trustEngine.assess(detections)
                        )
                    }
                }
            )

            Spacer(modifier = Modifier.height(12.dp))

            GradientActionButton(
                text = "Enable TrustOS Protection",
                leadingIcon = androidx.compose.material.icons.Icons.Default.Shield,
                onClick = onEnableOverlay
            )

            Spacer(modifier = Modifier.height(12.dp))

            GradientActionButton(
                text = "Privacy Settings",
                leadingIcon = androidx.compose.material.icons.Icons.Default.Settings,
                onClick = onOpenPrivacySettings
            )

            Spacer(modifier = Modifier.height(12.dp))

            GradientActionButton(
                text = "Threat History",
                leadingIcon = androidx.compose.material.icons.Icons.Default.History,
                onClick = onOpenThreatHistory
            )

            if (showDemoControls) {

                Spacer(modifier = Modifier.height(20.dp))

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = androidx.compose.material3.CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp)
                    ) {

                        Text(
                            text = "🛠 Developer / Demo Tools",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        val lastSeenCategory = remember(protectionEnabled) {
                            networkIntelRepository.getLastSeenCategory()
                        }

                        androidx.compose.material3.OutlinedButton(
                            onClick = {
                                val category =
                                    lastSeenCategory
                                        ?: com.axiom.trustos.core.intel.ThreatCategory.GENERIC_SUSPICIOUS

                                networkIntelRepository.simulateExternalReports(
                                    category = category,
                                    count = 3
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = if (lastSeenCategory != null) {
                                    "Simulate 3 Reports for Last Detected Threat"
                                } else {
                                    "Simulate 3 Reports (no threat detected yet)"
                                },
                                fontSize = 13.sp
                            )
                        }

                        if (lastSeenCategory != null) {

                            Spacer(modifier = Modifier.height(6.dp))

                            Text(
                                text = "Will target: ${lastSeenCategory.name}",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(start = 4.dp)
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        androidx.compose.material3.OutlinedButton(
                            onClick = {
                                networkIntelRepository.resetAll()
                                threatVaultRepository.clearAll()
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(text = "Reset Network Data", fontSize = 13.sp)
                        }
                    }
                }
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
private fun ThreatHistoryScreen(
    onBack: () -> Unit
) {

    val context = LocalContext.current

    val threatVaultRepository = remember {
        com.axiom.trustos.core.threat.ThreatVaultRepository(context.applicationContext)
    }

    val threats = remember {
        threatVaultRepository.getThreats().sortedByDescending { it.createdAt }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
        ) {

            Text(
                text = "Threat History",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "${threats.size} confirmed threat(s) blocked and reported",
                fontSize = 15.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(20.dp))

            if (threats.isEmpty()) {

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
                            text = "No threats blocked yet",
                            fontSize = 16.sp
                        )
                    }
                }

            } else {

                threats.forEach { threat ->

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 12.dp),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {

                            Text(
                                text = threat.threatType.replace("_", " "),
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = "From: ${threat.packageName}",
                                fontSize = 13.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            if (!threat.indicator.isNullOrBlank()) {

                                Spacer(modifier = Modifier.height(4.dp))

                                Text(
                                    text = threat.indicator,
                                    fontSize = 13.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "Risk Score: ${threat.riskScore}/100",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            androidx.compose.material3.TextButton(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = "Back")
            }
        }
    }
}

@Composable
private fun NeutralScanState() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            androidx.compose.material3.Icon(
                imageVector = androidx.compose.material.icons.Icons.Default.Shield,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )

            Spacer(modifier = Modifier.width(14.dp))

            Column {
                Text(
                    text = "No URL scanned yet",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Scan a link to check for potential threats.",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
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

            if (assessment.isTrending) {

                Spacer(modifier = Modifier.height(16.dp))

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = androidx.compose.material3.CardDefaults.cardColors(
                        containerColor = androidx.compose.ui.graphics.Color(0xFFFFF3E0)
                    )
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "🌐 Network Alert",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = androidx.compose.ui.graphics.Color(0xFFE65100)
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "This threat category is trending across TrustOS users " +
                                    "(${assessment.trendReportCount} recent verified reports). " +
                                    "Score boosted based on decentralized threat intelligence.",
                            fontSize = 14.sp,
                            color = androidx.compose.ui.graphics.Color(0xFFE65100)
                        )
                    }
                }
            }
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

@Composable
private fun PrivacySettingsScreen(
    currentProfile: PrivacyProfile,
    onProfileSelected: (PrivacyProfile) -> Unit,
    onBack: () -> Unit
) {

    val context = LocalContext.current

    val repository =
        remember {
            PrivacySettingsRepository(
                context.applicationContext
            )
        }

    val appsProvider =
        remember {
            InstalledAppsProvider(
                context.applicationContext
            )
        }

    val installedApps =
        remember {
            appsProvider.getInstalledApps()
        }

    var selectedApps by remember {
        mutableStateOf(
            repository.getAdditionalApps()
        )
    }

    val backgroundGradient = androidx.compose.ui.graphics.Brush.verticalGradient(
        colors = listOf(
            androidx.compose.ui.graphics.Color.White,
            androidx.compose.ui.graphics.Color(0xFFE0F2F1)
        )
    )

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .background(backgroundGradient),
        containerColor = androidx.compose.ui.graphics.Color.Transparent
    ) { innerPadding ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(24.dp)
                .verticalScroll(
                    rememberScrollState()
                )
        ) {

            Text(
                text = "Privacy Settings",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = "Choose how TrustOS protects your privacy.",
                fontSize = 16.sp,
                color =
                    MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(
                modifier = Modifier.height(24.dp)
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp)
            ) {

                Column(
                    modifier = Modifier.padding(20.dp)
                ) {

                    Text(
                        text = "Standard Privacy",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(
                        modifier = Modifier.height(8.dp)
                    )

                    Text(
                        text =
                            "TrustOS automatically protects predefined sensitive contexts such as galleries, banking, payments and password entry.",
                        fontSize = 14.sp
                    )

                    Spacer(
                        modifier = Modifier.height(12.dp)
                    )

                    androidx.compose.foundation.layout.Row(
                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        androidx.compose.material3.RadioButton(
                            selected =
                                currentProfile ==
                                        PrivacyProfile.STANDARD,
                            onClick = {
                                onProfileSelected(
                                    PrivacyProfile.STANDARD
                                )
                            }
                        )

                        Text(
                            text = "Use Standard Privacy",
                            fontSize = 16.sp
                        )
                    }
                }
            }

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp)
            ) {

                Column(
                    modifier = Modifier.padding(20.dp)
                ) {

                    Text(
                        text = "Enhanced Privacy",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(
                        modifier = Modifier.height(8.dp)
                    )

                    Text(
                        text =
                            "Keep all Standard protections and additionally protect apps that you personally select.",
                        fontSize = 14.sp
                    )

                    Spacer(
                        modifier = Modifier.height(12.dp)
                    )

                    androidx.compose.foundation.layout.Row(
                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        androidx.compose.material3.RadioButton(
                            selected =
                                currentProfile ==
                                        PrivacyProfile.ENHANCED,
                            onClick = {
                                onProfileSelected(
                                    PrivacyProfile.ENHANCED
                                )
                            }
                        )

                        Text(
                            text = "Use Enhanced Privacy",
                            fontSize = 16.sp
                        )
                    }

                    if (
                        currentProfile ==
                        PrivacyProfile.ENHANCED
                    ) {

                        Spacer(
                            modifier = Modifier.height(16.dp)
                        )

                        Text(
                            text = "Choose additional protected apps",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.SemiBold
                        )

                        Spacer(
                            modifier = Modifier.height(8.dp)
                        )

                        Text(
                            text =
                                "Standard protections remain active. These apps receive additional privacy protection.",
                            fontSize = 14.sp,
                            color =
                                MaterialTheme
                                    .colorScheme
                                    .onSurfaceVariant
                        )

                        Spacer(
                            modifier = Modifier.height(12.dp)
                        )

                        if (installedApps.isEmpty()) {

                            Text(
                                text = "No launchable apps found.",
                                fontSize = 15.sp
                            )

                        } else {

                            installedApps.forEach { app ->

                                Column(
                                    modifier = Modifier.fillMaxWidth()
                                ) {

                                    androidx.compose.foundation.layout.Row(
                                        modifier =
                                            Modifier.fillMaxWidth(),
                                        verticalAlignment =
                                            Alignment.CenterVertically
                                    ) {

                                        Checkbox(
                                            checked =
                                                selectedApps.contains(
                                                    app.packageName
                                                ),
                                            onCheckedChange = { checked ->

                                                selectedApps =
                                                    if (checked) {
                                                        selectedApps +
                                                                app.packageName
                                                    } else {
                                                        selectedApps -
                                                                app.packageName
                                                    }

                                                repository
                                                    .setAdditionalApps(
                                                        selectedApps
                                                    )
                                            }
                                        )

                                        Text(
                                            text = app.appName,
                                            fontSize = 16.sp
                                        )
                                    }

                                    if (app.permissionRisk.isNotable) {

                                        Text(
                                            text = "⚠ Notable permissions: " +
                                                    app.permissionRisk.findings.joinToString("; "),
                                            fontSize = 12.sp,
                                            color = androidx.compose.ui.graphics.Color(0xFFE65100),
                                            modifier = Modifier.padding(
                                                start = 48.dp,
                                                bottom = 8.dp
                                            )
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Spacer(
                modifier = Modifier.height(24.dp)
            )

            androidx.compose.material3.TextButton(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Back"
                )
            }
        }
    }
}