# 🛡️ TrustOS

## Privacy-First Android Threat Detection

> **AI detects instantly. The network confirms. Privacy stays in control.**

TrustOS is a privacy-first Android security prototype designed to detect suspicious content such as phishing messages, deceptive URLs, credential requests, impersonation attempts, and other scam indicators directly from the device.

It combines context-aware privacy controls, accessibility-based screen text extraction, OCR, URL analysis, on-device NLP, local risk scoring, threat fingerprinting, a local Threat Vault, and a prototype threat-intelligence layer.

---

## 🚨 The Problem

Mobile phishing and scam content can arrive through ordinary apps, not only traditional browsers:

- Urgent account or verification messages
- Fake payment or credential requests
- Impersonation of trusted organizations
- Shortened or deceptive URLs
- Scam content embedded in images
- Wording designed to evade simple keyword matching

TrustOS analyzes relevant on-screen content while applying privacy-aware controls based on the context in which that content appears.

---

## 💡 How TrustOS Works

```text
                 Android Screen
                       │
                       ▼
             Accessibility Service
                       │
                       ▼
              Privacy Controller
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
      Visible Screen Text       OCR
             │                   │
             └─────────┬─────────┘
                       ▼
                Text Analysis
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
       Text Risk Signals    NLP Detection
              │                 │
              └────────┬────────┘
                       │
                       ▼
                  URL Analysis
                       │
                       ▼
                  Trust Engine
                       │
                       ▼
              Risk Assessment
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
        Threat Vault       Network Intelligence
```

---

# 🔐 Privacy-First Architecture

TrustOS does not treat every screen equally.

The `PrivacyController` evaluates application context before analysis.

| Context | Mode |
|---|---|
| Browser | `SCAN` |
| Messaging | `SCAN` |
| SMS | `SCAN` |
| Email | `SCAN` |
| Social Media | `SCAN` |
| Gallery | `PAUSE` |
| Payment | `RESTRICT` |
| Banking | `RESTRICT` |
| Password Entry | `RESTRICT` |
| Unknown | `PAUSE` |
| Other | `SCAN` |

In Enhanced Privacy mode, user-selected applications can also be excluded from scanning.

---

# 🧠 Multi-Layer Threat Detection

## 1. Text Risk Detection

The text detector looks for:

- Urgency language
- Account threats or suspension language
- Credential/authentication requests
- Financial or payment-related language
- Suspicious calls to action
- Possible authority or organization impersonation

Each finding contributes a risk value and confidence level.

## 2. URL Risk Detection

URLs are inspected for indicators including:

- Deceptive brand-like domains
- Known URL shorteners
- Plain HTTP connections
- IP-address URLs
- Excessive subdomains
- Excessive hyphens
- Suspicious security/account keywords
- `@` destination-obfuscation patterns
- Unusually long URLs
- Random-looking hostnames

## 3. OCR-Based Screen Analysis

When accessible screen text is unavailable or insufficient, TrustOS can capture the screen and run OCR.

```text
Screen
  ↓
Screenshot Capture
  ↓
OCR
  ↓
Recognized Text
  ↓
TrustOS Analysis Pipeline
```

OCR URL cleanup also handles common formatting artifacts such as:

```text
https : / / example . com
```

## 4. NLP Detection

TrustOS includes an on-device NLP detection path for suspicious phrasing that may evade exact keyword matching.

---

# ⚖️ Trust Engine

The Trust Engine combines detection results using each finding's risk contribution and confidence:

```text
Risk Contribution × Confidence
```

The resulting local score is normalized to 0–100.

| Score | Risk Level |
|---:|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

A risk assessment can contain:

- Risk score
- Confidence
- Risk level
- Detection reasons
- Threat category
- Trending status
- Related report count

---

# 🌐 Threat Intelligence

TrustOS contains a local network-intelligence prototype.

User-confirmed threats can contribute to the intelligence repository. Threat categories can accumulate report activity and become trending.

When a category is trending, the Trust Engine can apply an intelligence-based score boost.

```text
Local Detection
      │
      ▼
 Local Risk Score
      │
      ▼
Network Intelligence
      │
      ├── Not Trending ──► Local Score
      │
      └── Trending ──────► Score Boost
                              │
                              ▼
                       Final Risk Score
```

> **Implementation note:** the current network-intelligence layer is a local prototype representing the trust-intelligence concept. It is not presented here as a production blockchain or decentralized consensus network.

---

# 🧬 Threat Fingerprinting

TrustOS generates a threat fingerprint from detected evidence and its primary threat category.

This supports:

- Threat identity
- Duplicate prevention
- Threat history
- Network reporting
- Trend analysis

---

# 🗄️ Threat Vault

User-confirmed threats can be saved locally.

A threat record can contain:

- Threat fingerprint/key
- Source package
- URL indicator when available
- Threat category
- Risk score
- Confidence
- Detection reasons
- Timestamp

---

# 🚨 Threat Warning Flow

When the final risk assessment reaches the dangerous threshold, TrustOS prepares a threat record and checks existing threat history and network intelligence before showing the warning overlay.

```text
Suspicious Content
       ↓
Privacy Controller
       ↓
   SCAN allowed
       ↓
Analysis Engine
       ↓
Trust Engine
       ↓
Risk Assessment
       ↓
HIGH / CRITICAL
       ↓
Threat Record prepared
       ↓
Threat Vault + Network Intel checked
       ↓
Warning Overlay
       │
       ├── Ignore
       │
       └── Block & Save
              ↓
        Save to Threat Vault
              ↓
        New confirmed threat?
          │           │
         YES          NO
          │           │
          ▼           ▼
   Report category   No duplicate
   to network intel    report
```

The warning overlay also provides access to the threat details in the application's protection flow.

---

# 🔒 Sensitive Context Protection

TrustOS detects password-entry fields through Android accessibility information.

```text
Password Field Detected
          ↓
   PASSWORD_ENTRY
          ↓
       RESTRICT
          ↓
   Analysis blocked
```

This is part of the privacy-first architecture.

---

# 🏗️ Project Structure

```text
com.axiom.trustos
│
├── MainActivity
│
├── core
│   ├── ScreenCaptureHelper
│   ├── TrustAccessibilityService
│   ├── context
│   ├── detector
│   ├── engine
│   ├── intel
│   ├── model
│   ├── ocr
│   ├── privacy
│   └── threat
│
└── ui
    ├── WarningOverlay
    └── theme
```

---

# ⚙️ Technology Stack

| Technology | Purpose |
|---|---|
| Kotlin | Application development |
| Android | Mobile platform |
| Jetpack Compose | UI |
| Android Accessibility Service | Screen/application context access |
| Google ML Kit Text Recognition | OCR |
| On-device NLP | Suspicious phrasing detection |
| URI / URL analysis | URL threat indicators |
| SharedPreferences | Local privacy settings |
| Local repositories | Threat and intelligence storage |
| SHA-256 | Threat fingerprinting |

---

# ✨ Key Features

- 📱 Android screen analysis
- 🔍 Accessibility-based text extraction
- 👁️ OCR fallback for image-based content
- 🔗 URL threat analysis
- 🧠 On-device NLP detection
- ⚖️ Multi-signal Trust Engine
- 🎯 0–100 risk scoring
- 🚦 LOW / MEDIUM / HIGH / CRITICAL classification
- 🔐 Context-aware privacy controls
- 🔑 Password-field protection
- 🧬 Threat fingerprinting
- 🗄️ Local Threat Vault
- 🌐 Network threat-intelligence prototype
- 📈 Trending threat categories
- 🚨 Warning overlay
- 🛑 Duplicate threat suppression

---

# 🧪 Testing

The repository contains unit tests covering core components including:

- Context detection
- Text risk detection
- URL risk detection
- Trust scoring
- Analysis pipeline
- Privacy-related logic

Android instrumentation testing can be expanded as the project moves toward production deployment.

---

# 🚀 Getting Started

## Requirements

- Android Studio
- Android SDK
- JDK compatible with the project configuration
- Android device or emulator

## Clone

```bash
git clone https://github.com/nova19-S/TrustOS.git
cd TrustOS
```

Open the project in Android Studio and allow Gradle to synchronize.

Build and run on a compatible Android device or emulator.

### Android access

TrustOS uses Android accessibility capabilities for its screen-analysis workflow. The required system access must be enabled by the user on the device.

---

# 👥 Team AXIOM6

| Member | Responsibility |
|---|---|
| **Shiuli Laha** | System Architecture, Product & Integration |
| **Ayushi Yadav** | AI & ML, Threat Intelligence |
| **Amitesh Tiwari** | Android, Screen Analysis & OCR |
| **Mayuresh Singh** | URL Security & Cybersecurity |
| **Rishika Gupta** | UI/UX & User Experience |
| **Sejal Gupta** | Testing, Data & GitHub |

---

# 🎯 Project Context

TrustOS is a cybersecurity prototype focused on mobile phishing and scam detection.

The project combines:

**AI + Mobile Security + Privacy Controls + Threat Intelligence**

with the goal of detecting suspicious content close to where the user encounters it: on the Android device.

---

# 🔮 Future Development

Potential future directions include:

- Federated threat intelligence
- Distributed threat verification
- Stronger on-device ML models
- More advanced semantic analysis
- Improved application-context classification
- Privacy-preserving collaborative intelligence
- Production-grade decentralized infrastructure

---

# 📌 Current Status

TrustOS is a working prototype demonstrating the core detection, privacy, OCR, threat-analysis, threat-storage, and intelligence concepts.

Some components, particularly the network-intelligence/decentralized layer, remain prototype implementations intended to demonstrate the architecture and workflow rather than a production-scale distributed network.

---

## 🛡️ TrustOS

**AI detects instantly.  
The network confirms.  
Privacy stays in control.**
