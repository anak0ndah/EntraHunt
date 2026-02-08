# EntraHunt

**Malicious OAuth Application Hunter for Microsoft Entra ID**

Scan your tenant for known malicious OAuth applications using threat intelligence from [EntraProtect.io](https://www.entraprotect.io).

---

## Quick Start

```powershell
.\EntraHunt.ps1
```

The script is fully interactive. Just run it and follow the prompts.

---

## Requirements

- PowerShell 5.1+
- Microsoft.Graph module (auto-installs if missing)
- Entra ID permissions: `Application.Read.All`, `Directory.Read.All`

---

## What It Does

1. Connects to your Entra ID tenant via Microsoft Graph
2. Retrieves all **Enterprise Applications** and **App Registrations**
3. Compares against a database of **17 known malicious applications**
4. Generates a detailed HTML report with:
   - Malicious apps count and statistics
   - Threat descriptions and attack methods
   - Affected users who granted consent
   - Threat actor attribution (for APT campaigns)
   - Remediation steps

---

## Threat Coverage

| Category | Examples |
|----------|----------|
| BEC / Exfiltration | PERFECTDATA SOFTWARE, Mail_Backup, eM Client |
| Persistence | Fastmail, Spike, PostBox, BlueMail |
| MFA Bypass | iLSMART (Tycoon 2FA phishing kit) |
| APT Campaigns | COZY BEAR (APT29) OAuth redirect app |
| Data Harvesting | ZoomInfo, SigParser |

---

## Commands

```powershell
# Run scan interactively
.\EntraHunt.ps1

# Test mode (no tenant connection)
.\EntraHunt.ps1 -OfflineTest

# Update threat database from GitHub
.\EntraHunt.ps1 -Update
```

---

## Project Structure

```
EntraHunt/
├── EntraHunt.ps1              # Main entry point
├── README.md
├── data/
│   └── threats.json           # Threat database (JSON)
├── modules/
│   ├── ThreatDatabase.ps1     # Database loader + update function
│   ├── EntraConnector.ps1     # Microsoft Graph integration
│   └── ReportGenerator.ps1    # HTML report generator
└── reports/                   # Generated reports
```

---

## Credits

- Threat intelligence: [EntraProtect.io](https://www.entraprotect.io)
- Created by [Kondah Hamza](https://www.linkedin.com/in/kondah/)
