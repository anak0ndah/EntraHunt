# EntraHunt

**Malicious OAuth Application Hunter for Microsoft Entra ID**

EntraHunt is a PowerShell-based threat hunting tool designed to detect malicious OAuth applications lurking in your Microsoft Entra ID (Azure AD) tenant. It leverages curated threat intelligence from [EntraProtect.io](https://www.entraprotect.io) to identify known malicious apps that attackers use for Business Email Compromise (BEC), credential theft, MFA bypass, and persistent access.

## Why EntraHunt?

OAuth consent phishing is one of the most dangerous attack vectors in cloud environments. Attackers trick users into granting permissions to malicious applications, which then:

- **Exfiltrate mailbox data** using apps like PERFECTDATA SOFTWARE and Mail_Backup
- **Bypass MFA** through adversary-in-the-middle phishing kits (Tycoon 2FA)
- **Maintain persistent access** via third-party email clients
- **Conduct APT campaigns** like COZY BEAR (APT29) targeting high-value organizations

Traditional security tools often miss these threats because the apps operate with legitimate OAuth tokens. EntraHunt fills this gap by comparing your tenant's applications against a continuously updated database of known malicious app signatures.

![EntraHunt Demo](images/discovery.gif)

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
├── images/
│   └── discovery.gif          # Demo animation
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
