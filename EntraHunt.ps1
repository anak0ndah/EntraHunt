#Requires -Version 5.1
<#
.SYNOPSIS
    EntraHunt - Malicious OAuth Application Hunter for Entra ID

.DESCRIPTION
    Scans your Entra ID tenant for known malicious OAuth applications 
    using threat intelligence from EntraProtect.io.

.EXAMPLE
    .\EntraHunt.ps1
    Runs the scanner interactively

.NOTES
    Requires Microsoft.Graph PowerShell module
    Required permissions: Application.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [switch]$OfflineTest,
    [switch]$Update,
    [string]$UpdateUrl
)

$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
if (-not $scriptDir) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

. "$scriptDir\modules\ThreatDatabase.ps1"
. "$scriptDir\modules\EntraConnector.ps1"
. "$scriptDir\modules\ReportGenerator.ps1"

function Write-Banner {
    $banner = @"

    ______       _             _   _             _   
   |  ____|     | |           | | | |           | |  
   | |__   _ __ | |_ _ __ __ _| |_| |_   _ _ __ | |_ 
   |  __| | '_ \| __| '__/ _` | __| | | | | '_ \| __|
   | |____| | | | |_| | | (_| | |_| | |_| | | | | |_ 
   |______|_| |_|\__|_|  \__,_|\__|_|\__,_|_| |_|\__|
                                                     
   Malicious OAuth Application Hunter
   Threat Intelligence: EntraProtect.io
   
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-GraphModule {
    Write-Host "[*] Checking Microsoft.Graph module..." -ForegroundColor Cyan
    
    $module = Get-Module -ListAvailable -Name "Microsoft.Graph.Applications" | Select-Object -First 1
    
    if (-not $module) {
        Write-Host "[!] Microsoft.Graph module not found." -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "Do you want to install it now? (Y/N)"
        
        if ($install -eq "Y" -or $install -eq "y") {
            Write-Host "[*] Installing Microsoft.Graph module..." -ForegroundColor Cyan
            try {
                Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
                Write-Host "[+] Module installed successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Failed to install module: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "[!] Please run: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
                return $false
            }
        }
        else {
            Write-Host "[!] Cannot continue without Microsoft.Graph module" -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "[+] Microsoft.Graph module found (v$($module.Version))" -ForegroundColor Green
    }
    
    return $true
}

function Start-Hunt {
    param(
        [string]$TenantId
    )
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host "             STARTING SECURITY SCAN" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host ""
    
    if (-not (Connect-EntraHunt -TenantId $TenantId)) {
        Write-Host "[!] Failed to connect to Microsoft Graph" -ForegroundColor Red
        return
    }
    
    Write-Host ""
    
    $enterpriseApps = Get-EnterpriseApplications
    $appRegistrations = Get-AppRegistrations
    
    Write-Host ""
    Write-Host "[*] Analyzing applications against threat database..." -ForegroundColor Cyan
    
    $maliciousAppIds = Get-AllMaliciousAppIds
    $findings = @()
    
    foreach ($app in $enterpriseApps) {
        if ($app.AppId -in $maliciousAppIds) {
            $threat = Find-ThreatByAppId -AppId $app.AppId
            
            if ($threat) {
                $affectedUsers = Get-ConsentedUsers -ServicePrincipalId $app.Id
                
                $finding = @{
                    Name          = $threat.Name
                    ApplicationId = $app.AppId
                    Categories    = $threat.Categories
                    Impact        = $threat.Impact
                    Description   = $threat.Description
                    AttackMethod  = $threat.AttackMethod
                    Scopes        = $threat.Scopes
                    AffectedUsers = $affectedUsers
                    ThreatActor   = $threat.ThreatActor
                    DetectedAs    = "Enterprise Application"
                    TenantAppName = $app.DisplayName
                }
                
                $findings += $finding
                
                Write-Host "[!] THREAT DETECTED: $($threat.Name) [$($threat.Impact.ToUpper())]" -ForegroundColor Red
            }
        }
    }
    
    foreach ($app in $appRegistrations) {
        if ($app.AppId -in $maliciousAppIds) {
            $existing = $findings | Where-Object { $_.ApplicationId -eq $app.AppId }
            
            if (-not $existing) {
                $threat = Find-ThreatByAppId -AppId $app.AppId
                
                if ($threat) {
                    $finding = @{
                        Name          = $threat.Name
                        ApplicationId = $app.AppId
                        Categories    = $threat.Categories
                        Impact        = $threat.Impact
                        Description   = $threat.Description
                        AttackMethod  = $threat.AttackMethod
                        Scopes        = $threat.Scopes
                        AffectedUsers = @()
                        ThreatActor   = $threat.ThreatActor
                        DetectedAs    = "App Registration"
                        TenantAppName = $app.DisplayName
                    }
                    
                    $findings += $finding
                    
                    Write-Host "[!] THREAT DETECTED (App Registration): $($threat.Name) [$($threat.Impact.ToUpper())]" -ForegroundColor Red
                }
            }
        }
    }
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host "                  SCAN COMPLETE" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host ""
    
    if ($findings.Count -eq 0) {
        Write-Host "[+] No malicious applications detected" -ForegroundColor Green
    }
    else {
        Write-Host "[!] Found $($findings.Count) malicious application(s)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "[*] Generating report..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    $reportsPath = Join-Path $scriptDir "reports"
    
    if (-not (Test-Path $reportsPath)) {
        New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
    }
    
    $reportFile = New-HuntingReport -Findings $findings `
        -TenantId $context.TenantId `
        -OutputPath $reportsPath `
        -TotalEnterpriseApps $enterpriseApps.Count `
        -TotalAppRegistrations $appRegistrations.Count
    
    Write-Host "[+] Report saved: $reportFile" -ForegroundColor Green
    
    $openReport = Read-Host "Open report in browser? (Y/N)"
    if ($openReport -eq "Y" -or $openReport -eq "y") {
        Start-Process $reportFile
    }
    
    Disconnect-EntraHunt
}

function Start-OfflineTest {
    Write-Host ""
    Write-Host "[*] Running offline test with sample data..." -ForegroundColor Yellow
    Write-Host ""
    
    $sampleFindings = @(
        @{
            Name          = "PERFECTDATA SOFTWARE"
            ApplicationId = "ff8d92dc-3d82-41d6-bcbd-b9174d163620"
            Categories    = @("bec", "exfiltration")
            Impact        = "high"
            Description   = "Known malicious application used in BEC campaigns. Performs complete mailbox backup and export operations."
            AttackMethod  = "Performs comprehensive mailbox exfiltration. All mailbox data should be considered compromised when this application is detected."
            Scopes        = @("Mail.Read", "Contacts.Read", "EWS.AccessAsUser.All")
            AffectedUsers = @(
                @{ DisplayName = "John Doe"; UserPrincipalName = "john.doe@contoso.com" },
                @{ DisplayName = "Jane Smith"; UserPrincipalName = "jane.smith@contoso.com" }
            )
            ThreatActor   = $null
        },
        @{
            Name          = "COZY BEAR OAuth Redirect App"
            ApplicationId = "fc45d3d0-d870-4c83-b3f7-08ebca61d3a0"
            Categories    = @("apt-campaign", "credential-theft")
            Impact        = "critical"
            Description   = "Malicious Azure application created by COZY BEAR (APT29). Single-tenant app hosted in attacker tenant."
            AttackMethod  = "Silent redirect via prompt=none to adversary infrastructure. Detection indicates direct targeting by Russian SVR."
            Scopes        = @("openid", "offline_access", "profile")
            AffectedUsers = @(
                @{ DisplayName = "Admin User"; UserPrincipalName = "admin@contoso.com" }
            )
            ThreatActor   = @{
                Name        = "COZY BEAR (APT29)"
                Attribution = "Russia - SVR"
                Confidence  = "Moderate"
            }
        }
    )
    
    $reportsPath = Join-Path $scriptDir "reports"
    
    if (-not (Test-Path $reportsPath)) {
        New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
    }
    
    $reportFile = New-HuntingReport -Findings $sampleFindings `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -OutputPath $reportsPath `
        -TotalEnterpriseApps 150 `
        -TotalAppRegistrations 35
    
    Write-Host "[+] Test report generated: $reportFile" -ForegroundColor Green
    Start-Process $reportFile
}

# Entry point
Clear-Host
Write-Banner

if ($OfflineTest) {
    Start-OfflineTest
    exit
}

if ($Update) {
    if ($UpdateUrl) {
        Set-ThreatDatabaseSource -Url $UpdateUrl
    }
    Update-ThreatDatabase
    exit
}

if (-not (Test-GraphModule)) {
    exit 1
}

Write-Host ""
Write-Host "Press ENTER to start the scan (or type a Tenant ID):" -ForegroundColor Yellow
$userInput = Read-Host

$tenantId = $null
if ($userInput -and $userInput.Length -gt 0) {
    $tenantId = $userInput
}

Start-Hunt -TenantId $tenantId
