# ThreatDatabase.ps1
# Malicious OAuth applications database
# Source: https://www.entraprotect.io/applications

$script:ThreatDbPath = Join-Path $PSScriptRoot "..\data\threats.json"
$script:GitHubRawUrl = "https://raw.githubusercontent.com/anak0ndah/EntraHunt/main/data/threats.json"

function Get-ThreatDatabase {
    if (Test-Path $script:ThreatDbPath) {
        try {
            $jsonContent = Get-Content -Path $script:ThreatDbPath -Raw -Encoding UTF8
            $threats = $jsonContent | ConvertFrom-Json
            return $threats
        }
        catch {
            Write-Host "[!] Error loading threat database: $($_.Exception.Message)" -ForegroundColor Red
            return @()
        }
    }
    else {
        Write-Host "[!] Threat database not found at: $script:ThreatDbPath" -ForegroundColor Red
        return @()
    }
}

function Find-ThreatByAppId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )
    
    $db = Get-ThreatDatabase
    $threat = $db | Where-Object { $_.ApplicationId -eq $AppId }
    return $threat
}

function Get-AllMaliciousAppIds {
    $db = Get-ThreatDatabase
    return $db | ForEach-Object { $_.ApplicationId }
}

function Get-ThreatDatabaseInfo {
    $db = Get-ThreatDatabase
    $info = @{
        TotalThreats = $db.Count
        Critical     = ($db | Where-Object { $_.Impact -eq "critical" }).Count
        High         = ($db | Where-Object { $_.Impact -eq "high" }).Count
        Medium       = ($db | Where-Object { $_.Impact -eq "medium" }).Count
        Low          = ($db | Where-Object { $_.Impact -eq "low" }).Count
        LastModified = (Get-Item $script:ThreatDbPath -ErrorAction SilentlyContinue).LastWriteTime
    }
    return $info
}

function Update-ThreatDatabase {
    param(
        [Parameter(Mandatory = $false)]
        [string]$SourceUrl = $script:GitHubRawUrl
    )
    
    Write-Host ""
    Write-Host "[*] Updating threat database..." -ForegroundColor Cyan
    Write-Host "[*] Source: $SourceUrl" -ForegroundColor Gray
    
    try {
        $currentInfo = Get-ThreatDatabaseInfo
        Write-Host "[*] Current database: $($currentInfo.TotalThreats) threats" -ForegroundColor Gray
        
        $newContent = Invoke-RestMethod -Uri $SourceUrl -Method Get -ErrorAction Stop
        
        if ($newContent -is [string]) {
            $newThreats = $newContent | ConvertFrom-Json
        }
        else {
            $newThreats = $newContent
        }
        
        if ($newThreats.Count -eq 0) {
            Write-Host "[!] Downloaded database is empty. Update cancelled." -ForegroundColor Yellow
            return $false
        }
        
        $backupPath = "$script:ThreatDbPath.backup"
        if (Test-Path $script:ThreatDbPath) {
            Copy-Item -Path $script:ThreatDbPath -Destination $backupPath -Force
            Write-Host "[+] Backup created: $backupPath" -ForegroundColor Green
        }
        
        $newContent | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:ThreatDbPath -Encoding UTF8 -Force
        
        $updatedInfo = Get-ThreatDatabaseInfo
        $diff = $updatedInfo.TotalThreats - $currentInfo.TotalThreats
        
        Write-Host ""
        Write-Host "[+] Database updated successfully!" -ForegroundColor Green
        Write-Host "[+] Total threats: $($updatedInfo.TotalThreats)" -ForegroundColor Green
        
        if ($diff -gt 0) {
            Write-Host "[+] New threats added: $diff" -ForegroundColor Cyan
        }
        elseif ($diff -lt 0) {
            Write-Host "[*] Threats removed: $([Math]::Abs($diff))" -ForegroundColor Yellow
        }
        else {
            Write-Host "[*] No change in threat count" -ForegroundColor Gray
        }
        
        return $true
    }
    catch {
        Write-Host "[!] Update failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Check your internet connection or the source URL" -ForegroundColor Yellow
        return $false
    }
}

function Set-ThreatDatabaseSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )
    
    $script:GitHubRawUrl = $Url
    Write-Host "[+] Update source set to: $Url" -ForegroundColor Green
}
