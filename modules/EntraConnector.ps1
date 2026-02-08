# EntraConnector.ps1
# Microsoft Graph API integration for EntraHunt

function Connect-EntraHunt {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    $requiredScopes = @(
        "Application.Read.All",
        "Directory.Read.All"
    )
    
    Write-Host ""
    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    try {
        $params = @{
            Scopes    = $requiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $params.TenantId = $TenantId
        }
        
        Connect-MgGraph @params
        
        $context = Get-MgContext
        if ($context) {
            Write-Host "[+] Connected to tenant: $($context.TenantId)" -ForegroundColor Green
            Write-Host "[+] Account: $($context.Account)" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "[!] Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    return $false
}

function Get-EnterpriseApplications {
    Write-Host "[*] Retrieving Enterprise Applications (Service Principals)..." -ForegroundColor Cyan
    
    try {
        $apps = Get-MgServicePrincipal -All -Property "Id,AppId,DisplayName,AppOwnerOrganizationId,CreatedDateTime,AccountEnabled"
        Write-Host "[+] Found $($apps.Count) Enterprise Applications" -ForegroundColor Green
        return $apps
    }
    catch {
        Write-Host "[!] Error retrieving Enterprise Applications: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-AppRegistrations {
    Write-Host "[*] Retrieving App Registrations..." -ForegroundColor Cyan
    
    try {
        $apps = Get-MgApplication -All -Property "Id,AppId,DisplayName,CreatedDateTime,SignInAudience"
        Write-Host "[+] Found $($apps.Count) App Registrations" -ForegroundColor Green
        return $apps
    }
    catch {
        Write-Host "[!] Error retrieving App Registrations: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-OAuthPermissionGrants {
    Write-Host "[*] Retrieving OAuth Permission Grants..." -ForegroundColor Cyan
    
    try {
        $grants = Get-MgOauth2PermissionGrant -All
        Write-Host "[+] Found $($grants.Count) OAuth Permission Grants" -ForegroundColor Green
        return $grants
    }
    catch {
        Write-Host "[!] Error retrieving OAuth grants: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-ConsentedUsers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    try {
        $grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$ServicePrincipalId'" -All
        $users = @()
        
        foreach ($grant in $grants) {
            if ($grant.ConsentType -eq "Principal" -and $grant.PrincipalId) {
                try {
                    $user = Get-MgUser -UserId $grant.PrincipalId -Property "DisplayName,UserPrincipalName" -ErrorAction SilentlyContinue
                    if ($user) {
                        $users += @{
                            DisplayName       = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Scopes            = $grant.Scope
                        }
                    }
                }
                catch {
                    # User might be deleted
                }
            }
            elseif ($grant.ConsentType -eq "AllPrincipals") {
                $users += @{
                    DisplayName       = "All Users (Admin Consent)"
                    UserPrincipalName = "admin-consent"
                    Scopes            = $grant.Scope
                }
            }
        }
        
        return $users
    }
    catch {
        return @()
    }
}

function Disconnect-EntraHunt {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "[*] Disconnected from Microsoft Graph" -ForegroundColor Cyan
    }
    catch {
        # Silently ignore
    }
}
