# ReportGenerator.ps1
# Premium HTML report generation for EntraHunt

function New-HuntingReport {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [int]$TotalEnterpriseApps = 0,
        
        [Parameter(Mandatory = $false)]
        [int]$TotalAppRegistrations = 0
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportFileName = "EntraHunt_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $OutputPath $reportFileName
    
    # Calculate statistics
    $totalAffectedUsers = ($Findings | ForEach-Object { $_.AffectedUsers } | Measure-Object).Count
    $totalAppsScanned = $TotalEnterpriseApps + $TotalAppRegistrations
    $threatDbSize = (Get-ThreatDatabase).Count
    $criticalCount = ($Findings | Where-Object { $_.Impact -eq "critical" }).Count
    $highCount = ($Findings | Where-Object { $_.Impact -eq "high" }).Count
    
    $findingsHtml = ""
    
    if ($Findings.Count -eq 0) {
        $findingsHtml = @"
        <div class="no-findings">
            <div class="shield-icon">
                <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#2ed573" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
            <h2>Your Tenant is Protected</h2>
            <p>No known malicious OAuth applications were detected in your environment.</p>
            <p class="subtitle">Continue monitoring regularly to maintain security posture.</p>
        </div>
"@
    }
    else {
        $findingIndex = 0
        foreach ($finding in $Findings) {
            $findingIndex++
            $impactClass = switch ($finding.Impact) {
                "critical" { "impact-critical" }
                "high" { "impact-high" }
                "medium" { "impact-medium" }
                default { "impact-low" }
            }
            
            $impactIcon = switch ($finding.Impact) {
                "critical" { '<svg class="severity-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' }
                "high" { '<svg class="severity-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' }
                default { '<svg class="severity-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>' }
            }
            
            $categories = ($finding.Categories -join " &bull; ").ToUpper()
            $scopes = $finding.Scopes -join ", "
            
            $usersHtml = ""
            if ($finding.AffectedUsers -and $finding.AffectedUsers.Count -gt 0) {
                $usersList = ""
                foreach ($user in $finding.AffectedUsers) {
                    $usersList += "<div class='user-item'><span class='user-icon'>&#128100;</span><div><strong>$($user.DisplayName)</strong><span class='user-email'>$($user.UserPrincipalName)</span></div></div>"
                }
                $usersHtml = "<div class='users-section'><h4><span class='section-icon'>&#128101;</span> Affected Users</h4><div class='users-list'>$usersList</div></div>"
            }
            
            $threatActorHtml = ""
            if ($finding.ThreatActor) {
                $threatActorHtml = @"
                <div class="threat-actor-card">
                    <div class="threat-actor-header">
                        <span class="apt-badge">APT</span>
                        <h4>Threat Actor Attribution</h4>
                    </div>
                    <div class="threat-actor-body">
                        <div class="actor-name">$($finding.ThreatActor.Name)</div>
                        <div class="actor-meta">
                            <span class="actor-attribution">$($finding.ThreatActor.Attribution)</span>
                            <span class="actor-confidence">Confidence: $($finding.ThreatActor.Confidence)</span>
                        </div>
                    </div>
                </div>
"@
            }
            
            $findingsHtml += @"
            <div class="finding-card $impactClass" style="animation-delay: $($findingIndex * 0.1)s">
                <div class="finding-number">#$findingIndex</div>
                <div class="finding-header">
                    <div class="finding-title-group">
                        $impactIcon
                        <div>
                            <h3>$($finding.Name)</h3>
                            <div class="finding-categories">$categories</div>
                        </div>
                    </div>
                    <div class="impact-badge $impactClass">$($finding.Impact.ToUpper())</div>
                </div>
                
                <div class="app-id-bar">
                    <span class="label">Application ID</span>
                    <code>$($finding.ApplicationId)</code>
                    <button class="copy-btn" onclick="navigator.clipboard.writeText('$($finding.ApplicationId)')">Copy</button>
                </div>
                
                <div class="finding-content">
                    <div class="info-section">
                        <h4><span class="section-icon">&#128269;</span> What is this?</h4>
                        <p>$($finding.Description)</p>
                    </div>
                    
                    <div class="info-section attack-section">
                        <h4><span class="section-icon">&#9888;</span> Attack Vector</h4>
                        <p>$($finding.AttackMethod)</p>
                    </div>
                    
                    <div class="info-section">
                        <h4><span class="section-icon">&#128273;</span> Permissions Requested</h4>
                        <div class="scopes-container">
                            <code class="scopes">$scopes</code>
                        </div>
                    </div>
                    
                    $usersHtml
                    $threatActorHtml
                </div>
            </div>
"@
        }
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EntraHunt Security Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: rgba(20, 20, 30, 0.8);
            --bg-glass: rgba(255, 255, 255, 0.03);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --text-muted: #6b6b7b;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-cyan: #06b6d4;
            --critical: #ff4757;
            --high: #ff6b6b;
            --medium: #ffa502;
            --low: #7bed9f;
            --success: #2ed573;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            background-image: 
                radial-gradient(ellipse 80% 50% at 50% -20%, rgba(59, 130, 246, 0.15), transparent),
                radial-gradient(ellipse 60% 40% at 100% 0%, rgba(139, 92, 246, 0.1), transparent);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        /* Hero Header */
        .hero-header {
            text-align: center;
            padding: 60px 40px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }
        
        .hero-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .logo-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.3);
        }
        
        .logo-icon svg {
            width: 32px;
            height: 32px;
            stroke: white;
        }
        
        h1 {
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #a0a0b0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }
        
        .hero-subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 16px;
        }
        
        .hero-description {
            font-size: 0.95rem;
            color: var(--text-muted);
            max-width: 700px;
            margin: 0 auto 32px;
            line-height: 1.7;
        }
        
        .report-meta {
            display: flex;
            justify-content: center;
            gap: 40px;
            flex-wrap: wrap;
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .meta-item svg {
            width: 16px;
            height: 16px;
            stroke: var(--accent-cyan);
        }
        
        /* Threat Counter */
        .threat-counter {
            margin-bottom: 40px;
        }
        
        .counter-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 60px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .counter-card.has-threats {
            border-color: rgba(255, 71, 87, 0.4);
            background: linear-gradient(135deg, rgba(255, 71, 87, 0.1), rgba(255, 107, 107, 0.05));
        }
        
        .counter-card.has-threats::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--critical), var(--high));
        }
        
        .counter-card.no-threats {
            border-color: rgba(46, 213, 115, 0.4);
            background: linear-gradient(135deg, rgba(46, 213, 115, 0.1), rgba(6, 182, 212, 0.05));
        }
        
        .counter-card.no-threats::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--success), var(--accent-cyan));
        }
        
        .counter-icon {
            margin-bottom: 20px;
        }
        
        .counter-icon svg {
            width: 64px;
            height: 64px;
        }
        
        .has-threats .counter-icon svg {
            stroke: var(--critical);
        }
        
        .no-threats .counter-icon svg {
            stroke: var(--success);
        }
        
        .counter-value {
            font-size: 6rem;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 16px;
        }
        
        .has-threats .counter-value {
            color: var(--critical);
        }
        
        .no-threats .counter-value {
            color: var(--success);
        }
        
        .counter-label {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        
        .stat-icon {
            width: 40px;
            height: 40px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 12px;
            font-size: 1.2rem;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .stat-critical .stat-icon { background: rgba(255, 71, 87, 0.2); }
        .stat-critical .stat-value { color: var(--critical); }
        .stat-high .stat-icon { background: rgba(255, 107, 107, 0.2); }
        .stat-high .stat-value { color: var(--high); }
        .stat-medium .stat-icon { background: rgba(255, 165, 2, 0.2); }
        .stat-medium .stat-value { color: var(--medium); }
        .stat-scanned .stat-icon { background: rgba(59, 130, 246, 0.2); }
        .stat-scanned .stat-value { color: var(--accent-blue); }
        .stat-users .stat-icon { background: rgba(139, 92, 246, 0.2); }
        .stat-users .stat-value { color: var(--accent-purple); }
        .stat-database .stat-icon { background: rgba(6, 182, 212, 0.2); }
        .stat-database .stat-value { color: var(--accent-cyan); }
        
        .stats-section {
            margin-bottom: 40px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }
        
        @media (max-width: 800px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }
        .stat-registrations .stat-value { color: var(--accent-cyan); }
        
        /* Findings Section */
        .findings-section {
            margin-bottom: 40px;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }
        
        .section-header h2 {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .threat-count {
            background: var(--critical);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        /* Finding Cards */
        .finding-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            margin-bottom: 24px;
            overflow: hidden;
            position: relative;
            animation: slideIn 0.5s ease-out forwards;
            opacity: 0;
            transform: translateY(20px);
        }
        
        @keyframes slideIn {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .finding-card.impact-critical { border-left: 4px solid var(--critical); }
        .finding-card.impact-high { border-left: 4px solid var(--high); }
        .finding-card.impact-medium { border-left: 4px solid var(--medium); }
        .finding-card.impact-low { border-left: 4px solid var(--low); }
        
        .finding-number {
            position: absolute;
            top: 20px;
            right: 20px;
            font-size: 3rem;
            font-weight: 800;
            color: rgba(255,255,255,0.03);
            pointer-events: none;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 24px 28px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .finding-title-group {
            display: flex;
            align-items: flex-start;
            gap: 16px;
        }
        
        .severity-icon {
            width: 28px;
            height: 28px;
            flex-shrink: 0;
            margin-top: 2px;
        }
        
        .finding-card.impact-critical .severity-icon { color: var(--critical); }
        .finding-card.impact-high .severity-icon { color: var(--high); }
        .finding-card.impact-medium .severity-icon { color: var(--medium); }
        .finding-card.impact-low .severity-icon { color: var(--low); }
        
        .finding-header h3 {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 6px;
        }
        
        .finding-categories {
            font-size: 0.75rem;
            color: var(--text-muted);
            letter-spacing: 0.1em;
        }
        
        .impact-badge {
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .impact-badge.impact-critical { background: var(--critical); color: white; }
        .impact-badge.impact-high { background: var(--high); color: white; }
        .impact-badge.impact-medium { background: var(--medium); color: #000; }
        .impact-badge.impact-low { background: var(--low); color: #000; }
        
        .app-id-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 28px;
            background: rgba(0,0,0,0.3);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        
        .app-id-bar .label {
            color: var(--text-muted);
            font-family: 'Inter', sans-serif;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .app-id-bar code {
            color: var(--accent-cyan);
            flex: 1;
        }
        
        .copy-btn {
            background: rgba(255,255,255,0.1);
            border: none;
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .copy-btn:hover {
            background: var(--accent-blue);
            color: white;
        }
        
        .finding-content {
            padding: 28px;
        }
        
        .info-section {
            margin-bottom: 24px;
        }
        
        .info-section h4 {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 10px;
        }
        
        .section-icon {
            font-size: 1rem;
        }
        
        .info-section p {
            color: var(--text-primary);
            line-height: 1.7;
        }
        
        .attack-section {
            background: rgba(255, 71, 87, 0.05);
            border: 1px solid rgba(255, 71, 87, 0.2);
            border-radius: 12px;
            padding: 20px;
        }
        
        .attack-section h4 {
            color: var(--critical);
        }
        
        .scopes-container {
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 16px;
            overflow-x: auto;
        }
        
        .scopes {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--accent-purple);
            word-break: break-all;
            line-height: 1.8;
        }
        
        .users-section {
            background: rgba(59, 130, 246, 0.05);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }
        
        .users-section h4 {
            color: var(--accent-blue);
            margin-bottom: 16px;
        }
        
        .users-list {
            display: grid;
            gap: 12px;
        }
        
        .user-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        
        .user-icon {
            font-size: 1.5rem;
        }
        
        .user-item strong {
            display: block;
            font-size: 0.95rem;
        }
        
        .user-email {
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .threat-actor-card {
            background: linear-gradient(135deg, rgba(255, 71, 87, 0.1), rgba(139, 92, 246, 0.1));
            border: 1px solid rgba(255, 71, 87, 0.3);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }
        
        .threat-actor-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px 20px;
            background: rgba(0,0,0,0.2);
        }
        
        .apt-badge {
            background: var(--critical);
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.1em;
        }
        
        .threat-actor-header h4 {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        .threat-actor-body {
            padding: 20px;
        }
        
        .actor-name {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--critical);
            margin-bottom: 8px;
        }
        
        .actor-meta {
            display: flex;
            gap: 20px;
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        
        .remediation-section {
            background: linear-gradient(135deg, rgba(46, 213, 115, 0.05), rgba(6, 182, 212, 0.05));
            border: 1px solid rgba(46, 213, 115, 0.2);
            border-radius: 12px;
            padding: 20px;
        }
        
        .remediation-section h4 {
            color: var(--success);
            margin-bottom: 16px;
        }
        
        .action-steps {
            display: grid;
            gap: 12px;
        }
        
        .action-step {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        
        .step-number {
            width: 28px;
            height: 28px;
            background: var(--success);
            color: #000;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.85rem;
            flex-shrink: 0;
        }
        
        /* No Findings */
        .no-findings {
            background: linear-gradient(135deg, rgba(46, 213, 115, 0.1), rgba(6, 182, 212, 0.1));
            border: 1px solid rgba(46, 213, 115, 0.3);
            border-radius: 24px;
            padding: 80px 40px;
            text-align: center;
        }
        
        .shield-icon {
            margin-bottom: 24px;
        }
        
        .no-findings h2 {
            font-size: 2rem;
            font-weight: 700;
            color: var(--success);
            margin-bottom: 16px;
        }
        
        .no-findings p {
            color: var(--text-secondary);
            font-size: 1.1rem;
            max-width: 500px;
            margin: 0 auto;
        }
        
        .no-findings .subtitle {
            font-size: 0.95rem;
            color: var(--text-muted);
            margin-top: 12px;
        }
        
        /* Footer */
        footer {
            text-align: center;
            padding: 40px;
            border-top: 1px solid var(--border-color);
        }
        
        .footer-brand {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-bottom: 16px;
        }
        
        .footer-brand svg {
            width: 20px;
            height: 20px;
            stroke: var(--accent-blue);
        }
        
        footer p {
            color: var(--text-muted);
            font-size: 0.85rem;
        }
        
        footer a {
            color: var(--accent-blue);
            text-decoration: none;
            transition: color 0.2s;
        }
        
        footer a:hover {
            color: var(--accent-purple);
        }
        
        .powered-by {
            margin-top: 8px;
            font-size: 0.8rem;
        }
        
        .remediation-section-global {
            background: linear-gradient(135deg, rgba(46, 213, 115, 0.08), rgba(6, 182, 212, 0.08));
            border: 1px solid rgba(46, 213, 115, 0.3);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
        }
        
        .remediation-section-global h2 {
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--success);
            font-size: 1.5rem;
            margin-bottom: 16px;
        }
        
        .remediation-intro {
            color: var(--text-secondary);
            margin-bottom: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="hero-header">
            <div class="logo">
                <div class="logo-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <h1>EntraHunt</h1>
            </div>
            <p class="hero-subtitle">OAuth Threat Intelligence Report</p>
            <p class="hero-description">Automatically detects malicious OAuth applications in your Microsoft Entra ID tenant by comparing your Enterprise Applications and App Registrations against a curated database of known threat indicators.</p>
            <div class="report-meta">
                <div class="meta-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
                        <line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>
                        <line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    <span>$reportDate</span>
                </div>
                <div class="meta-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                    </svg>
                    <span>Tenant: $TenantId</span>
                </div>
            </div>
        </header>
        
        <section class="threat-counter">
            <div class="counter-card $(if ($Findings.Count -gt 0) { 'has-threats' } else { 'no-threats' })">
                <div class="counter-icon">
                    $(if ($Findings.Count -gt 0) { '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' } else { '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>' })
                </div>
                <div class="counter-value">$($Findings.Count)</div>
                <div class="counter-label">$(if ($Findings.Count -gt 0) { 'Malicious Applications Detected' } else { 'No Threats Detected' })</div>
            </div>
        </section>
        
        <section class="stats-section">
            <div class="stats-grid">
                <div class="stat-card stat-users">
                    <div class="stat-icon">&#128101;</div>
                    <div class="stat-value">$totalAffectedUsers</div>
                    <div class="stat-label">Affected Users</div>
                </div>
                <div class="stat-card stat-scanned">
                    <div class="stat-icon">&#128269;</div>
                    <div class="stat-value">$totalAppsScanned</div>
                    <div class="stat-label">Apps Scanned</div>
                </div>
                <div class="stat-card stat-database">
                    <div class="stat-icon">&#128202;</div>
                    <div class="stat-value">$threatDbSize</div>
                    <div class="stat-label">Threats in Database</div>
                </div>
                <div class="stat-card stat-critical">
                    <div class="stat-icon">&#128680;</div>
                    <div class="stat-value">$criticalCount / $highCount</div>
                    <div class="stat-label">Critical / High</div>
                </div>
            </div>
        </section>
        
        <section class="findings-section">
            <div class="section-header">
                <h2>Detected Threats</h2>
                $(if ($Findings.Count -gt 0) { "<span class='threat-count'>$($Findings.Count) FOUND</span>" })
            </div>
            $findingsHtml
        </section>
        
        $(if ($Findings.Count -gt 0) {
        @"
        <section class="remediation-section-global">
            <h2><span class="section-icon">&#128736;</span> Recommended Actions</h2>
            <p class="remediation-intro">If any threats were detected, take the following steps immediately:</p>
            <div class="action-steps">
                <div class="action-step"><span class="step-number">1</span><span>Revoke all OAuth grants for detected malicious applications</span></div>
                <div class="action-step"><span class="step-number">2</span><span>Remove the applications from Enterprise Applications</span></div>
                <div class="action-step"><span class="step-number">3</span><span>Investigate affected user accounts for compromise indicators</span></div>
                <div class="action-step"><span class="step-number">4</span><span>Review Azure AD sign-in and audit logs</span></div>
                <div class="action-step"><span class="step-number">5</span><span>Reset credentials for all affected users</span></div>
            </div>
        </section>
"@
        })
        
        <footer>
            <div class="footer-brand">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <strong>EntraHunt</strong>
            </div>
            <p>Threat intelligence powered by <a href="https://www.entraprotect.io" target="_blank">EntraProtect.io</a></p>
            <p class="powered-by">Created by <a href="https://www.linkedin.com/in/kondah/" target="_blank">Kondah Hamza</a></p>
        </footer>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    
    return $reportPath
}
