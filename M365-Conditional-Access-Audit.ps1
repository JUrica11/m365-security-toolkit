# =============================================================================
# M365-Conditional-Access-Audit.ps1
# Version: 1.0
# Author: github.com/JUrica11
#
# DESCRIPTION:
#   Audits Conditional Access policies in Microsoft 365 / Entra ID:
#   - Lists all CA policies with status (enabled/disabled/report-only)
#   - Identifies critical gaps: no MFA policy, no block legacy auth, no admin policy
#   - Checks for users/groups excluded from policies (risky exclusions)
#   - Risk score per gap
#   - Exports HTML report
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Global Admin or Security Reader + Conditional Access Administrator
#
# USAGE:
#   .\M365-Conditional-Access-Audit.ps1
#   .\M365-Conditional-Access-Audit.ps1 -OpenReport
# =============================================================================

param([switch]$OpenReport)

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }
function Write-OK   { param([string]$Text); Write-Host "   [OK] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text); Write-Host "   [!!] $Text" -ForegroundColor Red }

Write-Header "M365 Conditional Access Audit v1.0"

Write-Step "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" -NoWelcome
Write-OK "Connected."

# ── FETCH POLICIES ────────────────────────────────────────────────────────────
Write-Step "Fetching Conditional Access policies..."
$Policies = Get-MgIdentityConditionalAccessPolicy -All
Write-OK "Found $($Policies.Count) policies."

# ── ANALYZE POLICIES ──────────────────────────────────────────────────────────
Write-Step "Analyzing policy coverage..."

$Findings = [System.Collections.Generic.List[object]]::new()
$PolicyRows = [System.Collections.Generic.List[object]]::new()

$hasMFAPolicy          = $false
$hasBlockLegacyAuth    = $false
$hasAdminMFAPolicy     = $false
$hasDeviceCompliance   = $false
$hasRiskySignInPolicy  = $false

foreach ($policy in $Policies) {
    $status      = $policy.State  # enabled, disabled, enabledForReportingButNotEnforced
    $conditions  = $policy.Conditions
    $controls    = $policy.GrantControls
    $sessionCtrl = $policy.SessionControls

    $requiresMFA      = $controls.BuiltInControls -contains "mfa"
    $blocksAccess     = $controls.BuiltInControls -contains "block"
    $requiresCompliant= $controls.BuiltInControls -contains "compliantDevice"

    $clientApps   = $conditions.ClientAppTypes
    $blocksLegacy = ($clientApps -contains "exchangeActiveSync" -or $clientApps -contains "other") -and $blocksAccess
    $targetsAdmins= $conditions.Users.IncludeRoles.Count -gt 0

    if ($status -eq "enabled") {
        if ($requiresMFA)       { $hasMFAPolicy = $true }
        if ($blocksLegacy)      { $hasBlockLegacyAuth = $true }
        if ($requiresMFA -and $targetsAdmins) { $hasAdminMFAPolicy = $true }
        if ($requiresCompliant) { $hasDeviceCompliance = $true }
        if ($conditions.SignInRiskLevels.Count -gt 0) { $hasRiskySignInPolicy = $true }
    }

    $excludedUsers  = $conditions.Users.ExcludeUsers.Count
    $excludedGroups = $conditions.Users.ExcludeGroups.Count
    $exclusionNote  = if (($excludedUsers + $excludedGroups) -gt 0) {
        "⚠️ $excludedUsers user(s), $excludedGroups group(s) excluded"
    } else { "—" }

    $statusColor = switch ($status) {
        "enabled"                              { "green" }
        "enabledForReportingButNotEnforced"    { "orange" }
        "disabled"                             { "gray" }
    }
    $statusLabel = switch ($status) {
        "enabled"                              { "Enabled" }
        "enabledForReportingButNotEnforced"    { "Report Only" }
        "disabled"                             { "Disabled" }
    }

    $PolicyRows.Add([PSCustomObject]@{
        Name         = $policy.DisplayName
        Status       = $statusLabel
        StatusColor  = $statusColor
        RequiresMFA  = if ($requiresMFA) { "Yes" } else { "—" }
        BlocksAccess = if ($blocksAccess) { "Yes" } else { "—" }
        Exclusions   = $exclusionNote
    })
}

# ── GAP ANALYSIS ──────────────────────────────────────────────────────────────
if (-not $hasMFAPolicy) {
    $Findings.Add([PSCustomObject]@{
        Severity    = "CRITICAL"
        Gap         = "No enabled MFA policy found"
        Impact      = "All users can sign in without MFA — highest breach risk"
        Remediation = "Create CA policy: Require MFA for All Users"
    })
}
if (-not $hasAdminMFAPolicy) {
    $Findings.Add([PSCustomObject]@{
        Severity    = "CRITICAL"
        Gap         = "No MFA policy targeting admin roles"
        Impact      = "Admin accounts unprotected — full tenant takeover risk"
        Remediation = "Create CA policy: Require MFA for Directory Roles"
    })
}
if (-not $hasBlockLegacyAuth) {
    $Findings.Add([PSCustomObject]@{
        Severity    = "HIGH"
        Gap         = "Legacy authentication not blocked"
        Impact      = "Legacy protocols bypass MFA — common attack vector"
        Remediation = "Create CA policy: Block Legacy Authentication"
    })
}
if (-not $hasDeviceCompliance) {
    $Findings.Add([PSCustomObject]@{
        Severity    = "MEDIUM"
        Gap         = "No device compliance requirement"
        Impact      = "Unmanaged/non-compliant devices can access resources"
        Remediation = "Create CA policy: Require Compliant Device (needs Intune)"
    })
}
if (-not $hasRiskySignInPolicy) {
    $Findings.Add([PSCustomObject]@{
        Severity    = "MEDIUM"
        Gap         = "No risky sign-in policy"
        Impact      = "Suspicious sign-ins (impossible travel, etc.) not automatically blocked"
        Remediation = "Create CA policy: Block or MFA on High Risk Sign-In (needs Entra P2)"
    })
}

if ($Findings.Count -eq 0) {
    Write-OK "No critical gaps found."
} else {
    Write-Host "`n  GAPS FOUND: $($Findings.Count)" -ForegroundColor Red
    $Findings | Format-Table Severity, Gap, Remediation -AutoSize -Wrap
}

# ── HTML ──────────────────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$htmlPath  = ".\M365-CA-Audit-$timestamp.html"

$policyTableRows = foreach ($p in $PolicyRows) {
    $statusBadge = "<span style='background:$($p.StatusColor);color:white;padding:2px 8px;border-radius:10px;font-size:11px'>$($p.Status)</span>"
    "<tr><td><strong>$($p.Name)</strong></td><td>$statusBadge</td><td>$($p.RequiresMFA)</td><td>$($p.BlocksAccess)</td><td>$($p.Exclusions)</td></tr>"
}

$findingRows = foreach ($f in $Findings) {
    $bg = if ($f.Severity -eq "CRITICAL") { "#fff0f0" } elseif ($f.Severity -eq "HIGH") { "#fffbf0" } else { "#f0f9ff" }
    $badge = if ($f.Severity -eq "CRITICAL") { "#dc2626" } elseif ($f.Severity -eq "HIGH") { "#d97706" } else { "#2563eb" }
    "<tr style='background:$bg'><td><span style='background:$badge;color:white;padding:2px 8px;border-radius:10px;font-size:11px'>$($f.Severity)</span></td><td>$($f.Gap)</td><td>$($f.Impact)</td><td>$($f.Remediation)</td></tr>"
}

@"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>CA Audit</title>
<style>body{font-family:Segoe UI,sans-serif;margin:30px;color:#1f2937;background:#f9fafb}h1{color:#111827}h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:#374151;margin:28px 0 10px}table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:24px}th{background:#1e40af;color:white;padding:10px 14px;text-align:left;font-size:12px}td{padding:9px 14px;border-bottom:1px solid #f3f4f6;font-size:13px}tr:last-child td{border-bottom:none}</style></head><body>
<h1>🛡️ Conditional Access Audit Report</h1>
<p style='color:#6b7280'>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm") &nbsp;|&nbsp; Policies found: $($Policies.Count)</p>
<h2>⚠️ Security Gaps ($($Findings.Count) found)</h2>
<table><tr><th>Severity</th><th>Gap</th><th>Impact</th><th>Remediation</th></tr>$($findingRows -join '')</table>
<h2>All Conditional Access Policies</h2>
<table><tr><th>Policy Name</th><th>Status</th><th>Requires MFA</th><th>Blocks Access</th><th>Exclusions</th></tr>$($policyTableRows -join '')</table>
<p style='font-size:12px;color:#9ca3af'>M365 Security Pack — github.com/YOUR_USERNAME/m365-msp-toolkit | Not affiliated with Microsoft.</p>
</body></html>
"@ | Out-File $htmlPath -Encoding UTF8

Write-Host "`n  HTML saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone.`n" -ForegroundColor Cyan
