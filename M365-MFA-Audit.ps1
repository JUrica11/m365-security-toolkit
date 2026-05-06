# =============================================================================
# M365-MFA-Audit.ps1
# Version: 1.0
# Author: github.com/YOUR_USERNAME
#
# DESCRIPTION:
#   Audits MFA status across all users in a Microsoft 365 tenant:
#   - Users with NO MFA registered (highest risk)
#   - Users with weak MFA only (SMS/voice call)
#   - Admin accounts without MFA (critical)
#   - Per-user MFA method breakdown
#   - Exports color-coded HTML report + CSV
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Global Admin or Reports Reader + Security Reader roles
#
# INSTALL MODULE (run once):
#   Install-Module Microsoft.Graph -Scope CurrentUser
#
# USAGE:
#   .\M365-MFA-Audit.ps1
#   .\M365-MFA-Audit.ps1 -OpenReport
# =============================================================================

param(
    [switch]$OpenReport
)

$ErrorActionPreference = "Continue"

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }
function Write-OK   { param([string]$Text); Write-Host "   [OK] $Text" -ForegroundColor Green }
function Write-Fail { param([string]$Text); Write-Host "   [!!] $Text" -ForegroundColor Red }

# ── CONNECT ───────────────────────────────────────────────────────────────────
Write-Header "M365 MFA Audit Tool v1.0"

Write-Step "Connecting to Microsoft Graph..."
try {
    Connect-MgGraph -Scopes `
        "User.Read.All",
        "UserAuthenticationMethod.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory" -NoWelcome
    Write-OK "Connected."
} catch {
    Write-Fail "Connection failed: $_"
    exit 1
}

# ── FETCH USERS ───────────────────────────────────────────────────────────────
Write-Step "Fetching all users..."
$AllUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType |
    Where-Object { $_.UserType -ne "Guest" -and $_.AccountEnabled -eq $true }
Write-OK "Found $($AllUsers.Count) active member accounts."

# ── FETCH ADMIN ROLE MEMBERS ──────────────────────────────────────────────────
Write-Step "Identifying admin accounts..."
$AdminUPNs = [System.Collections.Generic.HashSet[string]]::new()

try {
    $DirectoryRoles = Get-MgDirectoryRole -All
    foreach ($role in $DirectoryRoles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        foreach ($member in $members) {
            try {
                $u = Get-MgUser -UserId $member.Id -Property UserPrincipalName -ErrorAction SilentlyContinue
                if ($u) { $AdminUPNs.Add($u.UserPrincipalName) | Out-Null }
            } catch {}
        }
    }
    Write-OK "Found $($AdminUPNs.Count) admin accounts."
} catch {
    Write-Fail "Could not fetch admin roles (requires additional permissions). Continuing without admin flag."
}

# ── AUDIT MFA PER USER ────────────────────────────────────────────────────────
Write-Step "Auditing MFA methods for each user (this takes a while for large tenants)..."

$Results     = [System.Collections.Generic.List[object]]::new()
$NoMFA       = 0
$WeakMFA     = 0
$StrongMFA   = 0
$AdminNoMFA  = 0
$processed   = 0

foreach ($user in $AllUsers) {
    $processed++
    if ($processed % 25 -eq 0) {
        Write-Host "   Processing $processed / $($AllUsers.Count)..." -ForegroundColor DarkGray
    }

    $methods    = @()
    $methodTypes = [System.Collections.Generic.List[string]]::new()
    $mfaStatus  = "None"
    $riskLevel  = "CRITICAL"
    $isAdmin    = $AdminUPNs.Contains($user.UserPrincipalName)

    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -All

        foreach ($method in $authMethods) {
            $type = $method.AdditionalProperties["@odata.type"]
            switch ($type) {
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                    $methodTypes.Add("Authenticator App") | Out-Null
                }
                "#microsoft.graph.fido2AuthenticationMethod" {
                    $methodTypes.Add("FIDO2 Security Key") | Out-Null
                }
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                    $methodTypes.Add("Windows Hello") | Out-Null
                }
                "#microsoft.graph.phoneAuthenticationMethod" {
                    $phoneType = $method.AdditionalProperties["phoneType"]
                    if ($phoneType -eq "mobile") { $methodTypes.Add("SMS/Voice (Weak)") | Out-Null }
                }
                "#microsoft.graph.softwareOathAuthenticationMethod" {
                    $methodTypes.Add("TOTP App") | Out-Null
                }
                "#microsoft.graph.emailAuthenticationMethod" {
                    $methodTypes.Add("Email OTP (Weak)") | Out-Null
                }
            }
        }

        # Determine MFA status
        $hasStrong = $methodTypes | Where-Object { $_ -match "Authenticator|FIDO2|Hello|TOTP" }
        $hasWeak   = $methodTypes | Where-Object { $_ -match "SMS|Voice|Email" }
        $hasAny    = $methodTypes.Count -gt 0

        if ($hasStrong) {
            $mfaStatus = "Strong MFA"
            $riskLevel = "OK"
            $StrongMFA++
        } elseif ($hasWeak) {
            $mfaStatus = "Weak MFA only"
            $riskLevel = "MEDIUM"
            $WeakMFA++
        } else {
            $mfaStatus = "No MFA"
            $riskLevel = "CRITICAL"
            $NoMFA++
            if ($isAdmin) { $AdminNoMFA++ }
        }

    } catch {
        $mfaStatus = "Error reading"
        $riskLevel = "UNKNOWN"
    }

    $Results.Add([PSCustomObject]@{
        DisplayName  = $user.DisplayName
        UPN          = $user.UserPrincipalName
        IsAdmin      = if ($isAdmin) { "YES" } else { "No" }
        MFAStatus    = $mfaStatus
        Methods      = if ($methodTypes.Count -gt 0) { $methodTypes -join ", " } else { "—" }
        RiskLevel    = $riskLevel
    })
}

# Sort: Critical first, then by admin status
$Results = $Results | Sort-Object @{E={
    switch ($_.RiskLevel) { "CRITICAL" {0} "MEDIUM" {1} "OK" {2} default {3} }
}}, @{E={ if ($_.IsAdmin -eq "YES") {0} else {1} }}

# ── CONSOLE SUMMARY ───────────────────────────────────────────────────────────
Write-Header "MFA AUDIT RESULTS"
Write-Host ""
Write-Host "  Total users audited : $($AllUsers.Count)" -ForegroundColor White
Write-Host "  No MFA (CRITICAL)   : $NoMFA" -ForegroundColor Red
Write-Host "  Weak MFA only       : $WeakMFA" -ForegroundColor Yellow
Write-Host "  Strong MFA          : $StrongMFA" -ForegroundColor Green
Write-Host "  Admin accounts w/o MFA: $AdminNoMFA" -ForegroundColor $(if ($AdminNoMFA -gt 0) { "Red" } else { "Green" })

if ($NoMFA -gt 0) {
    Write-Host "`n  USERS WITH NO MFA (first 15):" -ForegroundColor Red
    $Results | Where-Object { $_.RiskLevel -eq "CRITICAL" } | Select-Object -First 15 |
        Format-Table DisplayName, UPN, IsAdmin -AutoSize
}

# ── CSV EXPORT ────────────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$csvPath   = ".\M365-MFA-Audit-$timestamp.csv"
$Results | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`n  CSV saved: $csvPath" -ForegroundColor Cyan

# ── HTML REPORT ───────────────────────────────────────────────────────────────
$htmlPath = ".\M365-MFA-Audit-$timestamp.html"

$riskPct   = if ($AllUsers.Count -gt 0) { [math]::Round($NoMFA / $AllUsers.Count * 100) } else { 0 }
$strongPct = if ($AllUsers.Count -gt 0) { [math]::Round($StrongMFA / $AllUsers.Count * 100) } else { 0 }

$tableRows = foreach ($r in $Results) {
    $rowBg = switch ($r.RiskLevel) {
        "CRITICAL" { "style='background:#fff0f0'" }
        "MEDIUM"   { "style='background:#fffbf0'" }
        default    { "" }
    }
    $badge = switch ($r.RiskLevel) {
        "CRITICAL" { "<span style='background:#dc2626;color:white;padding:2px 8px;border-radius:10px;font-size:11px'>CRITICAL</span>" }
        "MEDIUM"   { "<span style='background:#d97706;color:white;padding:2px 8px;border-radius:10px;font-size:11px'>MEDIUM</span>" }
        "OK"       { "<span style='background:#16a34a;color:white;padding:2px 8px;border-radius:10px;font-size:11px'>OK</span>" }
        default    { "<span style='background:#6b7280;color:white;padding:2px 8px;border-radius:10px;font-size:11px'>UNKNOWN</span>" }
    }
    $adminBadge = if ($r.IsAdmin -eq "YES") { "<span style='background:#7c3aed;color:white;padding:2px 6px;border-radius:10px;font-size:10px'>ADMIN</span>" } else { "" }
    "<tr $rowBg><td>$($r.DisplayName) $adminBadge</td><td style='font-size:12px;color:#555'>$($r.UPN)</td><td>$($r.Methods)</td><td>$badge</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html><head>
<meta charset='UTF-8'>
<title>M365 MFA Audit Report</title>
<style>
  body{font-family:Segoe UI,sans-serif;margin:30px;color:#1f2937;background:#f9fafb}
  .card-wrap{display:flex;gap:16px;margin:24px 0;flex-wrap:wrap}
  .card{background:white;border-radius:10px;padding:20px 24px;min-width:150px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  .card .num{font-size:36px;font-weight:700;line-height:1}
  .card .label{font-size:13px;color:#6b7280;margin-top:6px}
  .card.red .num{color:#dc2626}
  .card.yellow .num{color:#d97706}
  .card.green .num{color:#16a34a}
  .card.purple .num{color:#7c3aed}
  h1{color:#111827;margin-bottom:4px}
  h2{color:#374151;margin:32px 0 12px;font-size:16px;text-transform:uppercase;letter-spacing:.05em}
  table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  th{background:#1e40af;color:white;padding:10px 14px;text-align:left;font-size:13px}
  td{padding:9px 14px;border-bottom:1px solid #f3f4f6;font-size:13px}
  tr:last-child td{border-bottom:none}
  .progress-wrap{margin:8px 0 24px}
  .progress-bar{height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden;margin-top:6px}
  .progress-fill{height:100%;border-radius:4px}
  .risk-label{font-size:12px;color:#6b7280;display:flex;justify-content:space-between}
</style></head><body>
<h1>🔐 M365 MFA Audit Report</h1>
<p style='color:#6b7280;margin:0'>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm") &nbsp;|&nbsp; Total users: $($AllUsers.Count)</p>

<div class='card-wrap'>
  <div class='card red'><div class='num'>$NoMFA</div><div class='label'>No MFA — Critical</div></div>
  <div class='card yellow'><div class='num'>$WeakMFA</div><div class='label'>Weak MFA only</div></div>
  <div class='card green'><div class='num'>$StrongMFA</div><div class='label'>Strong MFA</div></div>
  <div class='card purple'><div class='num'>$AdminNoMFA</div><div class='label'>Admins without MFA</div></div>
</div>

<div class='progress-wrap'>
  <div class='risk-label'><span>MFA Coverage</span><span>$strongPct% protected</span></div>
  <div class='progress-bar'><div class='progress-fill' style='width:$strongPct%;background:#16a34a'></div></div>
</div>
<div class='progress-wrap'>
  <div class='risk-label'><span>No MFA at all</span><span>$riskPct% at risk</span></div>
  <div class='progress-bar'><div class='progress-fill' style='width:$riskPct%;background:#dc2626'></div></div>
</div>

<h2>Full User Breakdown</h2>
<table>
  <tr><th>User</th><th>UPN</th><th>MFA Methods</th><th>Risk</th></tr>
  $($tableRows -join "`n  ")
</table>

<p style='margin-top:32px;font-size:12px;color:#9ca3af'>
  Generated by M365 MFA Audit Tool — github.com/YOUR_USERNAME/m365-msp-toolkit<br>
  Not affiliated with Microsoft Corporation.
</p>
</body></html>
"@

$html | Out-File $htmlPath -Encoding UTF8
Write-Host "  HTML report saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone. Share the HTML report with your client or manager.`n" -ForegroundColor Cyan
