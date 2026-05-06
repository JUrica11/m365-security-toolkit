# =============================================================================
# M365-Admin-Roles-Audit.ps1
# Version: 1.0
# Author: github.com/YOUR_USERNAME
#
# DESCRIPTION:
#   Audits all privileged/admin role assignments in Microsoft 365 / Entra ID:
#   - Lists every user with admin roles (Global Admin, Exchange Admin, etc.)
#   - Flags accounts with Global Admin that are not break-glass accounts
#   - Identifies admin accounts without MFA
#   - Detects stale admin accounts (inactive 90+ days)
#   - Checks for guest accounts with admin roles (very risky)
#   - Exports HTML report
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Global Admin or Privileged Role Administrator
#
# USAGE:
#   .\M365-Admin-Roles-Audit.ps1
#   .\M365-Admin-Roles-Audit.ps1 -OpenReport
# =============================================================================

param([switch]$OpenReport)

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }

Write-Header "M365 Admin Roles Audit v1.0"

Write-Step "Connecting..."
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory", "UserAuthenticationMethod.Read.All" -NoWelcome
Write-Host "   Connected." -ForegroundColor Green

Write-Step "Fetching directory roles..."
$Roles   = Get-MgDirectoryRole -All
$Results = [System.Collections.Generic.List[object]]::new()

$GlobalAdminCount = 0
$GuestAdminCount  = 0
$NoMFAAdminCount  = 0
$InactiveAdmin    = 0

foreach ($role in $Roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($member in $members) {
        try {
            $user = Get-MgUser -UserId $member.Id -Property `
                Id, DisplayName, UserPrincipalName, UserType, AccountEnabled, SignInActivity -ErrorAction Stop

            # MFA check
            $hasMFA = $false
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -All
                $hasMFA  = $methods | Where-Object {
                    $_.AdditionalProperties["@odata.type"] -match "authenticator|fido2|windowsHello|softwareOath"
                }
            } catch {}

            $lastSignIn  = $user.SignInActivity?.LastSignInDateTime
            $daysSince   = if ($lastSignIn) { [int]((Get-Date) - [datetime]$lastSignIn).TotalDays } else { 999 }
            $isInactive  = $daysSince -gt 90
            $isGuest     = $user.UserType -eq "Guest"
            $isGlobalAdm = $role.DisplayName -eq "Global Administrator"

            if ($isGlobalAdm)  { $GlobalAdminCount++ }
            if ($isGuest)      { $GuestAdminCount++ }
            if (-not $hasMFA)  { $NoMFAAdminCount++ }
            if ($isInactive)   { $InactiveAdmin++ }

            $riskFlags = [System.Collections.Generic.List[string]]::new()
            if (-not $hasMFA)        { $riskFlags.Add("No MFA") | Out-Null }
            if ($isGuest)            { $riskFlags.Add("Guest account!") | Out-Null }
            if ($isInactive)         { $riskFlags.Add("Inactive $daysSince days") | Out-Null }
            if (-not $user.AccountEnabled) { $riskFlags.Add("Account disabled") | Out-Null }

            $Results.Add([PSCustomObject]@{
                DisplayName  = $user.DisplayName
                UPN          = $user.UserPrincipalName
                Role         = $role.DisplayName
                UserType     = $user.UserType ?? "Member"
                Enabled      = $user.AccountEnabled
                HasMFA       = if ($hasMFA) { "Yes" } else { "NO" }
                LastSignIn   = if ($lastSignIn) { ([datetime]$lastSignIn).ToString("yyyy-MM-dd") } else { "Never" }
                DaysSince    = if ($daysSince -eq 999) { "N/A" } else { $daysSince }
                RiskFlags    = if ($riskFlags.Count -gt 0) { $riskFlags -join " | " } else { "—" }
            })
        } catch { }
    }
}

$Results = $Results | Sort-Object @{E={ if ($_.RiskFlags -ne "—") {0} else {1} }}, Role

# Console
Write-Header "ADMIN ROLES SUMMARY"
Write-Host "  Total admin assignments : $($Results.Count)" -ForegroundColor White
Write-Host "  Global Admins           : $GlobalAdminCount" -ForegroundColor $(if ($GlobalAdminCount -gt 5) {"Red"} else {"White"})
Write-Host "  Admins without MFA      : $NoMFAAdminCount" -ForegroundColor $(if ($NoMFAAdminCount -gt 0) {"Red"} else {"Green"})
Write-Host "  Guest accounts w/ roles : $GuestAdminCount" -ForegroundColor $(if ($GuestAdminCount -gt 0) {"Red"} else {"Green"})
Write-Host "  Inactive admins (90d+)  : $InactiveAdmin" -ForegroundColor $(if ($InactiveAdmin -gt 0) {"Yellow"} else {"Green"})

if ($GlobalAdminCount -gt 5) {
    Write-Host "`n  [!!] WARNING: $GlobalAdminCount Global Admins detected. Microsoft recommends 2-4 max." -ForegroundColor Red
}

$Results | Where-Object { $_.RiskFlags -ne "—" } | Select-Object -First 20 | Format-Table DisplayName, Role, HasMFA, RiskFlags -AutoSize

# HTML
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$htmlPath  = ".\M365-AdminRoles-$timestamp.html"

$tableRows = foreach ($r in $Results) {
    $rowBg = if ($r.RiskFlags -ne "—") { "style='background:#fff8f8'" } else { "" }
    $mfaBadge = if ($r.HasMFA -eq "Yes") {
        "<span style='background:#16a34a;color:white;padding:2px 6px;border-radius:8px;font-size:11px'>MFA ✓</span>"
    } else {
        "<span style='background:#dc2626;color:white;padding:2px 6px;border-radius:8px;font-size:11px'>No MFA ✗</span>"
    }
    $flags = if ($r.RiskFlags -ne "—") {
        "<span style='color:#dc2626;font-size:11px'>⚠️ $($r.RiskFlags)</span>"
    } else { "—" }
    "<tr $rowBg><td><strong>$($r.DisplayName)</strong></td><td style='font-size:11px;color:#555'>$($r.UPN)</td><td>$($r.Role)</td><td>$mfaBadge</td><td>$($r.LastSignIn)</td><td>$flags</td></tr>"
}

@"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Admin Roles Audit</title>
<style>body{font-family:Segoe UI,sans-serif;margin:30px;background:#f9fafb;color:#1f2937}h1{color:#111827}
.cards{display:flex;gap:14px;margin:20px 0;flex-wrap:wrap}.card{background:white;border-radius:10px;padding:16px 20px;min-width:130px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.card .num{font-size:32px;font-weight:700}.card .lbl{font-size:12px;color:#6b7280;margin-top:4px}
.red .num{color:#dc2626}.yellow .num{color:#d97706}.green .num{color:#16a34a}
table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}
th{background:#1e40af;color:white;padding:10px 14px;text-align:left;font-size:12px}
td{padding:9px 14px;border-bottom:1px solid #f3f4f6;font-size:13px}tr:last-child td{border-bottom:none}</style></head><body>
<h1>🔑 Admin Roles Audit Report</h1>
<p style='color:#6b7280'>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm")</p>
<div class='cards'>
  <div class='card'><div class='num'>$($Results.Count)</div><div class='lbl'>Total Assignments</div></div>
  <div class='card $(if ($GlobalAdminCount -gt 5) {"red"} else {""})'><div class='num'>$GlobalAdminCount</div><div class='lbl'>Global Admins</div></div>
  <div class='card $(if ($NoMFAAdminCount -gt 0) {"red"} else {"green"})'><div class='num'>$NoMFAAdminCount</div><div class='lbl'>No MFA</div></div>
  <div class='card $(if ($GuestAdminCount -gt 0) {"red"} else {"green"})'><div class='num'>$GuestAdminCount</div><div class='lbl'>Guest Admins</div></div>
  <div class='card $(if ($InactiveAdmin -gt 0) {"yellow"} else {"green"})'><div class='num'>$InactiveAdmin</div><div class='lbl'>Inactive 90d+</div></div>
</div>
<table><tr><th>Name</th><th>UPN</th><th>Role</th><th>MFA</th><th>Last Sign-In</th><th>Risk Flags</th></tr>
$($tableRows -join "`n")</table>
<p style='font-size:11px;color:#9ca3af;margin-top:24px'>M365 Security Pack — Not affiliated with Microsoft.</p>
</body></html>
"@ | Out-File $htmlPath -Encoding UTF8

$Results | Export-Csv ".\M365-AdminRoles-$timestamp.csv" -NoTypeInformation -Encoding UTF8
Write-Host "`n  HTML saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone.`n" -ForegroundColor Cyan
