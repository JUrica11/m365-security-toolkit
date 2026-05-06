# =============================================================================
# M365-Legacy-Auth-Audit.ps1
# Version: 1.0
# Author: github.com/YOUR_USERNAME
#
# DESCRIPTION:
#   Detects legacy authentication usage in Microsoft 365:
#   - Scans sign-in logs for legacy auth protocol usage (IMAP, POP3, SMTP AUTH,
#     Exchange ActiveSync, Outlook legacy, MAPI over HTTP, etc.)
#   - Identifies which users are still using legacy auth (can't be MFA protected)
#   - Shows which client apps/protocols are being used
#   - Helps identify what to target before blocking legacy auth
#   - Exports HTML report with block readiness score
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Entra ID P1 or P2 license (for sign-in logs)
#   - Global Admin or Security Reader + Reports Reader
#
# USAGE:
#   .\M365-Legacy-Auth-Audit.ps1
#   .\M365-Legacy-Auth-Audit.ps1 -DaysBack 14 -OpenReport
# =============================================================================

param(
    [int]$DaysBack = 7,
    [switch]$OpenReport
)

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }

Write-Header "M365 Legacy Authentication Audit v1.0"
Write-Host "  Analyzing last $DaysBack days of sign-in logs" -ForegroundColor White

Write-Step "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "AuditLog.Read.All", "User.Read.All" -NoWelcome
Write-Host "   Connected." -ForegroundColor Green

# Legacy auth client apps to detect
$LegacyClientApps = @(
    "Exchange ActiveSync",
    "IMAP4",
    "POP3",
    "SMTP AUTH",
    "Authenticated SMTP",
    "Outlook 2013 and earlier",
    "Other clients",
    "Exchange Online PowerShell",
    "Autodiscover",
    "MAPI over HTTP",
    "Offline Address Book"
)

Write-Step "Fetching sign-in logs (last $DaysBack days)..."
$startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

try {
    $SignIns = Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $startDate" -Top 5000 |
        Where-Object { $_.ClientAppUsed -in $LegacyClientApps -or $_.ClientAppUsed -match "legacy|older|basic" }

    Write-Host "   Found $($SignIns.Count) legacy auth sign-in events." -ForegroundColor $(if ($SignIns.Count -gt 0) {"Red"} else {"Green"})
} catch {
    Write-Host "   [!!] Could not fetch sign-in logs. Ensure you have Entra ID P1/P2 and AuditLog.Read.All permission." -ForegroundColor Red
    Write-Host "   Error: $_" -ForegroundColor DarkRed
    Disconnect-MgGraph | Out-Null
    exit 1
}

# ── ANALYZE ───────────────────────────────────────────────────────────────────
$UserMap    = @{}
$ProtocolMap = @{}

foreach ($signIn in $SignIns) {
    $upn      = $signIn.UserPrincipalName
    $protocol = $signIn.ClientAppUsed
    $app      = $signIn.AppDisplayName

    if (-not $UserMap.ContainsKey($upn)) {
        $UserMap[$upn] = @{
            DisplayName = $signIn.UserDisplayName
            UPN         = $upn
            Protocols   = [System.Collections.Generic.HashSet[string]]::new()
            Apps        = [System.Collections.Generic.HashSet[string]]::new()
            Count       = 0
            LastSeen    = $signIn.CreatedDateTime
        }
    }
    $UserMap[$upn].Protocols.Add($protocol) | Out-Null
    $UserMap[$upn].Apps.Add($app) | Out-Null
    $UserMap[$upn].Count++
    if ($signIn.CreatedDateTime -gt $UserMap[$upn].LastSeen) {
        $UserMap[$upn].LastSeen = $signIn.CreatedDateTime
    }

    if (-not $ProtocolMap.ContainsKey($protocol)) { $ProtocolMap[$protocol] = 0 }
    $ProtocolMap[$protocol]++
}

$UserResults = $UserMap.Values | ForEach-Object {
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        UPN         = $_.UPN
        Protocols   = ($_.Protocols -join ", ")
        Apps        = ($_.Apps -join ", ")
        EventCount  = $_.Count
        LastSeen    = if ($_.LastSeen) { ([datetime]$_.LastSeen).ToString("yyyy-MM-dd") } else { "—" }
    }
} | Sort-Object EventCount -Descending

$ProtocolResults = $ProtocolMap.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{ Protocol = $_.Key; Events = $_.Value }
} | Sort-Object Events -Descending

# Console
Write-Header "LEGACY AUTH RESULTS"
$readyToBlock = if ($UserMap.Count -eq 0) { "YES ✓" } else { "NO — $($UserMap.Count) user(s) still using legacy auth" }
Write-Host "  Unique users using legacy auth : $($UserMap.Count)" -ForegroundColor $(if ($UserMap.Count -gt 0) {"Red"} else {"Green"})
Write-Host "  Total legacy auth events       : $($SignIns.Count)" -ForegroundColor White
Write-Host "  Ready to block legacy auth?    : $readyToBlock" -ForegroundColor $(if ($UserMap.Count -eq 0) {"Green"} else {"Red"})

if ($UserResults.Count -gt 0) {
    Write-Host "`n  TOP LEGACY AUTH USERS:" -ForegroundColor Yellow
    $UserResults | Select-Object -First 10 | Format-Table DisplayName, Protocols, EventCount, LastSeen -AutoSize
}

# HTML
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$htmlPath  = ".\M365-LegacyAuth-$timestamp.html"

$userRows = foreach ($r in $UserResults) {
    "<tr><td><strong>$($r.DisplayName)</strong></td><td style='font-size:11px;color:#555'>$($r.UPN)</td><td>$($r.Protocols)</td><td>$($r.Apps)</td><td>$($r.EventCount)</td><td>$($r.LastSeen)</td></tr>"
}
$protoRows = foreach ($p in $ProtocolResults) {
    "<tr><td>$($p.Protocol)</td><td>$($p.Events)</td></tr>"
}

$blockReadyBg    = if ($UserMap.Count -eq 0) { "#f0fdf4" } else { "#fff0f0" }
$blockReadyColor = if ($UserMap.Count -eq 0) { "#16a34a" } else { "#dc2626" }
$blockReadyText  = if ($UserMap.Count -eq 0) { "✅ Ready to block legacy auth" } else { "❌ NOT ready — $($UserMap.Count) users still on legacy auth" }

@"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Legacy Auth Audit</title>
<style>body{font-family:Segoe UI,sans-serif;margin:30px;background:#f9fafb;color:#1f2937}h1{color:#111827}
.banner{padding:16px 20px;border-radius:10px;background:$blockReadyBg;border:2px solid $blockReadyColor;color:$blockReadyColor;font-size:16px;font-weight:600;margin:20px 0}
.cards{display:flex;gap:14px;margin:20px 0;flex-wrap:wrap}.card{background:white;border-radius:10px;padding:16px 20px;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.card .num{font-size:32px;font-weight:700;color:#dc2626}.card .lbl{font-size:12px;color:#6b7280;margin-top:4px}
table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}
th{background:#1e40af;color:white;padding:9px 12px;text-align:left;font-size:12px}
td{padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:12px}h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;margin:24px 0 8px;color:#374151}</style></head><body>
<h1>🔓 Legacy Authentication Audit</h1>
<p style='color:#6b7280'>Last $DaysBack days | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm")</p>
<div class='banner'>$blockReadyText</div>
<div class='cards'>
  <div class='card'><div class='num'>$($UserMap.Count)</div><div class='lbl'>Users on Legacy Auth</div></div>
  <div class='card'><div class='num'>$($SignIns.Count)</div><div class='lbl'>Total Events</div></div>
  <div class='card'><div class='num'>$($ProtocolMap.Count)</div><div class='lbl'>Protocols Detected</div></div>
</div>
<h2>Protocol Breakdown</h2>
<table style='max-width:400px'><tr><th>Protocol</th><th>Events</th></tr>$($protoRows -join '')</table>
<h2>Users Using Legacy Auth</h2>
$(if ($userRows.Count -gt 0) { "<table><tr><th>Name</th><th>UPN</th><th>Protocols</th><th>Apps</th><th>Events</th><th>Last Seen</th></tr>$($userRows -join '')</table>" } else { "<p style='color:#16a34a;font-weight:600'>✅ No users detected using legacy authentication in the last $DaysBack days.</p>" })
<h2>Next Steps</h2>
<ol style='font-size:13px;line-height:2'>
  <li>Work with users still on legacy auth to migrate to modern auth clients (Outlook 2016+, mobile apps)</li>
  <li>Set a migration deadline (typically 30-60 days)</li>
  <li>Once user count reaches 0 — create Conditional Access policy to block legacy auth</li>
  <li>Monitor for 7 days after blocking, check for helpdesk tickets</li>
</ol>
<p style='font-size:11px;color:#9ca3af;margin-top:24px'>M365 Security Pack — Not affiliated with Microsoft.</p>
</body></html>
"@ | Out-File $htmlPath -Encoding UTF8

$UserResults | Export-Csv ".\M365-LegacyAuth-$timestamp.csv" -NoTypeInformation -Encoding UTF8
Write-Host "`n  HTML saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone.`n" -ForegroundColor Cyan
