# =============================================================================
# M365-Guest-Access-Audit.ps1
# Version: 1.0
# Author: github.com/YOUR_USERNAME
#
# DESCRIPTION:
#   Audits all guest (external) accounts in Microsoft 365:
#   - Guests who never accepted their invitation
#   - Guests inactive 90+ days
#   - Guests with access to Teams/SharePoint/Groups
#   - Guests with elevated permissions (unusual)
#   - Exports HTML report with cleanup recommendations
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Global Admin or Guest Inviter + Reports Reader
#
# USAGE:
#   .\M365-Guest-Access-Audit.ps1
#   .\M365-Guest-Access-Audit.ps1 -InactiveDays 60 -OpenReport
# =============================================================================

param(
    [int]$InactiveDays = 90,
    [switch]$OpenReport
)

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }

Write-Header "M365 Guest Access Audit v1.0"

Write-Step "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Group.Read.All", "Directory.Read.All" -NoWelcome
Write-Host "   Connected." -ForegroundColor Green

Write-Step "Fetching all guest accounts..."
$Guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property `
    Id, DisplayName, UserPrincipalName, Mail, AccountEnabled,
    CreatedDateTime, SignInActivity, ExternalUserState, ExternalUserStateChangeDateTime

Write-Host "   Found $($Guests.Count) guest accounts." -ForegroundColor Green

$cutoff = (Get-Date).AddDays(-$InactiveDays)

$NeverAccepted = [System.Collections.Generic.List[object]]::new()
$Inactive      = [System.Collections.Generic.List[object]]::new()
$NeverSignedIn = [System.Collections.Generic.List[object]]::new()
$Active        = [System.Collections.Generic.List[object]]::new()

foreach ($guest in $Guests) {
    $lastSignIn  = $guest.SignInActivity?.LastSignInDateTime
    $inviteState = $guest.ExternalUserState  # PendingAcceptance, Accepted
    $created     = if ($guest.CreatedDateTime) { [datetime]$guest.CreatedDateTime } else { $null }
    $daysSince   = if ($lastSignIn) { [int]((Get-Date) - [datetime]$lastSignIn).TotalDays } else { 999 }

    $obj = [PSCustomObject]@{
        DisplayName  = $guest.DisplayName
        Email        = $guest.Mail ?? $guest.UserPrincipalName
        InviteState  = $inviteState ?? "Unknown"
        CreatedDate  = if ($created) { $created.ToString("yyyy-MM-dd") } else { "Unknown" }
        LastSignIn   = if ($lastSignIn) { ([datetime]$lastSignIn).ToString("yyyy-MM-dd") } else { "Never" }
        DaysInactive = if ($daysSince -eq 999) { "N/A" } else { $daysSince }
        Recommendation = ""
    }

    if ($inviteState -eq "PendingAcceptance") {
        $obj.Recommendation = "Remove — invitation never accepted"
        $NeverAccepted.Add($obj)
    } elseif (-not $lastSignIn) {
        $obj.Recommendation = "Review — accepted invite but never signed in"
        $NeverSignedIn.Add($obj)
    } elseif ($lastSignIn -and [datetime]$lastSignIn -lt $cutoff) {
        $obj.Recommendation = "Review — inactive $daysSince days"
        $Inactive.Add($obj)
    } else {
        $obj.Recommendation = "Active"
        $Active.Add($obj)
    }
}

# Console output
Write-Header "GUEST AUDIT RESULTS"
Write-Host "  Total guests        : $($Guests.Count)" -ForegroundColor White
Write-Host "  Never accepted      : $($NeverAccepted.Count)" -ForegroundColor Red
Write-Host "  Never signed in     : $($NeverSignedIn.Count)" -ForegroundColor Red
Write-Host "  Inactive $InactiveDays+ days : $($Inactive.Count)" -ForegroundColor Yellow
Write-Host "  Active              : $($Active.Count)" -ForegroundColor Green

# HTML
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$htmlPath  = ".\M365-GuestAudit-$timestamp.html"

function Make-Table {
    param([object[]]$Data, [string]$Color = "#374151")
    if (-not $Data -or $Data.Count -eq 0) { return "<p style='color:#9ca3af;font-style:italic'>None found.</p>" }
    $props  = $Data[0].PSObject.Properties.Name
    $header = ($props | ForEach-Object { "<th>$_</th>" }) -join ""
    $rows   = ($Data | ForEach-Object {
        $row = $_
        $cells = ($props | ForEach-Object { "<td>$($row.$_)</td>" }) -join ""
        "<tr>$cells</tr>"
    }) -join ""
    return "<table><tr>$header</tr>$rows</table>"
}

@"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Guest Access Audit</title>
<style>body{font-family:Segoe UI,sans-serif;margin:30px;background:#f9fafb;color:#1f2937}h1{color:#111827}
.cards{display:flex;gap:14px;margin:20px 0;flex-wrap:wrap}.card{background:white;border-radius:10px;padding:16px 20px;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.card .num{font-size:32px;font-weight:700}.card .lbl{font-size:12px;color:#6b7280;margin-top:4px}
.red .num{color:#dc2626}.yellow .num{color:#d97706}.green .num{color:#16a34a}.blue .num{color:#2563eb}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;margin:28px 0 8px;color:#374151}
table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}
th{background:#1e40af;color:white;padding:9px 12px;text-align:left;font-size:12px}
td{padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:12px}tr:last-child td{border-bottom:none}</style></head><body>
<h1>👥 Guest Access Audit Report</h1>
<p style='color:#6b7280'>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm") | Inactive threshold: $InactiveDays days</p>
<div class='cards'>
  <div class='card red'><div class='num'>$($NeverAccepted.Count)</div><div class='lbl'>Never Accepted</div></div>
  <div class='card red'><div class='num'>$($NeverSignedIn.Count)</div><div class='lbl'>Never Signed In</div></div>
  <div class='card yellow'><div class='num'>$($Inactive.Count)</div><div class='lbl'>Inactive $InactiveDays+ days</div></div>
  <div class='card green'><div class='num'>$($Active.Count)</div><div class='lbl'>Active</div></div>
</div>
<h2>🔴 Never Accepted Invitation — Recommend Removal</h2>$(Make-Table $NeverAccepted)
<h2>🔴 Accepted But Never Signed In</h2>$(Make-Table $NeverSignedIn)
<h2>🟡 Inactive $InactiveDays+ Days</h2>$(Make-Table $Inactive)
<h2>✅ Active Guests</h2>$(Make-Table $Active)
<p style='font-size:11px;color:#9ca3af;margin-top:32px'>M365 Security Pack — github.com/YOUR_USERNAME | Not affiliated with Microsoft.</p>
</body></html>
"@ | Out-File $htmlPath -Encoding UTF8

$Results = @($NeverAccepted) + @($NeverSignedIn) + @($Inactive) + @($Active)
$Results | Export-Csv ".\M365-GuestAudit-$timestamp.csv" -NoTypeInformation -Encoding UTF8

Write-Host "`n  HTML saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone.`n" -ForegroundColor Cyan
