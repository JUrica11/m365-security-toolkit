# =============================================================================
# M365-Security-Score-Report.ps1
# Version: 1.0
# Author: github.com/JUrica11
#
# DESCRIPTION:
#   Generates a comprehensive M365 security posture report combining:
#   - Microsoft Secure Score (current + trend)
#   - Top improvement actions with point values
#   - Critical missing controls checklist
#   - Tenant-level security settings audit
#   - Exports polished HTML report suitable for client presentation
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module
#   - Security Reader or Global Reader role
#
# USAGE:
#   .\M365-Security-Score-Report.ps1
#   .\M365-Security-Score-Report.ps1 -OpenReport
# =============================================================================

param([switch]$OpenReport)

function Write-Header { param([string]$Text)
    Write-Host "`n$("=" * 65)" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$("=" * 65)" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text); Write-Host "`n>> $Text" -ForegroundColor Yellow }
function Write-OK   { param([string]$Text); Write-Host "   [OK] $Text" -ForegroundColor Green }

Write-Header "M365 Security Score Report v1.0"

Write-Step "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "User.Read.All", "Organization.Read.All", "Policy.Read.All" -NoWelcome
Write-OK "Connected."

# ── SECURE SCORE ──────────────────────────────────────────────────────────────
Write-Step "Fetching Microsoft Secure Score..."
$SecureScores = $null
$CurrentScore = $null
$MaxScore     = $null
$ScorePct     = 0
$ScoreHistory = [System.Collections.Generic.List[object]]::new()

try {
    $SecureScores = Get-MgSecuritySecureScore -Top 30 -ErrorAction Stop
    if ($SecureScores -and $SecureScores.Count -gt 0) {
        $Latest       = $SecureScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
        $CurrentScore = [math]::Round($Latest.CurrentScore, 1)
        $MaxScore     = [math]::Round($Latest.MaxScore, 1)
        $ScorePct     = if ($MaxScore -gt 0) { [math]::Round($CurrentScore / $MaxScore * 100) } else { 0 }
        Write-OK "Secure Score: $CurrentScore / $MaxScore ($ScorePct%)"

        # Build history (last 30 days)
        foreach ($s in ($SecureScores | Sort-Object CreatedDateTime)) {
            $ScoreHistory.Add([PSCustomObject]@{
                Date  = ([datetime]$s.CreatedDateTime).ToString("MMM dd")
                Score = [math]::Round($s.CurrentScore, 0)
                Max   = [math]::Round($s.MaxScore, 0)
            })
        }
    }
} catch {
    Write-Host "   [!!] Could not fetch Secure Score: $_" -ForegroundColor DarkYellow
}

# ── IMPROVEMENT ACTIONS ───────────────────────────────────────────────────────
Write-Step "Fetching improvement actions..."
$ImprovementActions = [System.Collections.Generic.List[object]]::new()

try {
    $Profiles = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop
    $LatestControls = if ($SecureScores -and $SecureScores.Count -gt 0) {
        ($SecureScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).ControlScores
    } else { @() }

    $ControlMap = @{}
    foreach ($ctrl in $LatestControls) { $ControlMap[$ctrl.ControlName] = $ctrl.Score }

    $notCompleted = $Profiles | Where-Object {
        $_.ActionType -ne "Review" -and
        ($ControlMap[$_.Id] ?? 0) -lt $_.MaxScore
    } | Sort-Object MaxScore -Descending | Select-Object -First 15

    foreach ($action in $notCompleted) {
        $currentPts = $ControlMap[$action.Id] ?? 0
        $ImprovementActions.Add([PSCustomObject]@{
            Action      = $action.Title
            Category    = $action.Category
            Points      = "$currentPts / $($action.MaxScore) pts"
            Gain        = $action.MaxScore - $currentPts
            UserImpact  = $action.UserImpact
            Threats     = ($action.Threats -join ", ")
        })
    }
    Write-OK "Found $($ImprovementActions.Count) improvement actions."
} catch {
    Write-Host "   [!!] Could not fetch improvement actions." -ForegroundColor DarkYellow
}

# ── TENANT SETTINGS AUDIT ─────────────────────────────────────────────────────
Write-Step "Auditing tenant security settings..."
$Checklist = [System.Collections.Generic.List[object]]::new()

# Check 1: Security defaults
try {
    $SecDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    $secDefEnabled = $SecDefaults.IsEnabled
    $Checklist.Add([PSCustomObject]@{
        Check   = "Security Defaults"
        Status  = if ($secDefEnabled) { "Enabled" } else { "Disabled" }
        OK      = $secDefEnabled
        Note    = if ($secDefEnabled) { "Basic MFA enforcement active" } else { "Disabled — ensure CA policies cover this" }
    })
} catch { }

# Check 2: CA policies exist
try {
    $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $enabledCA  = ($CAPolicies | Where-Object { $_.State -eq "enabled" }).Count
    $Checklist.Add([PSCustomObject]@{
        Check  = "Conditional Access Policies"
        Status = "$enabledCA enabled"
        OK     = $enabledCA -gt 0
        Note   = if ($enabledCA -gt 0) { "$enabledCA active policies" } else { "No enabled CA policies — high risk" }
    })
} catch { }

# Check 3: User count for context
try {
    $UserCount = (Get-MgUser -All -Filter "userType eq 'Member' and accountEnabled eq true" -Property Id).Count
    $GuestCount = (Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id).Count
    $Checklist.Add([PSCustomObject]@{
        Check  = "User Inventory"
        Status = "$UserCount members, $GuestCount guests"
        OK     = $true
        Note   = "Informational"
    })
} catch { }

# ── CONSOLE OUTPUT ────────────────────────────────────────────────────────────
Write-Header "SECURITY SCORE"
if ($CurrentScore) {
    Write-Host "  Current Score : $CurrentScore / $MaxScore ($ScorePct%)" -ForegroundColor $(
        if ($ScorePct -ge 70) {"Green"} elseif ($ScorePct -ge 40) {"Yellow"} else {"Red"}
    )
}

if ($ImprovementActions.Count -gt 0) {
    Write-Host "`n  TOP IMPROVEMENT ACTIONS:" -ForegroundColor Yellow
    $ImprovementActions | Select-Object -First 8 | Format-Table Action, Category, Points -AutoSize -Wrap
}

# ── HTML ──────────────────────────────────────────────────────────────────────
$timestamp   = Get-Date -Format "yyyyMMdd-HHmm"
$htmlPath    = ".\M365-SecurityScore-$timestamp.html"
$scoreColor  = if ($ScorePct -ge 70) {"#16a34a"} elseif ($ScorePct -ge 40) {"#d97706"} else {"#dc2626"}
$scoreLabel  = if ($ScorePct -ge 70) {"Good"} elseif ($ScorePct -ge 40) {"Needs Improvement"} else {"Critical"}

$actionRows = foreach ($a in $ImprovementActions) {
    $gainBadge = "<span style='background:#1e40af;color:white;padding:1px 7px;border-radius:8px;font-size:11px'>+$($a.Gain) pts</span>"
    "<tr><td>$($a.Action)</td><td>$($a.Category)</td><td>$gainBadge</td><td>$($a.UserImpact)</td></tr>"
}

$checkRows = foreach ($c in $Checklist) {
    $icon = if ($c.OK) { "✅" } else { "❌" }
    "<tr><td>$icon $($c.Check)</td><td>$($c.Status)</td><td>$($c.Note)</td></tr>"
}

$historyJson = ($ScoreHistory | ForEach-Object { "{`"date`":`"$($_.Date)`",`"score`":$($_.Score)}" }) -join ","

@"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>M365 Security Score Report</title>
<style>
body{font-family:Segoe UI,sans-serif;margin:30px;background:#f9fafb;color:#1f2937}
h1{color:#111827;margin-bottom:4px}h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;margin:28px 0 10px;color:#374151}
.score-wrap{display:flex;align-items:center;gap:40px;background:white;border-radius:14px;padding:28px 32px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin:24px 0;flex-wrap:wrap}
.score-circle{width:110px;height:110px;border-radius:50%;background:conic-gradient($scoreColor ${ScorePct}%, #e5e7eb 0);display:flex;align-items:center;justify-content:center;position:relative}
.score-inner{width:80px;height:80px;border-radius:50%;background:white;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-num{font-size:20px;font-weight:700;color:$scoreColor;line-height:1}.score-denom{font-size:10px;color:#9ca3af}
.score-info h2{margin:0 0 6px;color:#111827;font-size:22px;text-transform:none;letter-spacing:0}
.badge{display:inline-block;background:$scoreColor;color:white;padding:3px 12px;border-radius:12px;font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}
th{background:#1e40af;color:white;padding:9px 14px;text-align:left;font-size:12px}
td{padding:9px 14px;border-bottom:1px solid #f3f4f6;font-size:13px}tr:last-child td{border-bottom:none}
</style></head><body>
<h1>🏆 M365 Security Score Report</h1>
<p style='color:#6b7280;margin:0'>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm")</p>

$(if ($CurrentScore) {
"<div class='score-wrap'>
  <div class='score-circle'><div class='score-inner'><div class='score-num'>$ScorePct%</div><div class='score-denom'>score</div></div></div>
  <div class='score-info'>
    <h2>$CurrentScore / $MaxScore points</h2>
    <span class='badge'>$scoreLabel</span>
    <p style='color:#6b7280;font-size:13px;margin-top:8px'>$(if ($ScorePct -ge 70) {"Your tenant has a strong security posture."} elseif ($ScorePct -ge 40) {"Several improvements recommended."} else {"Immediate attention required — multiple critical gaps detected."})</p>
  </div>
</div>"
} else {
"<div style='background:#fffbf0;border:1px solid #d97706;padding:16px;border-radius:10px;margin:20px 0;color:#92400e'>⚠️ Secure Score data not available. Requires Security Reader role and appropriate licensing.</div>"
})

<h2>🎯 Top Improvement Actions</h2>
$(if ($actionRows.Count -gt 0) {
"<table><tr><th>Action</th><th>Category</th><th>Points Gain</th><th>User Impact</th></tr>$($actionRows -join '')</table>"
} else {
"<p style='color:#9ca3af;font-style:italic'>Improvement actions not available — requires Security Reader permissions.</p>"
})

<h2>⚙️ Tenant Security Checklist</h2>
$(if ($checkRows.Count -gt 0) {
"<table><tr><th>Check</th><th>Status</th><th>Notes</th></tr>$($checkRows -join '')</table>"
} else {
"<p style='color:#9ca3af;font-style:italic'>Checklist not available.</p>"
})

<p style='font-size:11px;color:#9ca3af;margin-top:32px'>M365 Security Pack — github.com/YOUR_USERNAME/m365-msp-toolkit | Not affiliated with Microsoft Corporation.</p>
</body></html>
"@ | Out-File $htmlPath -Encoding UTF8

Write-Host "`n  HTML saved: $htmlPath" -ForegroundColor Cyan
if ($OpenReport) { Start-Process $htmlPath }

Disconnect-MgGraph | Out-Null
Write-Host "`nDone.`n" -ForegroundColor Cyan
