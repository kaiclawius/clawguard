# ClawGuard Background Monitor — Windows Task Scheduler Setup
# Run this once to install ClawGuard as a background service
# No admin required — runs as current user

$NodePath = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $NodePath) {
    Write-Host "❌ Node.js not found. Please install Node.js first."
    exit 1
}

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$MonitorScript = Join-Path $ScriptPath "background-monitor.js"

if (-not (Test-Path $MonitorScript)) {
    Write-Host "❌ background-monitor.js not found at: $MonitorScript"
    exit 1
}

Write-Host "Installing ClawGuard Background Monitor..."
Write-Host "Node: $NodePath"
Write-Host "Script: $MonitorScript"

# Task 1: SOUL.md integrity check every 30 minutes
$Action1 = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$MonitorScript`" --soul"
$Trigger1 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) -Once -At (Get-Date)
$Settings1 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "ClawGuard-SoulCheck" `
    -Action $Action1 `
    -Trigger $Trigger1 `
    -Settings $Settings1 `
    -Description "ClawGuard: Checks SOUL.md integrity every 30 minutes" `
    -Force | Out-Null

Write-Host "✅ SOUL.md monitor: every 30 minutes"

# Task 2: Skills scan every hour (checks for newly installed skills)
$Action2 = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$MonitorScript`" --scan"
$Trigger2 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
$Settings2 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "ClawGuard-SkillScan" `
    -Action $Action2 `
    -Trigger $Trigger2 `
    -Settings $Settings2 `
    -Description "ClawGuard: Scans newly installed skills every hour" `
    -Force | Out-Null

Write-Host "✅ Skills monitor: every hour"
Write-Host ""
Write-Host "ClawGuard is now running in the background."
Write-Host "You will receive Telegram alerts if anything suspicious is detected."
Write-Host ""
Write-Host "To uninstall:"
Write-Host "  Unregister-ScheduledTask -TaskName 'ClawGuard-SoulCheck' -Confirm:`$false"
Write-Host "  Unregister-ScheduledTask -TaskName 'ClawGuard-SkillScan' -Confirm:`$false"
