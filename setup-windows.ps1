# sentry — one-time elevated Windows setup.
#
#   1. Registers a hidden logon task so WSL (and therefore sentry) starts at boot.
#   2. Removes the orphaned AnyDesk inbound firewall rules.
#
# Both need administrator rights. Read it before you run it — everything it does
# is printed as it happens, and nothing is removed without checking first.
#
# Run in an ELEVATED PowerShell:
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   & \\wsl.localhost\Ubuntu\home\chris\sentry\setup-windows.ps1

$ErrorActionPreference = 'Continue'

# --- 1. logon task ---------------------------------------------------------
try {
    if (Get-ScheduledTask -TaskName 'WSL sentry 24x7' -ErrorAction SilentlyContinue) {
        Write-Host "TASK: already registered, leaving it alone" -ForegroundColor Yellow
    } else {
        $a = New-ScheduledTaskAction -Execute 'wsl.exe' `
                -Argument '-d Ubuntu -u chris --exec /bin/true'
        $t = New-ScheduledTaskTrigger -AtLogOn -User 'chris'
        $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -Hidden `
                -MultipleInstances IgnoreNew
        $r = Register-ScheduledTask -TaskName 'WSL sentry 24x7' -Action $a `
                -Trigger $t -Settings $s -RunLevel Limited `
                -Description 'Starts WSL at logon so sentry keeps running'
        Write-Host "TASK: registered '$($r.TaskName)'" -ForegroundColor Green
    }
} catch { Write-Host "TASK FAILED: $($_.Exception.Message)" -ForegroundColor Red }

# --- 2. orphaned AnyDesk rules --------------------------------------------
# Scoped deliberately: inbound AnyDesk rules only, and only those whose program
# is missing from disk. AnyDesk is uninstalled; these leftovers pre-authorise
# inbound traffic to a path that anything could later occupy. A rule whose
# program still exists is left alone and reported.
try {
    $removed = 0; $kept = 0
    Get-NetFirewallRule -DisplayName 'AnyDesk' -Direction Inbound -ErrorAction SilentlyContinue |
      ForEach-Object {
        $rule = $_
        $prog = ($rule | Get-NetFirewallApplicationFilter).Program
        if ($prog -and -not (Test-Path -LiteralPath $prog)) {
            Write-Host "  removing: $($rule.DisplayName) -> $prog (missing)"
            Remove-NetFirewallRule -Name $rule.Name
            $removed++
        } else {
            Write-Host "  KEEPING:  $($rule.DisplayName) -> $prog (program exists)" -ForegroundColor Yellow
            $kept++
        }
      }
    Write-Host "FIREWALL: removed $removed orphaned rule(s), kept $kept" -ForegroundColor Green
} catch { Write-Host "FIREWALL FAILED: $($_.Exception.Message)" -ForegroundColor Red }

Write-Host "`nDone. Verify from WSL with:  sentry firewall --severity high"
