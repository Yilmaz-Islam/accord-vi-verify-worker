<#
  Sets up (or updates) a Windows scheduled task that runs the Accord VI backup every day.

    powershell -ExecutionPolicy Bypass -File scripts\install-backup-task.ps1 [-At 03:00]
    powershell -ExecutionPolicy Bypass -File scripts\install-backup-task.ps1 -Remove

  The task runs as you, only while you are signed in. If the laptop was off at the
  scheduled time it runs at the next opportunity ("run as soon as possible after a
  missed start"). Check backup.log in the backup folder to see each run's result.
#>
param(
  [string]$At = '03:00',
  [switch]$Remove
)

$TaskName = 'Accord VI daily backup'

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Output "Removed scheduled task '$TaskName'."
  return
}

$script = Join-Path $PSScriptRoot 'backup-accord.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
  -Description 'Copies the Accord VI database, receipts and logs to this computer every day and keeps 30 days.' -Force | Out-Null

$info = Get-ScheduledTask -TaskName $TaskName
Write-Output "Scheduled task '$TaskName' is $($info.State). It runs daily at $At."
