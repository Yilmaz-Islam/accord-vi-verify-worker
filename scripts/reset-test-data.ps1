<#
  Wipes every account, registration, receipt and ticket from the database so the whole flow
  (sign up, register, pay, confirm, ticket, gate) can be tested again from nothing.

  What it does, in order:
    1. shows how many accounts, registrations and tickets exist right now
    2. takes a full backup first (scripts\backup-accord.ps1), and stops if that fails
    3. asks you to type RESET
    4. runs scripts\reset-test-data.sql
    5. shows the counts again (all zero)

  It keeps the tables and the secrets, and does NOT touch the older registration log in KV
  (the "Older submissions" tab). The one-time codes and rate-limit counters in KV expire on their own
  within an hour, so if a test from the same network says "too many attempts", wait a little.

  This is permanent. The backup in step 2 is the only way back (restore steps are in backup-accord.ps1).

  Live database:   powershell -ExecutionPolicy Bypass -File scripts\reset-test-data.ps1
  Local database:  powershell -ExecutionPolicy Bypass -File scripts\reset-test-data.ps1 -Local
#>
param(
  [switch]$Local,
  [string]$Repo = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Push-Location $Repo
try {
  if ($Local) { $where = @('--local', '--config', 'wrangler.local.jsonc'); $label = 'LOCAL test database' }
  else        { $where = @('--remote'); $label = 'LIVE database' }

  # Wrangler is run straight through Node, not through `npx`. Node's npx.ps1 shim re-reads the command text
  # in its own scope when called from a script, so the variables below would arrive empty ("Cannot bind
  # argument to parameter 'Path' because it is an empty string").
  $Wrangler = Join-Path $Repo 'node_modules\wrangler\bin\wrangler.js'
  if (-not (Test-Path $Wrangler)) { throw "Wrangler is not installed in $Repo. Run npm install there first." }
  function Invoke-Wrangler { & node $Wrangler @args }

  $countSql = 'SELECT (SELECT COUNT(*) FROM users) AS accounts, (SELECT COUNT(*) FROM tickets) AS registrations, (SELECT COUNT(*) FROM attendee_tickets) AS qr_tickets, (SELECT COUNT(*) FROM receipt_history) AS earlier_receipts, (SELECT COUNT(*) FROM sessions) AS signed_in_devices;'
  function Show-Counts {
    Invoke-Wrangler d1 execute accord-accounts @where --yes --command $countSql
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the database (is wrangler logged in?)' }
  }

  Write-Output ''
  Write-Output "About to ERASE all accounts, registrations, receipts and tickets in the $label."
  Write-Output 'Right now it holds:'
  Show-Counts

  if (-not $Local) {
    Write-Output ''
    Write-Output 'Taking a backup first...'
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'backup-accord.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'The backup failed, so nothing was erased.' }
  }

  Write-Output ''
  $answer = Read-Host "Type RESET (capitals) to erase everything in the $label, or press Enter to cancel"
  if ($answer -cne 'RESET') { Write-Output 'Cancelled. Nothing was changed.'; return }

  Invoke-Wrangler d1 execute accord-accounts @where --yes --file (Join-Path $PSScriptRoot 'reset-test-data.sql')
  if ($LASTEXITCODE -ne 0) { throw 'The reset did not finish. Run the script again.' }

  Write-Output ''
  Write-Output 'Done. The database now holds:'
  Show-Counts
}
finally {
  Pop-Location
}
