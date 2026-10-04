<#
  Accord VI backup: copies everything the site stores to this computer.

  What it saves, into a new dated folder each run:
    accord-accounts.sql   the whole D1 database: accounts, registrations, receipt images
                          (also the history of replaced receipts) and the per-person tickets
    legacy-log.json       the older-style registration log kept in Cloudflare KV
  Folders older than -KeepDays (default 30) are deleted, which is also how deleted
  people's data leaves the backups: within 30 days.

  Run by hand:   powershell -ExecutionPolicy Bypass -File scripts\backup-accord.ps1
  Scheduled:     scripts\install-backup-task.ps1 sets it up to run daily.
  Restore:       npx wrangler d1 execute accord-accounts --remote --file <folder>\accord-accounts.sql
                 (into an empty database)

  These files contain personal details and payment receipts. They are kept outside
  OneDrive on purpose. Do not copy them anywhere shared.
#>
param(
  [string]$Root = (Join-Path $env:USERPROFILE 'accord-backups'),
  [int]$KeepDays = 30,
  [string]$Repo = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$KvNamespace = '7d31167ed85b4e8695aef6476c1fad9a'   # the CODES namespace in wrangler.jsonc

New-Item -ItemType Directory -Force -Path $Root | Out-Null
$log = Join-Path $Root 'backup.log'
function Write-Log([string]$msg) { "$(Get-Date -Format 's')  $msg" | Add-Content -Path $log -Encoding UTF8 }

$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$dir = Join-Path $Root $stamp

try {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Push-Location $Repo

  # 1. The D1 database (the receipts are table data, so they are in here)
  $sql = Join-Path $dir 'accord-accounts.sql'
  & npx --no-install wrangler d1 export accord-accounts --remote --output $sql 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "D1 export failed (exit $LASTEXITCODE). Is wrangler still logged in?" }
  if (-not (Test-Path $sql) -or (Get-Item $sql).Length -lt 500) { throw 'D1 export file is missing or too small' }
  $head = (Get-Content $sql -TotalCount 400) -join "`n"
  if ($head -notmatch 'CREATE TABLE') { throw 'D1 export does not look like a database dump' }

  # 2. The older-style registration log in KV (reg:<time>:<email>)
  $keys = & npx --no-install wrangler kv key list --namespace-id $KvNamespace --prefix 'reg:' --remote 2>$null | Out-String | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0) { throw "KV list failed (exit $LASTEXITCODE)" }
  $entries = @()
  foreach ($k in $keys) {
    $value = & npx --no-install wrangler kv key get $k.name --namespace-id $KvNamespace --remote 2>$null | Out-String
    if ($LASTEXITCODE -ne 0) { throw "KV get failed for one entry (exit $LASTEXITCODE)" }
    $entries += [pscustomobject]@{ key = $k.name; value = $value.Trim() }
  }
  ConvertTo-Json -InputObject @($entries) -Depth 4 | Set-Content -Path (Join-Path $dir 'legacy-log.json') -Encoding UTF8

  # 3. Remove backups older than the retention window (only folders this script made)
  $cutoff = (Get-Date).AddDays(-$KeepDays)
  $removed = 0
  Get-ChildItem -Path $Root -Directory | Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' -and $_.CreationTime -lt $cutoff } | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force
    $removed++
  }

  $mb = [math]::Round((Get-Item $sql).Length / 1MB, 2)
  Write-Log "OK  $stamp  database ${mb} MB, $($entries.Count) older-log entries, removed $removed old backup(s)"
  Write-Output "Backup saved to $dir  (database ${mb} MB, $($entries.Count) older-log entries, removed $removed old)"
}
catch {
  Write-Log "FAILED  $stamp  $($_.Exception.Message)"
  # a failed run should not leave a half-written folder that looks like a good backup
  if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Error $_.Exception.Message
  exit 1
}
finally {
  Pop-Location -ErrorAction SilentlyContinue
}
