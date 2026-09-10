param([string]$ValuesPath, [string]$BackupPath, [switch]$Restore)
# Dot-source only defines functions. Tests replace the two environment adapters
# with an in-memory dictionary; they never touch HKCU or machine environment.
function Get-FzUserValue([string]$Name) { [Environment]::GetEnvironmentVariable($Name, 'User') }
function Set-FzUserValue([string]$Name, $Value) { [Environment]::SetEnvironmentVariable($Name, $Value, 'User') }
function Save-FzBackup($Backup, [string]$Path) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $Backup -Depth 8), (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Invoke-FzUserEnvironment($Values, [string]$BackupFile, [bool]$Undo) {
    $backup = @{}
    if (Test-Path -LiteralPath $BackupFile) {
        $saved = Get-Content -Raw -Encoding UTF8 -LiteralPath $BackupFile | ConvertFrom-Json
        foreach ($property in $saved.PSObject.Properties) { $backup[$property.Name] = $property.Value }
    }
    if ($Undo) {
        foreach ($name in @($backup.Keys)) {
            $entry = $backup[$name]
            if ((Get-FzUserValue $name) -ceq $entry.applied) { Set-FzUserValue $name $entry.previous }
            else { Write-Warning "Preserving externally changed user variable $name" }
        }
        return
    }
    $planned = @{}
    foreach ($property in $Values.PSObject.Properties) {
        $name = $property.Name
        if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid environment variable name" }
        $planned[$name] = [string]$property.Value
    }
    # Windows names are case-insensitive. Only one user value is written.
    $planned['NO_PROXY'] = @((($planned['NO_PROXY'] + ',' + (Get-FzUserValue 'NO_PROXY') + ',' + $env:NO_PROXY).Split(',')) | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique) -join ','
    $before = @{}
    foreach ($name in $planned.Keys) {
        $before[$name] = Get-FzUserValue $name
        $previous = if ($backup.ContainsKey($name)) { $backup[$name].previous } else { $before[$name] }
        $backup[$name] = @{ previous = $previous; applied = $planned[$name] }
    }
    # Recovery metadata is durable BEFORE the first environment write.
    Save-FzBackup $backup $BackupFile
    $written = @()
    try {
        foreach ($name in $planned.Keys) {
            if ($before[$name] -cne $planned[$name]) { Set-FzUserValue $name $planned[$name]; $written += $name }
        }
    } catch {
        foreach ($name in $written) { Set-FzUserValue $name $before[$name] }
        throw
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    if (-not $BackupPath) { throw 'BackupPath is required' }
    $values = if ($Restore) { $null } else { Get-Content -Raw -Encoding UTF8 -LiteralPath $ValuesPath | ConvertFrom-Json }
    Invoke-FzUserEnvironment $values $BackupPath ([bool]$Restore)
}