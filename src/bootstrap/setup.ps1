# Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. Run in the guest.
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This script is for Windows guests.' }
$architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($architecture) { 'AMD64' { 'x86_64' } 'ARM64' { 'aarch64' } default { throw 'Supported guest architectures: AMD64, ARM64.' } }
if (-not $container) { $container = [Environment]::MachineName }
$config = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'friendzone'
[IO.Directory]::CreateDirectory($config) | Out-Null
$staging = Join-Path $config ('bootstrap-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
Add-Type -AssemblyName System.Net.Http
$handler = New-Object Net.Http.HttpClientHandler
$handler.UseProxy = $false
$handler.AllowAutoRedirect = $false
$client = New-Object Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(120)
try {
    Write-Host "Downloading Windows $arch fz from $broker (trusted host only)..."
    $response = $client.GetAsync("$broker/bootstrap/fz?target=windows-$arch").GetAwaiter().GetResult()
    if ([int]$response.StatusCode -ne 200) { throw ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() + ' No guest configuration was changed.') }
    $binary = Join-Path $staging 'fz.exe'
    [IO.File]::WriteAllBytes($binary, $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult())
    & $binary --version
    if ($LASTEXITCODE -ne 0) { throw 'Guest binary could not run. Profiles and user environment unchanged.' }
    Write-Host 'Configuring this GUEST user, including persistent user environment. Stop guest Cline first.'
    & $binary setup --broker $broker --container $container --output (Join-Path $config 'friendzone-ca.pem') --shell powershell --persist-profile
    if ($LASTEXITCODE -ne 0) { throw 'fz setup failed. Inspect its output; do not assume persistence succeeded.' }
    Move-Item -LiteralPath $binary -Destination (Join-Path $config 'fz.exe') -Force
    . (Join-Path $config 'friendzone-env.ps1')
    Write-Host 'Guest environment active in this PowerShell process and saved to user environment.'
    Write-Host 'Restart agents. Sign out/in to refresh GUI launchers; child processes launched here inherit it now.'
    Write-Host 'No machine environment, firewall or system trust store was changed. Approve the guest in host Inbox.'
    Write-Host "Rollback user environment: & '$config\persist-environment.ps1' -BackupPath '$config\user-environment-backup.json' -Restore"
} finally {
    $client.Dispose()
    $handler.Dispose()
    Remove-Item -LiteralPath $staging -Recurse -Force
}