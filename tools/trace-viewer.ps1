param(
    [ValidateSet('Broker', 'Start', 'Stop', 'Status', 'Export')]
    [string]$Action = 'Start',
    [string]$BrokerAddress = '127.0.0.1',
    [int]$ProxyPort = 8080,
    [int]$UiPort = 8081,
    [int]$BootstrapPort = 8082,
    [string]$DataDir,
    [string]$TraceId,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$version = '2.21.0'
$archiveName = "jaeger-$version-windows-amd64.zip"
$archiveSha256 = '197c4b42aba6983b3d9cbca3577a0e14191bcb9431fde1b6661471b6fece39fc'
$executableSha256 = 'd42156cceff213cb24a0595ca5a2de0008de7d09298ddca6e17a464b9ffdaf35'
$downloadUrl = "https://github.com/jaegertracing/jaeger/releases/download/v$version/$archiveName"
$root = Join-Path $env:LOCALAPPDATA 'Friendzone\trace-viewer'
$versionRoot = Join-Path $root "jaeger-$version"
$archive = Join-Path $root $archiveName
$executable = Join-Path $versionRoot "jaeger-$version-windows-amd64\jaeger.exe"
$pidFile = Join-Path $root 'jaeger.pid'
$stdoutLog = Join-Path $root 'jaeger.stdout.log'
$stderrLog = Join-Path $root 'jaeger.stderr.log'

function Get-FzJaegerProcess {
    if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
    $raw = (Get-Content -Raw -LiteralPath $pidFile).Trim()
    if ($raw -notmatch '^\d+$') { return $null }
    $process = Get-Process -Id ([int]$raw) -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    try {
        if ([IO.Path]::GetFullPath($process.Path) -cne [IO.Path]::GetFullPath($executable)) {
            return $null
        }
    } catch { return $null }
    $process
}

function Test-FzTcpPort([string]$Address, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(500)) { return $false }
        $client.EndConnect($connect)
        $true
    } catch { $false } finally { $client.Dispose() }
}

function Wait-FzJaeger([Diagnostics.Process]$Process) {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($Process.HasExited) {
            $detail = if (Test-Path $stderrLog) { Get-Content -Raw $stderrLog } else { '' }
            throw "Jaeger exited during startup. $detail"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 'http://127.0.0.1:16686/'
            if ([int]$response.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw "Jaeger did not make its UI ready. Inspect $stderrLog"
}

function Install-FzJaeger {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'The pinned portable Jaeger build requires 64-bit Windows.'
    }
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    if (-not (Test-Path -LiteralPath $archive)) {
        Write-Host "Downloading portable Jaeger $version (one-time, about 65 MB)..."
        $temporary = "$archive.download"
        Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $temporary
            Move-Item -Force -LiteralPath $temporary -Destination $archive
        } finally {
            Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
        }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -cne $archiveSha256) {
        throw "Downloaded Jaeger archive failed SHA-256 verification. Expected $archiveSha256, got $actual. Remove $archive and retry."
    }
    if (-not (Test-Path -LiteralPath $executable)) {
        Remove-Item -Recurse -Force -LiteralPath $versionRoot -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $versionRoot | Out-Null
        Expand-Archive -LiteralPath $archive -DestinationPath $versionRoot
    }
    if (-not (Test-Path -LiteralPath $executable)) {
        throw "The verified Jaeger archive did not contain $executable"
    }
    $actualExecutable = (Get-FileHash -Algorithm SHA256 -LiteralPath $executable).Hash.ToLowerInvariant()
    if ($actualExecutable -cne $executableSha256) {
        throw "Portable jaeger.exe failed SHA-256 verification. Expected $executableSha256, got $actualExecutable. Remove $versionRoot and retry."
    }
}

function Assert-FzBrokerAddress {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($BrokerAddress, [ref]$parsed)) {
        throw '-BrokerAddress must be one concrete IPv4 address owned by this host.'
    }
    if ($parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.Equals([Net.IPAddress]::Any) -or
        $parsed.Equals([Net.IPAddress]::Broadcast)) {
        throw '-BrokerAddress must be one concrete IPv4 address, not a wildcard or broadcast address.'
    }
    $owned = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
        ForEach-Object { $_.Address.ToString() })
    if ($owned -notcontains $parsed.ToString()) {
        throw "$BrokerAddress is not assigned to this host. Choose the same host address used by --proxy-addr."
    }
}

function Show-FzStatus {
    $process = Get-FzJaegerProcess
    if ($null -eq $process) {
        Write-Host 'Friendzone trace viewer is stopped.'
        return $false
    }
    Write-Host "Friendzone trace viewer is running (PID $($process.Id))."
    Write-Host 'UI:   http://127.0.0.1:16686/'
    Write-Host "Logs: $stderrLog"
    $true
}

switch ($Action) {
    'Broker' {
        Assert-FzBrokerAddress
        & $PSCommandPath -Action Start
        Remove-Item Env:OTEL_SDK_DISABLED -ErrorAction SilentlyContinue
        Remove-Item Env:OTEL_EXPORTER_OTLP_HEADERS -ErrorAction SilentlyContinue
        Remove-Item Env:OTEL_EXPORTER_OTLP_TRACES_HEADERS -ErrorAction SilentlyContinue
        Remove-Item Env:OTEL_EXPORTER_OTLP_COMPRESSION -ErrorAction SilentlyContinue
        Remove-Item Env:OTEL_EXPORTER_OTLP_TRACES_COMPRESSION -ErrorAction SilentlyContinue
        $env:OTEL_SERVICE_NAME = 'friendzone'
        $env:OTEL_TRACES_EXPORTER = 'otlp'
        $env:OTEL_EXPORTER_OTLP_TRACES_PROTOCOL = 'http/protobuf'
        $env:OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = 'http://127.0.0.1:4318/v1/traces'
        $env:FZ_TRACE_RELAY_ENABLED = 'true'
        $arguments = @(
            'run', '--', 'broker',
            '--proxy-addr', "${BrokerAddress}:$ProxyPort",
            '--ui-addr', "127.0.0.1:$UiPort",
            '--bootstrap-addr', "${BrokerAddress}:$BootstrapPort"
        )
        if (-not [string]::IsNullOrWhiteSpace($DataDir)) {
            $arguments += @('--data-dir', [IO.Path]::GetFullPath($DataDir))
        }
        Write-Host ''
        Write-Host 'Starting Friendzone with OTLP trace export enabled. Press Ctrl+C to stop Friendzone.'
        Write-Host 'The trace viewer remains available until you run tools\trace-viewer.cmd Stop.'
        Push-Location (Join-Path $PSScriptRoot '..')
        try {
            & cargo @arguments
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } finally {
            Pop-Location
        }
    }
    'Start' {
        Install-FzJaeger
        if (Show-FzStatus) { return }
        foreach ($endpoint in @(@('127.0.0.1', 16686), @('127.0.0.1', 4318))) {
            if (Test-FzTcpPort $endpoint[0] $endpoint[1]) {
                throw "TCP $($endpoint[0]):$($endpoint[1]) is already in use. Stop that listener or choose another host address."
            }
        }
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        Remove-Item -Force -LiteralPath $stdoutLog, $stderrLog -ErrorAction SilentlyContinue
        $arguments = @(
            '--set=receivers.otlp.protocols.http.endpoint=127.0.0.1:4318',
            '--set=receivers.otlp.protocols.grpc.endpoint=127.0.0.1:4317',
            '--set=extensions.jaeger_query.http.endpoint=127.0.0.1:16686',
            '--set=extensions.jaeger_query.grpc.endpoint=127.0.0.1:16685',
            '--set=extensions.jaeger_storage.backends.some_storage.memory.max_traces=10000'
        )
        $process = Start-Process -FilePath $executable -ArgumentList $arguments `
            -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog `
            -WindowStyle Hidden -PassThru
        Set-Content -NoNewline -LiteralPath $pidFile -Value $process.Id
        try { Wait-FzJaeger $process } catch {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Remove-Item -Force -LiteralPath $pidFile -ErrorAction SilentlyContinue
            throw
        }
        Write-Host ''
        Write-Host "Jaeger $version is ready. It receives Friendzone traces in memory; stopping it clears them."
        Write-Host 'Trace UI: http://127.0.0.1:16686/'
        Write-Host 'OTLP:     http://127.0.0.1:4318/v1/traces'
        Write-Host ''
        Write-Host 'Start only runs Jaeger. Prefer the Broker action to enable Friendzone and the guest relay together.'
        Write-Host 'For manual host-only Friendzone export, set:'
        Write-Host "`$env:OTEL_SERVICE_NAME = 'friendzone'"
        Write-Host "`$env:OTEL_EXPORTER_OTLP_TRACES_PROTOCOL = 'http/protobuf'"
        Write-Host "`$env:OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = 'http://127.0.0.1:4318/v1/traces'"
        Write-Host 'cargo run -- broker --proxy-addr HOST_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_IP:8082'
    }
    'Stop' {
        $process = Get-FzJaegerProcess
        if ($null -ne $process) {
            Stop-Process -Id $process.Id -Force
            Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
        }
        Remove-Item -Force -LiteralPath $pidFile -ErrorAction SilentlyContinue
        Write-Host 'Friendzone trace viewer stopped. In-memory traces were discarded.'
    }
    'Status' { [void](Show-FzStatus) }
    'Export' {
        if ($TraceId -notmatch '^[0-9a-fA-F]{32}$') {
            throw 'Export requires -TraceId followed by the 32-character trace ID shown in Jaeger.'
        }
        if (-not (Show-FzStatus)) { throw 'Start the trace viewer before exporting.' }
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = Join-Path (Get-Location) "friendzone-trace-$($TraceId.ToLowerInvariant()).json"
        }
        $destination = [IO.Path]::GetFullPath($OutputPath)
        Invoke-WebRequest -UseBasicParsing `
            -Uri "http://127.0.0.1:16686/api/v3/traces/$TraceId" -OutFile $destination
        Write-Host "Saved OTLP-based Jaeger trace JSON to $destination"
    }
}