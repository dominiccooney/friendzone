# Function parameters keep test writes inside a temporary home. Tests replace
# Get/Set-FzUserValue before calling this function; main is not run by tests.
function Quote-FzPowerShell([string]$Value) {
    "'" + [regex]::Replace($Value, "['\u2018\u2019\u201a\u201b]", '$0$0') + "'"
}
function Write-FzFile([string]$Path, [string]$Text) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($temporary,$Text,(New-Object Text.UTF8Encoding($Path.EndsWith('.ps1'))))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Set-FzProperty($Object, [string]$Name, $Value) { $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force }
function Get-FzProviderJson([string]$Path, [string]$Fake) {
    $root=if(Test-Path -LiteralPath $Path){Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json}else{[pscustomobject]@{}}
    if ($root -isnot [pscustomobject] -or ($null -ne $root.version -and $root.version -ne 1)) { throw 'Unsupported Cline providers.json; configuration unchanged' }
    Set-FzProperty $root version 1
    if ($null -eq $root.modes) {Set-FzProperty $root modes ([pscustomobject]@{})}
    if ($null -eq $root.providers) {Set-FzProperty $root providers ([pscustomobject]@{})}
    if ($root.providers -isnot [pscustomobject]) {throw 'Invalid Cline provider map'}
    if ($null -eq $root.providers.cline) {Set-FzProperty $root.providers cline ([pscustomobject]@{settings=[pscustomobject]@{provider='cline'}})}
    $entry=$root.providers.cline
    if ($entry -isnot [pscustomobject] -or $entry.settings -isnot [pscustomobject]) {throw 'Invalid Cline provider settings'}
    Set-FzProperty $entry.settings apiKey $Fake
    $entry.settings.PSObject.Properties.Remove('auth')
    Set-FzProperty $entry tokenSource 'manual'
    Set-FzProperty $entry updatedAt ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
    if ($null -eq $root.lastUsedProvider) {Set-FzProperty $root lastUsedProvider 'cline'}
    ConvertTo-Json -InputObject $root -Depth 100
}
function Invoke-FzConfigure($Data, [string]$HomeDirectory, [string]$ConfigDirectory) {
    $cert=Join-Path $ConfigDirectory 'friendzone-ca.pem'
    $envFile=Join-Path $ConfigDirectory 'friendzone-env.ps1'
    $origin=[Uri]$Data.broker
    $builder=New-Object UriBuilder('http',$origin.Host,[int]$Data.proxy_port)
    $builder.UserName=$Data.container; $builder.Password='x'
    $proxy=$builder.Uri.AbsoluteUri.TrimEnd('/')
    $values=@{FZ_HOST=$origin.DnsSafeHost;FZ_BROKER=$Data.broker;HTTP_PROXY=$proxy;HTTPS_PROXY=$proxy}
    foreach($key in @('NODE_EXTRA_CA_CERTS','REQUESTS_CA_BUNDLE','SSL_CERT_FILE','GIT_SSL_CAINFO','GIT_PROXY_SSL_CAINFO')) {$values[$key]=$cert}
    foreach($property in $Data.fakes.PSObject.Properties) {$values[$property.Name]=[string]$property.Value}
    $values.NO_PROXY=$origin.DnsSafeHost+',localhost,127.0.0.1,::1,[::1]'
    $lines=@('# Friendzone guest environment')
    foreach($key in $values.Keys) {
        if ($key -ne 'NO_PROXY') {$lines += '[Environment]::SetEnvironmentVariable('+(Quote-FzPowerShell $key)+','+(Quote-FzPowerShell $values[$key])+",'Process')"}
    }
    $lines += '$env:NO_PROXY = @(('+ (Quote-FzPowerShell $values.NO_PROXY) + ' + '','' + $env:NO_PROXY).Split('','') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique) -join '','''
    $provider=Join-Path $HomeDirectory '.cline/data/settings/providers.json'
    $providerJson=if($Data.fakes.CLINE_API_KEY){Get-FzProviderJson $provider $Data.fakes.CLINE_API_KEY}else{$null}
    # Validate/prepare JSON before writes; backup first, never overwrite a backup.
    if ($providerJson -and (Test-Path -LiteralPath $provider) -and -not (Test-Path -LiteralPath ($provider+'.friendzone-backup'))) {Copy-Item -LiteralPath $provider -Destination ($provider+'.friendzone-backup')}
    Write-FzFile $cert $Data.ca
    Write-FzFile $envFile ($lines -join "`n")
    if($providerJson){Write-FzFile $provider $providerJson}
    $valuesPath=Join-Path $ConfigDirectory 'user-environment.json'
    Write-FzFile $valuesPath (ConvertTo-Json -InputObject $values)
    Invoke-FzUserEnvironment ([pscustomobject]$values) (Join-Path $ConfigDirectory 'user-environment-backup.json') $false
    return $envFile
}
function Start-FzGuestSetup($Data) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {throw 'Select the Linux script on non-Windows guests'}
    if (-not $Data.container) {$Data.container=[Environment]::MachineName}
    if ($Data.container.Contains(':') -or [Text.Encoding]::UTF8.GetByteCount($Data.container) -gt 128) {throw 'Invalid guest name'}
    Add-Type -AssemblyName System.Net.Http
    $handler=New-Object Net.Http.HttpClientHandler
    $handler.UseProxy=$false; $handler.AllowAutoRedirect=$false
    $client=New-Object Net.Http.HttpClient($handler); $client.Timeout=[TimeSpan]::FromSeconds(10)
    try {
        $response=$client.GetAsync($Data.broker+'/bootstrap/hello?container='+[Uri]::EscapeDataString($Data.container)).GetAwaiter().GetResult()
        if([int]$response.StatusCode -ne 200){throw 'Broker could not register this guest; configuration unchanged'}
        $approval=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        $config=Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'friendzone'
        Write-FzFile (Join-Path $config 'persist-environment.ps1') ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Data.persistence)))
        $envFile=Invoke-FzConfigure $Data ([Environment]::GetFolderPath('UserProfile')) $config
        . $envFile
        Write-Host ('Configured guest '+$Data.container+'. '+$(if($approval.approved){'Approved.'}else{'Approve it in the host Inbox.'}))
        Write-Host 'Restart guest Cline from this terminal. Sign out/in to refresh other Windows launchers.'
    } finally {$client.Dispose();$handler.Dispose()}
}