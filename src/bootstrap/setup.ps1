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
function Add-FzGitSchannelTrust($Values) {
    # Git for Windows defaults to Schannel, which intentionally ignores
    # GIT_SSL_CAINFO unless this Git option is enabled. Use one exact managed
    # environment entry instead of changing Git config or the Windows root store.
    # Never copy/overwrite arbitrary indexed entries: they may contain secrets.
    $userCount=Get-FzUserValue 'GIT_CONFIG_COUNT'
    $userKey=Get-FzUserValue 'GIT_CONFIG_KEY_0'
    $userValue=Get-FzUserValue 'GIT_CONFIG_VALUE_0'
    $managed=$userCount -ceq '1' -and $userKey -ceq 'http.schannelUseSSLCAInfo' -and $userValue -ceq 'true'
    $userConflict=(-not [string]::IsNullOrEmpty($userCount) -or $null -ne $userKey -or $null -ne $userValue) -and -not $managed
    $processManaged=$env:GIT_CONFIG_COUNT -ceq '1' -and $env:GIT_CONFIG_KEY_0 -ceq 'http.schannelUseSSLCAInfo' -and $env:GIT_CONFIG_VALUE_0 -ceq 'true'
    $processConflict=(-not [string]::IsNullOrEmpty($env:GIT_CONFIG_COUNT) -or $null -ne $env:GIT_CONFIG_KEY_0 -or $null -ne $env:GIT_CONFIG_VALUE_0) -and -not $processManaged
    if($userConflict -or $processConflict){throw 'Existing GIT_CONFIG_* environment entries conflict with Friendzone Git trust; configuration unchanged'}
    $Values.GIT_CONFIG_COUNT='1'
    $Values.GIT_CONFIG_KEY_0='http.schannelUseSSLCAInfo'
    $Values.GIT_CONFIG_VALUE_0='true'
}
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
function Invoke-FzConfigure($Data, [string]$HomeDirectory, [string]$ConfigDirectory, [string]$ClineDirectory) {
    $cert=Join-Path $ConfigDirectory 'friendzone-ca.pem'
    $envFile=Join-Path $ConfigDirectory 'friendzone-env.ps1'
    $origin=[Uri]$Data.broker
    $builder=New-Object UriBuilder('http',$origin.Host,[int]$Data.proxy_port)
    $proxy=$builder.Uri.AbsoluteUri.TrimEnd('/')
    $values=@{FZ_HOST=$origin.DnsSafeHost;FZ_BROKER=$Data.broker;HTTP_PROXY=$proxy;HTTPS_PROXY=$proxy}
    foreach($key in @('NODE_EXTRA_CA_CERTS','REQUESTS_CA_BUNDLE','SSL_CERT_FILE','GIT_SSL_CAINFO','GIT_PROXY_SSL_CAINFO','CARGO_HTTP_CAINFO')) {$values[$key]=$cert}
    # Friendzone's dynamic leaf certificates have no public CRL/OCSP endpoint.
    # Cargo/Schannel must skip revocation lookup while retaining CA/host checks.
    $values.CARGO_HTTP_CHECK_REVOKE='false'
    foreach($property in $Data.fakes.PSObject.Properties) {$values[$property.Name]=[string]$property.Value}
    $values.NO_PROXY=$origin.DnsSafeHost+',localhost,127.0.0.1,::1,[::1]'
    Add-FzGitSchannelTrust $values
    $lines=@('# Friendzone guest environment')
    $oldValuesPath=Join-Path $ConfigDirectory 'user-environment.json'
    $legacyIdleMarker=Join-Path $ConfigDirectory 'remove-legacy-cline-idle-timeout'
    $removeLegacyIdle=(Test-Path -LiteralPath $legacyIdleMarker)
    $legacyIdlePrevious=$null
    $backupPath=Join-Path $ConfigDirectory 'user-environment-backup.json'
    if(Test-Path -LiteralPath $oldValuesPath){
        try{$oldValues=Get-Content -Raw -LiteralPath $oldValuesPath|ConvertFrom-Json;$removeLegacyIdle=$removeLegacyIdle -or ($oldValues.CLINE_PLUGIN_IDLE_TIMEOUT_MS -ceq '90000000')}catch{}
    }
    if($removeLegacyIdle -and (Test-Path -LiteralPath $legacyIdleMarker)){
        try{$legacyIdlePrevious=(Get-Content -Raw -LiteralPath $legacyIdleMarker|ConvertFrom-Json).previous}catch{}
    }elseif($removeLegacyIdle -and (Test-Path -LiteralPath $backupPath)){
        try{$saved=Get-Content -Raw -LiteralPath $backupPath|ConvertFrom-Json;$property=$saved.PSObject.Properties['CLINE_PLUGIN_IDLE_TIMEOUT_MS'];if($property.Value.applied -ceq '90000000'){$legacyIdlePrevious=$property.Value.previous}}catch{}
    }
    foreach($key in $values.Keys) {
        if ($key -ne 'NO_PROXY') {$lines += '[Environment]::SetEnvironmentVariable('+(Quote-FzPowerShell $key)+','+(Quote-FzPowerShell $values[$key])+",'Process')"}
    }
    $lines += '$env:NO_PROXY = @(('+ (Quote-FzPowerShell $values.NO_PROXY) + ' + '','' + $env:NO_PROXY).Split('','') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique) -join '','''
    if($removeLegacyIdle){
        if($null -eq $legacyIdlePrevious){$restoreIdle='Remove-Item Env:CLINE_PLUGIN_IDLE_TIMEOUT_MS'}
        else{$restoreIdle="[Environment]::SetEnvironmentVariable('CLINE_PLUGIN_IDLE_TIMEOUT_MS',"+(Quote-FzPowerShell ([string]$legacyIdlePrevious))+",'Process')"}
        $markerLiteral=Quote-FzPowerShell $legacyIdleMarker
        $lines += "if (Test-Path -LiteralPath $markerLiteral) { if (`$env:CLINE_PLUGIN_IDLE_TIMEOUT_MS -ceq '90000000') { $restoreIdle }; Remove-Item -Force -LiteralPath $markerLiteral }"
    }
    $provider=Join-Path $HomeDirectory '.cline/data/settings/providers.json'
    $providerJson=if($Data.fakes.CLINE_API_KEY){Get-FzProviderJson $provider $Data.fakes.CLINE_API_KEY}else{$null}
    if (-not $ClineDirectory) {$ClineDirectory=Join-Path $HomeDirectory '.cline'}
    $pluginPath=Join-Path $ClineDirectory 'plugins/friendzone.js'
    $pluginConfig=Join-Path $ClineDirectory 'friendzone.json'
    $plugin=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Data.plugin))
    if(-not $plugin.StartsWith('// Friendzone managed plugin v1.')){throw 'Invalid Friendzone plugin payload'}
    if((Test-Path -LiteralPath $pluginPath) -and -not ([IO.File]::ReadAllText($pluginPath).StartsWith('// Friendzone managed plugin v1.'))){throw 'Unmanaged friendzone.js exists; configuration unchanged'}
    if(Test-Path -LiteralPath $pluginConfig){$old=Get-Content -Raw -LiteralPath $pluginConfig | ConvertFrom-Json;if($old.managed_by -ne 'friendzone'){throw 'Unmanaged Friendzone plugin configuration; configuration unchanged'}}
    $pluginJson=ConvertTo-Json -InputObject @{managed_by='friendzone';broker=$Data.broker;container=$Data.container}
    # Validate/prepare JSON before writes; backup first, never overwrite a backup.
    if ($providerJson -and (Test-Path -LiteralPath $provider) -and -not (Test-Path -LiteralPath ($provider+'.friendzone-backup'))) {Copy-Item -LiteralPath $provider -Destination ($provider+'.friendzone-backup')}
    foreach($path in @($pluginPath,$pluginConfig)){if((Test-Path -LiteralPath $path) -and -not (Test-Path -LiteralPath ($path+'.backup'))){Copy-Item -LiteralPath $path -Destination ($path+'.backup')}}
    Write-FzFile $pluginPath $plugin
    Write-FzFile $pluginConfig $pluginJson
    if($removeLegacyIdle){Write-FzFile $legacyIdleMarker (ConvertTo-Json -InputObject @{previous=$legacyIdlePrevious})}
    Write-FzFile $cert $Data.ca
    Write-FzFile $envFile ($lines -join "`n")
    if($providerJson){Write-FzFile $provider $providerJson}
    $valuesPath=$oldValuesPath
    Write-FzFile $valuesPath (ConvertTo-Json -InputObject $values)
    Invoke-FzUserEnvironment ([pscustomobject]$values) $backupPath $false
    if($removeLegacyIdle){Remove-FzManagedUserValue 'CLINE_PLUGIN_IDLE_TIMEOUT_MS' '90000000' $backupPath}
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
        $envFile=Invoke-FzConfigure $Data ([Environment]::GetFolderPath('UserProfile')) $config $env:CLINE_DIR
        . $envFile
        Write-Host ('Configured guest '+$Data.container+'. '+$(if($approval.approved){'Approved.'}else{'Use Approve + pin IP in the host Inbox.'}))
        Write-Host 'Installed the Friendzone Cline plugin for async GraphQL, reviewed Git publication, and session updates.'
        Write-Host 'Restart guest Cline from this terminal. Sign out/in to refresh other Windows launchers.'
    } finally {$client.Dispose();$handler.Dispose()}
}