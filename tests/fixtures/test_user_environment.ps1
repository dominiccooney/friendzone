param([string]$Implementation, [string]$TemporaryDirectory, [string]$BootstrapScript, [string]$BootstrapCommand, [string]$RotationCertificate)
$ErrorActionPreference = 'Stop'
# Loading a reviewed test helper as a script block keeps this test independent
# of host script-file policy. No Set-ExecutionPolicy or -ExecutionPolicy flags.
. ([scriptblock]::Create([IO.File]::ReadAllText($Implementation)))
# Replace production adapters BEFORE invoking persistence. Never access User
# or Machine environment, even on failure or rollback branches.
$script:fakeUser = @{ HTTP_PROXY = 'previous-proxy'; NO_PROXY = 'existing.example'; CLINE_API_KEY = 'old-fake' }
$script:writes = @()
function Get-FzUserValue([string]$Name) { $script:fakeUser[$Name] }
function Set-FzUserValue([string]$Name, $Value) { $script:writes += $Name; $script:fakeUser[$Name] = $Value }
function Copy-FzTestSetting($Setting) { ConvertFrom-Json (ConvertTo-Json -Depth 8 -InputObject $Setting) }
$script:fakeInternet = @{
    ProxyEnable = @{exists=$true;kind='DWord';value=0}
    ProxyServer = @{exists=$true;kind='ExpandString';value='%OLD_PROXY%:8123'}
    ProxyOverride = @{exists=$true;kind='String';value='existing.test;<local>'}
}
$script:internetWrites=@();$script:internetNotifications=0
function Get-FzInternetSetting([string]$Name) { Copy-FzTestSetting $script:fakeInternet[$Name] }
function Set-FzInternetSetting([string]$Name, $Setting) {$script:internetWrites+=$Name;$script:fakeInternet[$Name]=Copy-FzTestSetting $Setting}
function Notify-FzInternetSettings {$script:internetNotifications++}
$script:fakeRoots=@{}
function Get-FzTrustedCertificate([string]$Thumbprint){if($script:fakeRoots.ContainsKey($Thumbprint)){return @{present=$true;der=$script:fakeRoots[$Thumbprint]}};return @{present=$false;der=$null}}
function Add-FzTrustedCertificate([string]$Der){$certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Der));try{$script:fakeRoots[$certificate.Thumbprint.ToUpperInvariant()]=$Der}finally{$certificate.Dispose()}}
function Remove-FzTrustedCertificate([string]$Thumbprint,[string]$ExpectedDer){if($script:fakeRoots.ContainsKey($Thumbprint)-and $script:fakeRoots[$Thumbprint]-cne$ExpectedDer){throw 'mock root changed'};$script:fakeRoots.Remove($Thumbprint)}
$systemBackup=Join-Path $TemporaryDirectory 'system-proxy-backup.json'
$transaction=Invoke-FzSystemProxy '192.0.2.1' 8080 $systemBackup $false
if($script:fakeInternet.ProxyEnable.kind -cne 'DWord' -or $script:fakeInternet.ProxyEnable.value -ne 1){throw 'system proxy was not enabled as DWORD'}
if($script:fakeInternet.ProxyServer.value -cne 'http=192.0.2.1:8080;https=192.0.2.1:8080'){throw 'wrong credential-free system proxy mapping'}
foreach($bypass in @('existing.test','<local>','192.0.2.1','localhost','127.0.0.1','::1','[::1]')){if(-not @($script:fakeInternet.ProxyOverride.value.Split(';')).Contains($bypass)){throw "system proxy bypass missing $bypass"}}
$savedSystem=Get-Content -Raw -Encoding UTF8 -LiteralPath $systemBackup|ConvertFrom-Json
if($savedSystem.settings.ProxyServer.previous.kind -cne 'ExpandString' -or $savedSystem.settings.ProxyServer.previous.value -cne '%OLD_PROXY%:8123'){throw 'typed original proxy was not preserved'}
$beforeSystemWrites=$script:internetWrites.Count;$beforeNotifications=$script:internetNotifications
$null=Invoke-FzSystemProxy '192.0.2.1' 8080 $systemBackup $false
if($script:internetWrites.Count -ne $beforeSystemWrites -or $script:internetNotifications -ne $beforeNotifications){throw 'system proxy rerun was not idempotent'}
$script:fakeInternet.ProxyServer=@{exists=$true;kind='String';value='externally-edited:9000'}
Invoke-FzSystemProxy $null 0 $systemBackup $true
if($script:fakeInternet.ProxyServer.value -cne 'externally-edited:9000'){throw 'external system proxy edit was overwritten'}
if($script:fakeInternet.ProxyEnable.value -ne 0 -or $script:fakeInternet.ProxyOverride.value -cne 'existing.test;<local>'){throw 'owned system proxy values were not restored'}

# A failed registry write restores completed writes and the pre-transaction backup.
$script:fakeInternet=@{ProxyEnable=@{exists=$true;kind='DWord';value=0};ProxyServer=@{exists=$false;kind=$null;value=$null};ProxyOverride=@{exists=$false;kind=$null;value=$null}}
$failureBackup=Join-Path $TemporaryDirectory 'failed-system-proxy.json'
$script:systemSetCalls=0
function Set-FzInternetSetting([string]$Name, $Setting){$script:systemSetCalls++;if($script:systemSetCalls -eq 2){throw 'simulated system proxy failure'};$script:fakeInternet[$Name]=Copy-FzTestSetting $Setting}
try{Invoke-FzSystemProxy '192.0.2.1' 8080 $failureBackup $false;throw 'expected system proxy failure'}catch{if($_.Exception.Message -eq 'expected system proxy failure'){throw}}
if($script:fakeInternet.ProxyEnable.value -ne 0 -or (Test-Path -LiteralPath $failureBackup)){throw 'partial system proxy transaction was not rolled back'}

# Environment failure after successful system-proxy writes rolls both stores back.
$script:fakeInternet=@{ProxyEnable=@{exists=$true;kind='DWord';value=0};ProxyServer=@{exists=$true;kind='String';value='old:8000'};ProxyOverride=@{exists=$true;kind='String';value='existing.test'}}
$compositeSystemBackup=Join-Path $TemporaryDirectory 'composite-system.json'
$compositeEnvironmentBackup=Join-Path $TemporaryDirectory 'composite-environment.json'
$compositeTrustState=Join-Path $TemporaryDirectory 'composite-trust.json'
$compositeCertificate=Join-Path $TemporaryDirectory 'composite-ca.pem'
[IO.File]::WriteAllText($compositeCertificate,'mock certificate identity is supplied by the test adapter')
function Read-FzCertificateIdentity([string]$Path){@{thumbprint=('A'*40);der='ZmFrZQ=='}}
function Set-FzInternetSetting([string]$Name, $Setting){$script:fakeInternet[$Name]=Copy-FzTestSetting $Setting}
function Set-FzUserValue([string]$Name, $Value){throw 'simulated environment failure'}
$compositeValues=[pscustomobject]@{HTTP_PROXY='http://192.0.2.1:8080';NO_PROXY='192.0.2.1'}
try{Invoke-FzWindowsPersistence $compositeValues $compositeEnvironmentBackup $compositeSystemBackup $compositeCertificate $compositeTrustState $false;throw 'expected composite failure'}catch{if($_.Exception.Message -eq 'expected composite failure'){throw}}
if($script:fakeInternet.ProxyEnable.value -ne 0 -or $script:fakeInternet.ProxyServer.value -cne 'old:8000' -or $script:fakeInternet.ProxyOverride.value -cne 'existing.test'){throw 'system proxy survived failed environment transaction'}
if($script:fakeRoots.Count -or (Test-Path -LiteralPath $compositeTrustState) -or (Test-Path -LiteralPath $compositeSystemBackup) -or (Test-Path -LiteralPath $compositeEnvironmentBackup)){throw 'failed composite transaction retained trust or recovery metadata'}
function Set-FzUserValue([string]$Name, $Value) { $script:writes += $Name; $script:fakeUser[$Name] = $Value }
$values = [pscustomobject]@{ HTTP_PROXY = 'http://192.0.2.1:8080'; NO_PROXY = '192.0.2.1,localhost,127.0.0.1'; CLINE_API_KEY = 'new-fake' }
$backup = Join-Path $TemporaryDirectory 'backup.json'
Invoke-FzUserEnvironment $values $backup $false
if ($script:fakeUser.HTTP_PROXY -cne $values.HTTP_PROXY) { throw 'proxy not persisted to mock' }
if ($script:fakeUser.NO_PROXY -notmatch 'existing.example') { throw 'existing exclusion lost' }
$before = $script:writes.Count
Invoke-FzUserEnvironment $values $backup $false
if ($script:writes.Count -ne $before) { throw 'rerun wrote unchanged values' }
$script:fakeUser.CLINE_API_KEY = 'external-edit'
Invoke-FzUserEnvironment $null $backup $true
if ($script:fakeUser.HTTP_PROXY -cne 'previous-proxy') { throw 'original proxy not restored' }
if ($script:fakeUser.CLINE_API_KEY -cne 'external-edit') { throw 'external edit overwritten by rollback' }
if ($script:fakeUser.NO_PROXY -cne 'existing.example') { throw 'original exclusion not restored' }
$before = $script:writes.Count
try { Invoke-FzUserEnvironment $values (Join-Path $TemporaryDirectory 'missing/backup.json') $false; throw 'expected backup failure' }
catch { if ($_.Exception.Message -eq 'expected backup failure') { throw } }
if ($script:writes.Count -ne $before) { throw 'wrote values before backup succeeded' }

# Failure after a real (mocked) write must restore the pre-transaction values.
$script:mockCalls = 0
$script:failedOnce = $false
$originalProxy = $script:fakeUser.HTTP_PROXY
$originalExclusions = $script:fakeUser.NO_PROXY
$originalKey = $script:fakeUser.CLINE_API_KEY
function Set-FzUserValue([string]$Name, $Value) {
    $script:mockCalls++
    if ($script:mockCalls -eq 2 -and -not $script:failedOnce) { $script:failedOnce=$true; throw 'simulated registry failure' }
    $script:fakeUser[$Name]=$Value
}
try { Invoke-FzUserEnvironment $values $backup $false; throw 'expected write failure' }
catch { if ($_.Exception.Message -eq 'expected write failure') { throw } }
if ($script:fakeUser.HTTP_PROXY -cne $originalProxy -or $script:fakeUser.NO_PROXY -cne $originalExclusions -or $script:fakeUser.CLINE_API_KEY -cne $originalKey) { throw 'partial write was not rolled back' }

# Native environment activation affects ONLY this disposable child process.
# Load the actual self-contained script with main disabled, mock persistence,
# then execute its configuration function against explicit temporary paths.
. ([scriptblock]::Create([IO.File]::ReadAllText($BootstrapScript).TrimStart([char]0xfeff)))
# Registration errors must identify the exact endpoint and preserve the broker's
# actionable explanation instead of collapsing every failure to one generic line.
$registrationData=[pscustomobject]@{broker='http://192.0.2.1:9082';container='requested'}
function Invoke-FzRegistrationRequest([string]$Url){[pscustomobject]@{status=409;reason='Conflict';body='{"error":"source address is ambiguous","action":"Fix duplicate pins in host Settings."}'}}
try{Invoke-FzGuestRegistration $registrationData;throw 'expected registration conflict'}catch{
    if($_.Exception.Message-eq'expected registration conflict'){throw}
    foreach($text in @('http://192.0.2.1:9082/bootstrap/hello?container=requested','HTTP 409','source address is ambiguous','Fix duplicate pins in host Settings.','No guest settings were changed')){if(-not$_.Exception.Message.Contains($text)){throw "registration error omitted $text"}}
}
function Invoke-FzRegistrationRequest([string]$Url){throw 'simulated route failure'}
try{Invoke-FzGuestRegistration $registrationData;throw 'expected registration transport failure'}catch{
    if($_.Exception.Message-eq'expected registration transport failure'){throw}
    foreach($text in @('Could not contact Friendzone','simulated route failure','Verify the broker bootstrap address and VM network route')){if(-not$_.Exception.Message.Contains($text)){throw "transport error omitted $text"}}
}
function Invoke-FzRegistrationRequest([string]$Url){[pscustomobject]@{status=200;reason='OK';body='{"approved":true,"container":"pinned-owner","canonicalized":true}'}}
$registration=Invoke-FzGuestRegistration $registrationData
if($registration.container-cne'pinned-owner'-or-not$registration.approved){throw 'canonical registration response was not accepted'}
function Invoke-FzRegistrationRequest([string]$Url){[pscustomobject]@{status=200;reason='OK';body='{"approved":true,"container":"bad:name"}'}}
try{Invoke-FzGuestRegistration $registrationData;throw 'expected invalid canonical name'}catch{if($_.Exception.Message-eq'expected invalid canonical name'){throw};if(-not$_.Exception.Message.Contains('did not identify a valid guest')){throw 'invalid canonical guest error was not actionable'}}
function Get-FzUserValue([string]$Name) { $script:fakeUser[$Name] }
function Set-FzUserValue([string]$Name, $Value) { $script:fakeUser[$Name]=$Value }
function Get-FzInternetSetting([string]$Name) { Copy-FzTestSetting $script:fakeInternet[$Name] }
function Set-FzInternetSetting([string]$Name, $Setting) {$script:internetWrites+=$Name;$script:fakeInternet[$Name]=Copy-FzTestSetting $Setting}
function Notify-FzInternetSettings {$script:internetNotifications++}
$script:fakeInternet=@{ProxyEnable=@{exists=$true;kind='DWord';value=0};ProxyServer=@{exists=$true;kind='String';value='old:8000'};ProxyOverride=@{exists=$true;kind='String';value='existing.test'}}
$script:fakeRoots=@{}
function Get-FzTrustedCertificate([string]$Thumbprint){if($script:fakeRoots.ContainsKey($Thumbprint)){return @{present=$true;der=$script:fakeRoots[$Thumbprint]}};return @{present=$false;der=$null}}
function Add-FzTrustedCertificate([string]$Der){$certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Der));try{$script:fakeRoots[$certificate.Thumbprint.ToUpperInvariant()]=$Der}finally{$certificate.Dispose()}}
function Remove-FzTrustedCertificate([string]$Thumbprint,[string]$ExpectedDer){if($script:fakeRoots.ContainsKey($Thumbprint)-and $script:fakeRoots[$Thumbprint]-cne$ExpectedDer){throw 'mock root changed'};$script:fakeRoots.Remove($Thumbprint)}
$homeDir=Join-Path $TemporaryDirectory ("Guest space ' " + [char]0x00fc)
$configDir=Join-Path $TemporaryDirectory "Config space '"
$provider=Join-Path $homeDir '.cline/data/settings/providers.json'
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($provider)) | Out-Null
[IO.File]::WriteAllText($provider,'{"version":1,"lastUsedProvider":"other","modes":{},"providers":{"cline":{"settings":{"provider":"cline","model":"keep","auth":{"refreshToken":"stale"}}},"other":{"settings":{"key":"preserved"}}}}')
$data=[pscustomobject]@{broker='http://192.0.2.1:9082';container='guest';proxy_port=9080;ca='';cline_oauth=$false;fakes=[pscustomobject]@{CLINE_API_KEY="fake'`$(not-a-command)"}}
# Extract the exact payload emitted by the Rust bootstrap endpoint. Do not
# substitute the source file here: that previously missed packaging failures.
$bootstrapText=[IO.File]::ReadAllText($BootstrapScript)
$payloadMatch=[regex]::Match($bootstrapText, '\$data=\[Text.Encoding\]::UTF8.GetString\(\[Convert\]::FromBase64String\(''([A-Za-z0-9+/=]+)''\)\)')
if(-not $payloadMatch.Success){throw 'Could not find generated bootstrap payload'}
$payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadMatch.Groups[1].Value)) | ConvertFrom-Json
$data | Add-Member -NotePropertyName plugin -NotePropertyValue $payload.plugin
$data.ca=[string]$payload.ca
$data.cline_oauth=$payload.cline_oauth -eq $true
$data | Add-Member -NotePropertyName git_credential_config -NotePropertyValue ([string]$payload.git_credential_config)
$data.fakes | Add-Member -NotePropertyName GITHUB_TOKEN -NotePropertyValue ([string]$payload.fakes.GITHUB_TOKEN)
# Model ebfa82b's exact managed value/metadata, then verify this upgrade removes
# it without inventing a general environment cleanup policy.
$legacyBackup=Join-Path $configDir 'user-environment-backup.json'
[IO.Directory]::CreateDirectory($configDir)|Out-Null
$script:fakeUser.CLINE_PLUGIN_IDLE_TIMEOUT_MS='90000000'
[IO.File]::WriteAllText((Join-Path $configDir 'user-environment.json'),'{"CLINE_PLUGIN_IDLE_TIMEOUT_MS":"90000000"}')
[IO.File]::WriteAllText($legacyBackup,'{"CLINE_PLUGIN_IDLE_TIMEOUT_MS":{"previous":"user-original","applied":"90000000"}}')
$env:CLINE_PLUGIN_IDLE_TIMEOUT_MS='90000000'
$otherPlugin=Join-Path $homeDir '.cline/plugins/other.js'
Write-FzFile $otherPlugin '// unrelated plugin'
$EnvironmentFile=Invoke-FzConfigure $data $homeDir $configDir
$EnvironmentFile=Invoke-FzConfigure $data $homeDir $configDir
$caIdentity=Read-FzCertificateIdentity (Join-Path $configDir 'friendzone-ca.pem')
if($script:fakeRoots.Count-ne 1 -or -not $script:fakeRoots.ContainsKey($caIdentity.thumbprint) -or $script:fakeRoots[$caIdentity.thumbprint]-cne$caIdentity.der){throw 'generated installer did not trust the exact Friendzone CA'}
if(-not (Test-Path -LiteralPath (Join-Path $configDir 'certificate-trust-state.json'))){throw 'generated installer did not persist CA ownership state'}
$owned=@(Get-FzOwnedCertificates (Join-Path $configDir 'certificate-trust-state.json'))
if($owned.Count-ne 1 -or $owned[0].thumbprint-cne$caIdentity.thumbprint){throw 'generated installer did not record exact CA ownership'}

# A pre-existing identical current-user root is used but never claimed or removed.
$rotationIdentity=Read-FzCertificateIdentity $RotationCertificate
$script:fakeRoots[$rotationIdentity.thumbprint]=$rotationIdentity.der
$preexistingState=Join-Path $configDir 'preexisting-trust.json'
$null=Invoke-FzCertificateTrust $RotationCertificate $preexistingState $false
if(@(Get-FzOwnedCertificates $preexistingState).Count-ne 0){throw 'pre-existing root was incorrectly claimed'}
Invoke-FzCertificateTrust $null $preexistingState $true
if(-not $script:fakeRoots.ContainsKey($rotationIdentity.thumbprint)){throw 'pre-existing root was removed on rollback'}

# Rotation replaces only the old Friendzone-owned root and transfers ownership.
$script:fakeRoots.Remove($rotationIdentity.thumbprint)
$trustState=Join-Path $configDir 'certificate-trust-state.json'
$null=Invoke-FzCertificateTrust $RotationCertificate $trustState $false
if($script:fakeRoots.ContainsKey($caIdentity.thumbprint)-or-not $script:fakeRoots.ContainsKey($rotationIdentity.thumbprint)){throw 'CA rotation did not replace the owned root'}
$rotatedOwned=@(Get-FzOwnedCertificates $trustState)
if($rotatedOwned.Count-ne 1 -or $rotatedOwned[0].thumbprint-cne$rotationIdentity.thumbprint){throw 'CA rotation ownership is wrong'}
$null=Invoke-FzCertificateTrust (Join-Path $configDir 'friendzone-ca.pem') $trustState $false
if(-not $script:fakeRoots.ContainsKey($caIdentity.thumbprint)-or $script:fakeRoots.ContainsKey($rotationIdentity.thumbprint)){throw 'CA rotation back to configured root failed'}
# Uninstall removes only the root installed and owned by Friendzone.
Invoke-FzCertificateTrust $null $trustState $true
if($script:fakeRoots.ContainsKey($caIdentity.thumbprint)-or(Test-Path -LiteralPath $trustState)){throw 'owned Friendzone root or ownership state survived uninstall'}
$null=Invoke-FzCertificateTrust (Join-Path $configDir 'friendzone-ca.pem') $trustState $false
if(-not $script:fakeRoots.ContainsKey($caIdentity.thumbprint)){throw 'Friendzone CA could not be reinstalled after uninstall'}
if($script:fakeInternet.ProxyEnable.value -ne 1 -or $script:fakeInternet.ProxyServer.value -cne 'http=192.0.2.1:9080;https=192.0.2.1:9080'){throw 'generated installer did not configure the current-user system proxy'}
if(@($script:fakeInternet.ProxyOverride.value.Split(';')).Contains('<local>')){throw 'generated installer introduced a broad local-host bypass'}
if(-not (Test-Path -LiteralPath (Join-Path $configDir 'system-proxy-backup.json'))){throw 'generated installer did not persist system proxy recovery metadata'}
$plugin=Join-Path $homeDir '.cline/plugins/friendzone.js'
if([Convert]::ToBase64String([IO.File]::ReadAllBytes($plugin)) -cne $payload.plugin){throw 'installed plugin differs from bootstrap payload'}
if(-not ([IO.File]::ReadAllText($plugin).Contains('module.exports=plugin;'))){throw 'plugin export wrapper regressed'}
if([IO.File]::ReadAllText($otherPlugin) -cne '// unrelated plugin'){throw 'unrelated plugin changed'}
$pluginConfig=Get-Content -Raw -LiteralPath (Join-Path $homeDir '.cline/friendzone.json') | ConvertFrom-Json
if($pluginConfig.broker -ne $data.broker -or $pluginConfig.container -ne 'guest'){throw 'wrong plugin configuration'}
$customCline=Join-Path $TemporaryDirectory 'Custom Cline space'
$null=Invoke-FzConfigure $data $homeDir $configDir $customCline
if(-not (Test-Path -LiteralPath (Join-Path $customCline 'plugins/friendzone.js'))){throw 'custom Cline path ignored'}
# Managed upgrade keeps the first backup; unmanaged collision must fail before
# any environment write. Both paths remain inside this temporary guest.
$firstBackup=[IO.File]::ReadAllText($plugin+'.backup')
Write-FzFile $plugin "// Friendzone managed plugin v1. previous revision"
$null=Invoke-FzConfigure $data $homeDir $configDir
if([Convert]::ToBase64String([IO.File]::ReadAllBytes($plugin)) -cne $payload.plugin){throw 'managed plugin upgrade failed'}
if([IO.File]::ReadAllText($plugin+'.backup') -cne $firstBackup){throw 'first plugin backup overwritten'}
$beforeEnv=[IO.File]::ReadAllText($EnvironmentFile)
$beforeRegistry=ConvertTo-Json $script:fakeUser -Compress
Write-FzFile $plugin '// unmanaged plugin'
try {Invoke-FzConfigure $data $homeDir $configDir;throw 'expected unmanaged plugin failure'} catch {if($_.Exception.Message -eq 'expected unmanaged plugin failure'){throw}}
if([IO.File]::ReadAllText($EnvironmentFile) -cne $beforeEnv -or (ConvertTo-Json $script:fakeUser -Compress) -cne $beforeRegistry){throw 'unmanaged collision changed environment'}
Write-FzFile $plugin ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.plugin)))
$root=Get-Content -Raw -Encoding UTF8 -LiteralPath $provider | ConvertFrom-Json
if($root.providers.cline.settings.model -ne 'keep' -or $root.providers.cline.settings.apiKey -or $root.providers.cline.settings.auth.accessToken -cne "workos:fake'`$(not-a-command)" -or $root.providers.cline.settings.auth.expiresAt -ne 253402300799000 -or $root.providers.cline.settings.auth.refreshToken -or $root.providers.cline.settings.auth.accountId -or $root.providers.cline.tokenSource -cne 'oauth' -or $root.providers.other.settings.key -ne 'preserved' -or $root.lastUsedProvider -ne 'other'){throw 'OAuth provider facade merge failed'}
# Both presentation transitions remove the other mode's stale credential fields.
$data.cline_oauth=$false
$null=Invoke-FzConfigure $data $homeDir $configDir
$manual=Get-Content -Raw -Encoding UTF8 -LiteralPath $provider | ConvertFrom-Json
if($manual.providers.cline.settings.apiKey -cne "fake'`$(not-a-command)" -or $manual.providers.cline.settings.auth -or $manual.providers.cline.tokenSource -cne 'manual'){throw 'OAuth-to-manual provider transition failed'}
$data.cline_oauth=$true
$null=Invoke-FzConfigure $data $homeDir $configDir
$root=Get-Content -Raw -Encoding UTF8 -LiteralPath $provider | ConvertFrom-Json
if($root.providers.cline.settings.apiKey -or $root.providers.cline.settings.auth.accessToken -cne "workos:fake'`$(not-a-command)" -or $root.providers.cline.settings.auth.refreshToken -or $root.providers.cline.tokenSource -cne 'oauth'){throw 'Manual-to-OAuth provider transition failed'}
$beforeEnv=[IO.File]::ReadAllText($EnvironmentFile)
[IO.File]::WriteAllText($provider,'{"version":99}')
try {Invoke-FzConfigure $data $homeDir $configDir;throw 'expected invalid provider failure'} catch {if($_.Exception.Message -eq 'expected invalid provider failure'){throw}}
if([IO.File]::ReadAllText($EnvironmentFile) -cne $beforeEnv){throw 'wrote configuration before validation'}
Write-FzFile $provider (ConvertTo-Json -InputObject $root -Depth 100)
. ([scriptblock]::Create([IO.File]::ReadAllText($EnvironmentFile).TrimStart([char]0xfeff)))
if ($env:FZ_HOST -ne '192.0.2.1') { throw 'wrong broker host' }
if ($env:CLINE_API_KEY -cne "fake'`$(not-a-command)") { throw 'fake changed or evaluated' }
if ($env:NO_PROXY -notmatch 'localhost' -or $env:NO_PROXY -notmatch '127.0.0.1') { throw 'loopback exclusions missing' }
if($env:NODE_EXTRA_CA_CERTS -cne (Join-Path $configDir 'friendzone-ca.pem')){throw 'CA path with spaces/apostrophe did not survive activation'}
if($env:CARGO_HTTP_CAINFO -cne (Join-Path $configDir 'friendzone-ca.pem')){throw 'Cargo CA path with spaces/apostrophe did not survive activation'}
if($env:CARGO_HTTP_CHECK_REVOKE -cne 'false'){throw 'Cargo Schannel revocation override was not activated'}
if($env:GIT_CONFIG_COUNT -cne '2' -or $env:GIT_CONFIG_KEY_0 -cne 'http.schannelUseSSLCAInfo' -or $env:GIT_CONFIG_VALUE_0 -cne 'true' -or $env:GIT_CONFIG_KEY_1 -cne 'include.path' -or $env:GIT_CONFIG_VALUE_1 -cne (Join-Path $configDir 'friendzone.gitconfig')){throw 'Git trust/authentication configuration was not activated'}
$git=Get-Command git -ErrorAction SilentlyContinue
if($git){
    function Invoke-FzTestGitCredential([string]$GitPath,[string]$Protocol,[string]$HostName){
        $id=[Guid]::NewGuid().ToString('N')
        $inputFile=Join-Path $TemporaryDirectory ($id+'.in')
        $outputFile=Join-Path $TemporaryDirectory ($id+'.out')
        $errorFile=Join-Path $TemporaryDirectory ($id+'.err')
        try{
            [IO.File]::WriteAllBytes($inputFile,[Text.Encoding]::ASCII.GetBytes("protocol=$Protocol`nhost=$HostName`n`n"))
            $process=Start-Process -FilePath $GitPath -ArgumentList @('credential','fill') -NoNewWindow -Wait -PassThru -RedirectStandardInput $inputFile -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
            @{stdout=[IO.File]::ReadAllText($outputFile);stderr=[IO.File]::ReadAllText($errorFile);exitCode=$process.ExitCode}
        }finally{Remove-Item -Force -LiteralPath $inputFile,$outputFile,$errorFile -ErrorAction SilentlyContinue}
    }
    $isolatedGlobal=Join-Path $TemporaryDirectory 'isolated-global.gitconfig'
    [IO.File]::WriteAllText($isolatedGlobal,"[credential]`n`thelper = !f() { if test `"`$1`" = get; then printf `"%s\n`" `"username=stale`" `"password=stale`"; fi; }; f`n")
    $env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL=$isolatedGlobal;$env:GIT_TERMINAL_PROMPT='0'
    if((& $git.Source config --get http.schannelUseSSLCAInfo) -cne 'true'){throw 'Git did not receive Schannel CA configuration'}
    $credential=Invoke-FzTestGitCredential ($git.Source) 'https' 'github.com'
    if($credential.exitCode-ne 0 -or $credential.stdout-notmatch 'username=x-access-token' -or $credential.stdout-notmatch 'password=fz-test-github-token'){throw "plain Git did not receive the managed fake GitHub token: $($credential.stderr)"}
    foreach($origin in @(@('http','github.com'),@('https','github.com.evil.test'),@('https','api.github.com'))){
        $output=Invoke-FzTestGitCredential ($git.Source) $origin[0] $origin[1]
        if(($output.stdout+$output.stderr)-match 'fz-test-github-token'){throw 'Friendzone Git helper disclosed its token to a non-GitHub origin'}
    }
    $savedGithubToken=$env:GITHUB_TOKEN;Remove-Item Env:GITHUB_TOKEN
    try{$output=Invoke-FzTestGitCredential ($git.Source) 'https' 'github.com';if(($output.stdout+$output.stderr)-match 'fz-test-github-token|username=x-access-token'){throw 'Friendzone Git helper returned credentials without GITHUB_TOKEN'}}finally{$env:GITHUB_TOKEN=$savedGithubToken}
}
# Removing GitHub escrow replaces the include with a marker and retires only
# Friendzone's last applied fake from both persistent and activated environments.
$withoutGithub=[pscustomobject]@{broker=$data.broker;container=$data.container;proxy_port=$data.proxy_port;ca=$data.ca;plugin=$data.plugin;git_credential_config="# Friendzone managed Git configuration v1`n";fakes=[pscustomobject]@{CLINE_API_KEY=$data.fakes.CLINE_API_KEY}}
$EnvironmentFile=Invoke-FzConfigure $withoutGithub $homeDir $configDir
if($null-ne(Get-FzUserValue 'GITHUB_TOKEN')){throw 'removed GitHub escrow left the managed user token'}
if([IO.File]::ReadAllText((Join-Path $configDir 'friendzone.gitconfig'))-cne"# Friendzone managed Git configuration v1`n"){throw 'removed GitHub escrow left the credential helper'}
. ([scriptblock]::Create([IO.File]::ReadAllText($EnvironmentFile).TrimStart([char]0xfeff)))
if($null-ne$env:GITHUB_TOKEN){throw 'removed GitHub escrow left the managed process token'}
$EnvironmentFile=Invoke-FzConfigure $data $homeDir $configDir
. ([scriptblock]::Create([IO.File]::ReadAllText($EnvironmentFile).TrimStart([char]0xfeff)))
if((Get-FzUserValue 'GITHUB_TOKEN')-cne'fz-test-github-token'-or$env:GITHUB_TOKEN-cne'fz-test-github-token'){throw 'GitHub escrow could not be restored after removal'}
if((Get-Content -Raw -LiteralPath (Join-Path $configDir 'user-environment.json')) -notmatch 'http.schannelUseSSLCAInfo'){throw 'Schannel trust was not persisted'}
$beforeEnv=[IO.File]::ReadAllText($EnvironmentFile)
$script:fakeUser.GIT_CONFIG_COUNT='2'
$script:fakeUser.GIT_CONFIG_KEY_0='http.extraHeader'
$script:fakeUser.GIT_CONFIG_VALUE_0='secret must not be copied'
try{Invoke-FzConfigure $data $homeDir $configDir;throw 'expected invalid Git environment failure'}catch{if($_.Exception.Message -eq 'expected invalid Git environment failure'){throw}}
$script:fakeUser.GIT_CONFIG_COUNT='2'
$script:fakeUser.GIT_CONFIG_KEY_0='http.schannelUseSSLCAInfo'
$script:fakeUser.GIT_CONFIG_VALUE_0='true'
$script:fakeUser.GIT_CONFIG_KEY_1='include.path'
$script:fakeUser.GIT_CONFIG_VALUE_1=Join-Path $configDir 'friendzone.gitconfig'
if([IO.File]::ReadAllText($EnvironmentFile) -cne $beforeEnv){throw 'invalid Git environment changed configuration'}
if($env:CLINE_PLUGIN_IDLE_TIMEOUT_MS -ne 'user-original' -or $script:fakeUser.CLINE_PLUGIN_IDLE_TIMEOUT_MS -ne 'user-original'){throw "legacy managed idle override not restored (process='$($env:CLINE_PLUGIN_IDLE_TIMEOUT_MS)', user='$($script:fakeUser.CLINE_PLUGIN_IDLE_TIMEOUT_MS)')"}
if((Get-Content -Raw -LiteralPath (Join-Path $configDir 'user-environment.json')) -match 'CLINE_PLUGIN_IDLE_TIMEOUT_MS'){throw 'legacy override retained in managed values'}
if((Get-Content -Raw -LiteralPath $legacyBackup) -match 'CLINE_PLUGIN_IDLE_TIMEOUT_MS'){throw 'legacy backup entry retained'}
# A certificate-store failure must not prevent proxy/environment rollback. The
# ownership file remains so a second rollback can safely remove the root.
$script:failRootRemoval=$true
function Remove-FzTrustedCertificate([string]$Thumbprint,[string]$ExpectedDer){
    if($script:failRootRemoval){$script:failRootRemoval=$false;throw 'simulated certificate removal failure'}
    if($script:fakeRoots.ContainsKey($Thumbprint)-and $script:fakeRoots[$Thumbprint]-cne$ExpectedDer){throw 'mock root changed'}
    $script:fakeRoots.Remove($Thumbprint)
}
try{Invoke-FzWindowsPersistence $null (Join-Path $configDir 'user-environment-backup.json') (Join-Path $configDir 'system-proxy-backup.json') $null $trustState $true;throw 'expected certificate rollback failure'}catch{if($_.Exception.Message -eq 'expected certificate rollback failure'){throw}}
if($script:fakeInternet.ProxyEnable.value-ne 0 -or $script:fakeInternet.ProxyServer.value-cne 'old:8000' -or $script:fakeInternet.ProxyOverride.value-cne 'existing.test'){throw 'certificate failure skipped Windows proxy rollback'}
if($script:fakeUser.HTTP_PROXY-cne 'previous-proxy'){throw 'certificate failure skipped environment rollback'}
if(-not $script:fakeRoots.ContainsKey($caIdentity.thumbprint)-or-not(Test-Path -LiteralPath $trustState)){throw 'failed root removal lost retry ownership state'}
Invoke-FzWindowsPersistence $null (Join-Path $configDir 'user-environment-backup.json') (Join-Path $configDir 'system-proxy-backup.json') $null $trustState $true
if($script:fakeRoots.ContainsKey($caIdentity.thumbprint)-or(Test-Path -LiteralPath $trustState)){throw 'retry did not remove Friendzone-owned root'}
foreach ($path in @($BootstrapScript,$BootstrapCommand)) {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
}
Write-Output 'PASS: mocked user/proxy/root trust persistence, rotation, uninstall, rollback and failure; child-only activation; PowerShell syntax'