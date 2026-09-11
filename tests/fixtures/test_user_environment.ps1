param([string]$Implementation, [string]$TemporaryDirectory, [string]$BootstrapScript, [string]$BootstrapCommand)
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
$values = [pscustomobject]@{ HTTP_PROXY = 'http://guest:x@192.0.2.1:8080'; NO_PROXY = '192.0.2.1,localhost,127.0.0.1'; CLINE_API_KEY = 'new-fake' }
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
function Get-FzUserValue([string]$Name) { $script:fakeUser[$Name] }
function Set-FzUserValue([string]$Name, $Value) { $script:fakeUser[$Name]=$Value }
$homeDir=Join-Path $TemporaryDirectory 'guest-home'
$configDir=Join-Path $TemporaryDirectory 'config'
$provider=Join-Path $homeDir '.cline/data/settings/providers.json'
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($provider)) | Out-Null
[IO.File]::WriteAllText($provider,'{"version":1,"lastUsedProvider":"other","modes":{},"providers":{"cline":{"settings":{"provider":"cline","model":"keep","auth":{"refreshToken":"stale"}}},"other":{"settings":{"key":"preserved"}}}}')
$data=[pscustomobject]@{broker='http://192.0.2.1:9082';container='guest';proxy_port=9080;ca='CERTIFICATE';fakes=[pscustomobject]@{CLINE_API_KEY="fake'`$(not-a-command)"}}
$repoRoot=Split-Path (Split-Path (Split-Path $Implementation))
$data | Add-Member -NotePropertyName plugin -NotePropertyValue ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $repoRoot 'src/plugin/friendzone.js'))))
$EnvironmentFile=Invoke-FzConfigure $data $homeDir $configDir
$EnvironmentFile=Invoke-FzConfigure $data $homeDir $configDir
$plugin=Join-Path $homeDir '.cline/plugins/friendzone.js'
if(-not ([IO.File]::ReadAllText($plugin).Contains('steer_message'))){throw 'plugin not installed'}
$pluginConfig=Get-Content -Raw -LiteralPath (Join-Path $homeDir '.cline/friendzone.json') | ConvertFrom-Json
if($pluginConfig.broker -ne $data.broker -or $pluginConfig.container -ne 'guest'){throw 'wrong plugin configuration'}
$customCline=Join-Path $TemporaryDirectory 'custom-cline'
$null=Invoke-FzConfigure $data $homeDir $configDir $customCline
if(-not (Test-Path -LiteralPath (Join-Path $customCline 'plugins/friendzone.js'))){throw 'custom Cline path ignored'}
$root=Get-Content -Raw -Encoding UTF8 -LiteralPath $provider | ConvertFrom-Json
if($root.providers.cline.settings.model -ne 'keep' -or $root.providers.cline.settings.auth -or $root.providers.other.settings.key -ne 'preserved' -or $root.lastUsedProvider -ne 'other'){throw 'Provider merge failed'}
$beforeEnv=[IO.File]::ReadAllText($EnvironmentFile)
[IO.File]::WriteAllText($provider,'{"version":99}')
try {Invoke-FzConfigure $data $homeDir $configDir;throw 'expected invalid provider failure'} catch {if($_.Exception.Message -eq 'expected invalid provider failure'){throw}}
if([IO.File]::ReadAllText($EnvironmentFile) -cne $beforeEnv){throw 'wrote configuration before validation'}
. ([scriptblock]::Create([IO.File]::ReadAllText($EnvironmentFile).TrimStart([char]0xfeff)))
if ($env:FZ_HOST -ne '192.0.2.1') { throw 'wrong broker host' }
if ($env:CLINE_API_KEY -cne "fake'`$(not-a-command)") { throw 'fake changed or evaluated' }
if ($env:NO_PROXY -notmatch 'localhost' -or $env:NO_PROXY -notmatch '127.0.0.1') { throw 'loopback exclusions missing' }
foreach ($path in @($BootstrapScript,$BootstrapCommand)) {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
}
Write-Output 'PASS: mocked user persistence, idempotence, rollback, failure; child-only activation; PowerShell syntax'