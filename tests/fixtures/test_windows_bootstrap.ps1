param([string]$BootstrapScript, [string]$MachineCertificateScript, [string]$TemporaryDirectory)
$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($BootstrapScript).TrimStart([char]0xfeff)))
$payloadMatch=[regex]::Match([IO.File]::ReadAllText($BootstrapScript),'\$data=\[Text.Encoding\]::UTF8.GetString\(\[Convert\]::FromBase64String\(''([A-Za-z0-9+/=]+)''\)\)')
$data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadMatch.Groups[1].Value))|ConvertFrom-Json
$identity=ConvertTo-FzCertificateIdentity $data.ca
. ([scriptblock]::Create([IO.File]::ReadAllText($MachineCertificateScript).TrimStart([char]0xfeff)))
$script:allowMachine=$true;$script:rootWrites=0
$script:roots=@{CurrentUser=@{};LocalMachine=@{}}
function Assert-FzMachineCertificateAccess {if(-not$script:allowMachine){throw 'mock elevation required'}}
function Get-FzTrustedCertificate([string]$Thumbprint,[string]$StoreLocation='CurrentUser'){
    $stores=if($StoreLocation-eq'CurrentUser'){@('CurrentUser','LocalMachine')}else{@('LocalMachine')}
    foreach($store in $stores){if($script:roots[$store].ContainsKey($Thumbprint)){return @{present=$true;der=$script:roots[$store][$Thumbprint]}}}
    @{present=$false;der=$null}
}
function Add-FzTrustedCertificate([string]$Der,[string]$StoreLocation='CurrentUser'){
    $script:rootWrites++
    $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Der))
    try{$script:roots[$StoreLocation][$certificate.Thumbprint.ToUpperInvariant()]=$Der}finally{$certificate.Dispose()}
}
function Remove-FzTrustedCertificate([string]$Thumbprint,[string]$ExpectedDer){
    if($script:roots.CurrentUser.ContainsKey($Thumbprint)-and$script:roots.CurrentUser[$Thumbprint]-cne$ExpectedDer){throw 'mock root mismatch'}
    $script:roots.CurrentUser.Remove($Thumbprint)
}
$machineOutput=Install-FzMachineCertificate $data.ca 6>&1|Out-String
if($script:rootWrites-ne 1-or$script:roots.CurrentUser.Count-ne 0-or$script:roots.LocalMachine[$identity.thumbprint]-cne$identity.der){throw 'machine bootstrap wrote the wrong trust store'}
$repeat=Install-FzMachineCertificate $data.ca 6>&1|Out-String
if($script:rootWrites-ne 1-or-not$repeat.Contains('already installed')){throw 'machine bootstrap rerun was not idempotent'}
$script:allowMachine=$false
try{Install-FzMachineCertificate $data.ca;throw 'expected elevation failure'}catch{if($_.Exception.Message-eq'expected elevation failure'){throw}}
$script:allowMachine=$true
try{Install-FzMachineCertificate 'invalid PEM';throw 'expected malformed CA failure'}catch{if($_.Exception.Message-eq'expected malformed CA failure'){throw}}
$script:roots.LocalMachine[$identity.thumbprint]='different bytes'
try{Install-FzMachineCertificate $data.ca;throw 'expected trust mismatch failure'}catch{if($_.Exception.Message-eq'expected trust mismatch failure'){throw}}
$script:roots.LocalMachine[$identity.thumbprint]=$identity.der
if($script:rootWrites-ne 1){throw 'machine bootstrap wrote during failed validation'}

# Every registry/trust operation stays in these adapters. File operations use
# generated scripts and real temporary profile files under both runtimes.
$script:user=@{};$script:internet=@{};$script:userWrites=0
function Get-FzUserValue([string]$Name){$script:user[$Name]}
function Set-FzUserValue([string]$Name,$Value){$script:userWrites++;$script:user[$Name]=$Value}
function Get-FzInternetSetting([string]$Name){if($script:internet.ContainsKey($Name)){$script:internet[$Name]}else{@{exists=$false;kind=$null;value=$null}}}
function Set-FzInternetSetting([string]$Name,$Setting){$script:internet[$Name]=$Setting}
function Notify-FzInternetSettings {}
foreach($name in @('GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_KEY_1','GIT_CONFIG_VALUE_1','GIT_CONFIG_PARAMETERS')){Remove-Item ('Env:'+$name) -ErrorAction SilentlyContinue}
$homeDir=Join-Path $TemporaryDirectory 'user home'
$configDir=Join-Path $TemporaryDirectory "user config '"
$documents=Join-Path $TemporaryDirectory "Documents '"
$profiles=@(Get-FzPowerShellProfilePaths $documents)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($profiles[0]))|Out-Null
$original="# custom profile $([char]0x00fc)"
[IO.File]::WriteAllText($profiles[0],$original,[Text.Encoding]::Unicode)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($profiles[1]))|Out-Null
$utf8Original="# UTF-8 original $([char]0x00fc)`r`n"
[IO.File]::WriteAllText($profiles[1],$utf8Original,(New-Object Text.UTF8Encoding($false)))
$before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($profiles[0]))
$output=Invoke-FzConfigure $data $homeDir $configDir $null $profiles 6>&1
$envFile=@($output|Where-Object{$_-is[string]})[-1]
foreach($path in @($BootstrapScript,$MachineCertificateScript,$envFile,(Join-Path $configDir 'friendzone-proxy-env.ps1'))){
    $text=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($path))
    if(-not$text.Contains("`r`n")-or$text.Replace("`r`n",'').Contains("`n")-or$text.Replace("`r`n",'').Contains("`r")){throw "PowerShell artifact does not use CRLF: $path"}
}
$persistence=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($data.persistence))
if(-not$persistence.Contains("`r`n")-or$persistence.Replace("`r`n",'').Contains("`n")-or$persistence.Replace("`r`n",'').Contains("`r")){throw 'packaged persistence script does not use CRLF'}
if(-not($output|Out-String).Contains('already installed')){throw 'user setup did not report machine trust reuse'}
if($script:rootWrites-ne 1-or$script:roots.CurrentUser.Count){throw 'user setup tried to insert an already machine-trusted CA'}
$trustState=Join-Path $configDir 'certificate-trust-state.json'
if(@(Get-FzOwnedCertificates $trustState).Count){throw 'user setup claimed the machine root'}
$profileState=Join-Path $configDir 'powershell-profile-state.json'
$first=@($profiles|ForEach-Object{[Convert]::ToBase64String([IO.File]::ReadAllBytes($_))})
$lockPath=Join-Path $configDir 'windows-setup.lock'
$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try{
    try{Invoke-FzWindowsPersistence $null (Join-Path $configDir 'user-environment-backup.json') (Join-Path $configDir 'system-proxy-backup.json') $null $trustState $true;throw 'expected concurrent setup failure'}catch{if($_.Exception.Message-eq'expected concurrent setup failure'){throw};if(-not$_.Exception.Message.Contains('already running')){throw}}
}finally{$lock.Dispose()}
$null=Invoke-FzConfigure $data $homeDir $configDir $null $profiles
for($index=0;$index-lt$profiles.Count;$index++){
    $path=$profiles[$index]
    if([Convert]::ToBase64String([IO.File]::ReadAllBytes($path))-cne$first[$index]){throw 'profile rerun changed content or encoding'}
    if([regex]::Matches([IO.File]::ReadAllText($path),'# BEGIN Friendzone proxy environment').Count-ne 1){throw 'duplicate profile blocks'}
}
Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:CARGO_HTTP_PROXY -ErrorAction SilentlyContinue
# Execute the installed all-hosts profile, not a reimplementation of the hook.
$compatibilityFile=Join-Path $configDir 'friendzone-proxy-env.ps1'
# Route file invocations to their real bytes without relaxing host execution policy.
function Invoke-FzTestEnvironment { . ([scriptblock]::Create([IO.File]::ReadAllText($envFile).TrimStart([char]0xfeff))) }
function Invoke-FzTestCompatibility { . ([scriptblock]::Create([IO.File]::ReadAllText($compatibilityFile).TrimStart([char]0xfeff))) }
Set-Alias -Name $envFile -Value Invoke-FzTestEnvironment
Set-Alias -Name $compatibilityFile -Value Invoke-FzTestCompatibility
try{. ([scriptblock]::Create([IO.File]::ReadAllText($profiles[0])))}finally{Remove-Item -LiteralPath ('Alias:'+$envFile),('Alias:'+$compatibilityFile)}
if($env:HTTP_PROXY-cne$env:FZ_PROXY-or$env:HTTPS_PROXY-cne$env:FZ_PROXY-or$env:CARGO_HTTP_PROXY-cne$env:FZ_PROXY){throw 'installed profile did not activate proxy environment'}
$runtime=(Get-Process -Id $PID).Path
$child=@(& $runtime -NoProfile -NonInteractive -Command '$env:HTTP_PROXY; $env:HTTPS_PROXY; $env:CARGO_HTTP_PROXY')
if($LASTEXITCODE-ne 0-or$child.Count-ne 3-or@($child|Where-Object{$_-cne$env:FZ_PROXY}).Count){throw 'profile environment was not inherited'}
$edited=[IO.File]::ReadAllText($profiles[1]).Replace('# END Friendzone proxy environment','# edited end marker')
[IO.File]::WriteAllText($profiles[1],$edited,(New-Object Text.UTF8Encoding($true)))
$writesBefore=$script:userWrites
try{Invoke-FzConfigure $data $homeDir $configDir $null $profiles;throw 'expected modified block failure'}catch{if($_.Exception.Message-eq'expected modified block failure'){throw}}
if($script:userWrites-ne$writesBefore-or[Convert]::ToBase64String([IO.File]::ReadAllBytes($profiles[0]))-cne$first[0]){throw 'invalid profile caused partial policy/profile publication'}
[IO.File]::WriteAllBytes($profiles[1],[Convert]::FromBase64String($first[1]))
[IO.File]::AppendAllText($profiles[1],"# keep external edit`r`n",(New-Object Text.UTF8Encoding($true)))
Invoke-FzWindowsPersistence $null (Join-Path $configDir 'user-environment-backup.json') (Join-Path $configDir 'system-proxy-backup.json') $null $trustState $true
if([Convert]::ToBase64String([IO.File]::ReadAllBytes($profiles[0]))-cne$before){throw 'rollback did not preserve exact original UTF-16 profile'}
if([IO.File]::ReadAllText($profiles[1])-cne($utf8Original+"# keep external edit`r`n")){throw 'rollback lost external edits or retained hook'}
if(-not$script:roots.LocalMachine.ContainsKey($identity.thumbprint)){throw 'user rollback removed the machine root'}

# Failed profile writes roll back earlier files and the ownership snapshot.
$failureDir=Join-Path $TemporaryDirectory 'failed-profile'
[IO.Directory]::CreateDirectory($failureDir)|Out-Null
$failurePaths=@((Join-Path $failureDir 'one.ps1'),(Join-Path $failureDir 'two.ps1'))
$failureState=Join-Path $failureDir 'state.json'
$realWriter=${function:Write-FzProfileFile};$script:profileWrites=0
function Write-FzProfileFile([string]$Path,[string]$Text,$Encoding){$script:profileWrites++;if($script:profileWrites-eq 2){throw 'mock profile write failure'};& $realWriter $Path $Text $Encoding}
try{$null=Invoke-FzPowerShellProfiles $failurePaths (Join-Path $configDir 'friendzone-proxy-env.ps1') $failureState $false;throw 'expected profile write failure'}catch{if($_.Exception.Message-eq'expected profile write failure'){throw}}
foreach($path in $failurePaths){if(Test-Path -LiteralPath $path){throw 'failed profile transaction retained a profile'}}
if(Test-Path -LiteralPath $failureState){throw 'failed profile transaction retained ownership state'}
Set-Item Function:Write-FzProfileFile $realWriter
$null=Invoke-FzPowerShellProfiles $failurePaths (Join-Path $configDir 'friendzone-proxy-env.ps1') $failureState $false
# Model interruption after durable opt-out ownership but before both profile writes.
[IO.File]::Delete($failurePaths[0])
$null=Invoke-FzPowerShellProfiles @() $null $failureState $false
foreach($path in $failurePaths){if(Test-Path -LiteralPath $path){throw 'opting out retained a managed profile'}}
if(Test-Path -LiteralPath $failureState){throw 'opt-out retained recovery metadata'}
# Interrupted first install leaves one missing block, which a rerun repairs.
$null=Invoke-FzPowerShellProfiles $failurePaths (Join-Path $configDir 'friendzone-proxy-env.ps1') $failureState $false
[IO.File]::Delete($failurePaths[0])
$null=Invoke-FzPowerShellProfiles $failurePaths (Join-Path $configDir 'friendzone-proxy-env.ps1') $failureState $false
foreach($path in $failurePaths){if(-not(Test-Path -LiteralPath $path)){throw 'profile rerun did not repair interrupted installation'}}
$null=Invoke-FzPowerShellProfiles @() $null $failureState $true
# If a later environment write fails, composite rollback removes both profile
# hooks while retaining an externally provisioned machine root.
$composite=Join-Path $TemporaryDirectory 'composite-profile-failure'
[IO.Directory]::CreateDirectory($composite)|Out-Null
$compositeProfiles=@((Join-Path $composite 'one.ps1'),(Join-Path $composite 'two.ps1'))
$certificatePath=Join-Path $composite 'ca.pem'
[IO.File]::WriteAllText($certificatePath,$data.ca)
$script:failEnvironment=$true
function Set-FzUserValue([string]$Name,$Value){if($script:failEnvironment){$script:failEnvironment=$false;throw 'mock environment failure'};$script:user[$Name]=$Value}
try{Invoke-FzWindowsPersistence ([pscustomobject]@{FZ_PAC_URL='http://192.0.2.1:9082/bootstrap/proxy.pac';TEST_VALUE='new'}) (Join-Path $composite 'environment.json') (Join-Path $composite 'proxy.json') $certificatePath (Join-Path $composite 'trust.json') $false $compositeProfiles;throw 'expected composite failure'}catch{if($_.Exception.Message-eq'expected composite failure'){throw}}
foreach($path in $compositeProfiles){if(Test-Path -LiteralPath $path){throw 'composite rollback left a profile hook'}}
if(Test-Path -LiteralPath (Join-Path $composite 'powershell-profile-state.json')){throw 'composite rollback lost ownership snapshot'}
if(-not$script:roots.LocalMachine.ContainsKey($identity.thumbprint)){throw 'failed composite setup removed machine trust'}
foreach($path in @($BootstrapScript,$MachineCertificateScript)){
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors|Out-String)}
}
Write-Output 'PASS: machine-only trust, user reuse, installed profile activation/inheritance, encoding, rerun, rollback, failure and opt-out'