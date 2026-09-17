param([string]$ValuesPath, [string]$BackupPath, [string]$SystemProxyBackupPath, [string]$CertificateTrustStatePath, [switch]$Restore)
# Dot-source only defines functions. Tests replace environment, Internet Settings,
# and certificate-store adapters; they never touch real HKCU or machine state.
function Get-FzUserValue([string]$Name) { [Environment]::GetEnvironmentVariable($Name, 'User') }
function Set-FzUserValue([string]$Name, $Value) { [Environment]::SetEnvironmentVariable($Name, $Value, 'User') }
function Read-FzCertificateIdentity([string]$Path) {
    $text=[IO.File]::ReadAllText($Path)
    $match=[regex]::Match($text,'\A\s*-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*\z')
    if(-not $match.Success){throw 'Friendzone CA file must contain exactly one PEM certificate'}
    try{$der=[Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s',''))}catch{throw 'Friendzone CA file contains invalid base64'}
    $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
    try{
        $basic=$certificate.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'}|Select-Object -First 1
        if($null -eq $basic){throw 'Friendzone certificate is not a CA'}
        $constraints=New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension -ArgumentList $basic,$basic.Critical
        if(-not $constraints.CertificateAuthority){throw 'Friendzone certificate is not a CA'}
        if([DateTime]::UtcNow -lt $certificate.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $certificate.NotAfter.ToUniversalTime()){throw 'Friendzone CA is not currently valid'}
        return @{thumbprint=$certificate.Thumbprint.ToUpperInvariant();der=[Convert]::ToBase64String($der)}
    }finally{$certificate.Dispose()}
}
function Get-FzTrustedCertificate([string]$Thumbprint) {
    $store=New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root','CurrentUser'
    try{
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches=@($store.Certificates|Where-Object{$_.Thumbprint -ieq $Thumbprint})
        if($matches.Count -gt 1){throw "Multiple current-user root certificates have thumbprint $Thumbprint"}
        if($matches.Count -eq 0){return @{present=$false;der=$null}}
        return @{present=$true;der=[Convert]::ToBase64String($matches[0].RawData)}
    }finally{$store.Dispose()}
}
function Add-FzTrustedCertificate([string]$Der) {
    $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Der))
    $store=New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root','CurrentUser'
    try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Add($certificate)}finally{$store.Dispose();$certificate.Dispose()}
}
function Remove-FzTrustedCertificate([string]$Thumbprint, [string]$ExpectedDer) {
    $store=New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root','CurrentUser'
    try{
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches=@($store.Certificates|Where-Object{$_.Thumbprint -ieq $Thumbprint})
        foreach($certificate in $matches){
            if([Convert]::ToBase64String($certificate.RawData) -cne $ExpectedDer){throw "Current-user root certificate $Thumbprint does not match Friendzone's recorded certificate"}
            $store.Remove($certificate)
        }
    }finally{$store.Dispose()}
}
function Get-FzInternetSetting([string]$Name) {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings',$false)
    try {
        $actualName=if($null -ne $key){@($key.GetValueNames())|Where-Object{$_ -ieq $Name}|Select-Object -First 1}else{$null}
        if($null -eq $actualName){
            return @{exists=$false;kind=$null;value=$null}
        }
        $kind=$key.GetValueKind($actualName).ToString()
        $options=if($kind -eq 'ExpandString'){[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames}else{[Microsoft.Win32.RegistryValueOptions]::None}
        return @{exists=$true;kind=$kind;value=$key.GetValue($actualName,$null,$options)}
    } finally {if($null -ne $key){$key.Dispose()}}
}
function Set-FzInternetSetting([string]$Name, $Setting) {
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings',$true)
    try {
        if(-not [bool]$Setting.exists){$key.DeleteValue($Name,$false);return}
        $kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$Setting.kind,$false)
        $value=switch([string]$Setting.kind){
            'DWord' {[int]$Setting.value;break}
            'QWord' {[long]$Setting.value;break}
            {$_ -in @('Binary','None')} {[byte[]]@($Setting.value);break}
            'MultiString' {[string[]]@($Setting.value);break}
            default {[string]$Setting.value;break}
        }
        $key.SetValue($Name,$value,$kind)
    } finally {$key.Dispose()}
}
function Notify-FzInternetSettings {
    try {
        if(-not ('Friendzone.WinInet' -as [type])){
            Add-Type -TypeDefinition @'
namespace Friendzone {
    using System;
    using System.Runtime.InteropServices;
    public static class WinInet {
        [DllImport("wininet.dll", SetLastError=true)]
        public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length);
    }
}
'@
        }
        $null=[Friendzone.WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)
        $null=[Friendzone.WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)
    } catch {
        Write-Warning 'Windows proxy changed, but running applications could not be notified; restart them'
    }
}
function Save-FzBackup($Backup, [string]$Path) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $Backup -Depth 8), (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Test-FzSettingEqual($Left, $Right) {
    if([bool]$Left.exists -ne [bool]$Right.exists){return $false}
    if(-not [bool]$Left.exists){return $true}
    if(([string]$Left.kind) -cne ([string]$Right.kind)){return $false}
    return (ConvertTo-Json -Compress -InputObject $Left.value) -ceq (ConvertTo-Json -Compress -InputObject $Right.value)
}
function Restore-FzBackupSnapshot($Snapshot, [string]$Path) {
    if([bool]$Snapshot.exists){[IO.File]::WriteAllBytes($Path,[Convert]::FromBase64String([string]$Snapshot.base64))}
    elseif(Test-Path -LiteralPath $Path){Remove-Item -Force -LiteralPath $Path}
}
function Get-FzOwnedCertificates([string]$StateFile) {
    if(-not (Test-Path -LiteralPath $StateFile)){return @()}
    $saved=Get-Content -Raw -Encoding UTF8 -LiteralPath $StateFile|ConvertFrom-Json
    if($saved.version -ne 1 -or $null -eq $saved.PSObject.Properties['owned']){throw 'Unsupported Friendzone certificate trust state; no certificates changed'}
    $owned=@()
    foreach($record in @($saved.owned)){
        if($null -eq $record -or [string]$record.thumbprint -cnotmatch '^[A-Fa-f0-9]{40}$' -or [string]::IsNullOrWhiteSpace([string]$record.der)){throw 'Invalid Friendzone certificate trust state; no certificates changed'}
        try{$der=[Convert]::FromBase64String([string]$record.der)}catch{throw 'Invalid Friendzone certificate trust state; no certificates changed'}
        $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
        try{if($certificate.Thumbprint -ine [string]$record.thumbprint){throw 'Invalid Friendzone certificate trust state; no certificates changed'}}finally{$certificate.Dispose()}
        $owned+=@{thumbprint=([string]$record.thumbprint).ToUpperInvariant();der=[string]$record.der}
    }
    if(@($owned|Group-Object thumbprint|Where-Object Count -gt 1).Count){throw 'Duplicate Friendzone certificate trust state; no certificates changed'}
    return @($owned)
}
function Save-FzOwnedCertificates([string]$StateFile, $Owned) {
    $records=@()
    foreach($record in @($Owned)){if($null-ne$record){$records+=$record}}
    Save-FzBackup @{version=1;owned=$records} $StateFile
}
function Undo-FzCertificateTrustTransaction($Transaction) {
    $firstError=$null;$addedRemoved=$true
    foreach($record in @($Transaction.added)){
        try{
            $current=Get-FzTrustedCertificate $record.thumbprint
            if([bool]$current.present -and [string]$current.der -ceq [string]$record.der){Remove-FzTrustedCertificate $record.thumbprint $record.der}
            elseif([bool]$current.present){$addedRemoved=$false;Write-Warning "Preserving externally changed current-user root $($record.thumbprint)"}
        }catch{$addedRemoved=$false;if($null-eq$firstError){$firstError=$_}}
    }
    # Only restore roots removed by rotation once every newly-added root was
    # removed. Otherwise retain the applied/staged ownership file so a later
    # rollback can safely retry without creating an untracked trusted root.
    if($addedRemoved){
        foreach($record in @($Transaction.removed)){
            try{
                $current=Get-FzTrustedCertificate $record.thumbprint
                if(-not [bool]$current.present){Add-FzTrustedCertificate $record.der}
                elseif([string]$current.der -cne [string]$record.der){$addedRemoved=$false;Write-Warning "Preserving externally changed current-user root $($record.thumbprint)"}
            }catch{$addedRemoved=$false;if($null-eq$firstError){$firstError=$_}}
        }
    }
    if($addedRemoved -and (Test-Path -LiteralPath $Transaction.stateFile)){
        $current=[Convert]::ToBase64String([IO.File]::ReadAllBytes($Transaction.stateFile))
        if($current -ceq $Transaction.stateApplied){Restore-FzBackupSnapshot $Transaction.stateBefore $Transaction.stateFile}
        else{Write-Warning 'Preserving externally changed Friendzone certificate trust state'}
    }elseif($addedRemoved -and [bool]$Transaction.stateBefore.exists){Write-Warning 'Friendzone certificate trust state disappeared; not recreating it during rollback'}
    elseif(-not $addedRemoved){Write-Warning 'Certificate rollback was incomplete; preserving Friendzone certificate ownership state for retry'}
    if($null-ne$firstError){throw $firstError}
}
function Invoke-FzCertificateTrust([string]$CertificatePath, [string]$StateFile, [bool]$Undo) {
    $owned=@(Get-FzOwnedCertificates $StateFile)
    if($Undo){
        $remaining=@();$firstError=$null
        foreach($record in $owned){
            try{
                $current=Get-FzTrustedCertificate $record.thumbprint
                if(-not [bool]$current.present){continue}
                if([string]$current.der -cne [string]$record.der){$remaining+=$record;Write-Warning "Current-user root certificate $($record.thumbprint) changed; it was not removed";continue}
                Remove-FzTrustedCertificate $record.thumbprint $record.der
            }catch{$remaining+=$record;if($null-eq$firstError){$firstError=$_}}
        }
        if($remaining.Count){Save-FzOwnedCertificates $StateFile $remaining}
        elseif(Test-Path -LiteralPath $StateFile){Remove-Item -Force -LiteralPath $StateFile}
        if($null-ne$firstError){throw $firstError}
        return
    }
    $identity=Read-FzCertificateIdentity $CertificatePath
    $current=Get-FzTrustedCertificate $identity.thumbprint
    if([bool]$current.present -and [string]$current.der -cne [string]$identity.der){throw 'Current-user root store contains a different certificate with the Friendzone CA thumbprint'}
    $alreadyOwned=@($owned|Where-Object{$_.thumbprint -ceq $identity.thumbprint -and $_.der -ceq $identity.der}).Count -eq 1
    $added=@();$removed=@()
    $stateBefore=@{exists=(Test-Path -LiteralPath $StateFile);base64=$null}
    if($stateBefore.exists){$stateBefore.base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($StateFile))}
    $staged=@($owned)
    if(-not [bool]$current.present -and -not $alreadyOwned){$staged+=@{thumbprint=$identity.thumbprint;der=$identity.der}}
    Save-FzOwnedCertificates $StateFile $staged
    try{
        if(-not [bool]$current.present){
            $newRecord=@{thumbprint=$identity.thumbprint;der=$identity.der}
            # Record this before Add: a store implementation may insert the
            # certificate and still report an error afterward.
            $added+=$newRecord
            Add-FzTrustedCertificate $identity.der
            $verified=Get-FzTrustedCertificate $identity.thumbprint
            if(-not [bool]$verified.present -or [string]$verified.der -cne [string]$identity.der){throw 'Friendzone CA was not installed in the current-user root store'}
        }
        foreach($record in $owned|Where-Object{$_.thumbprint -cne $identity.thumbprint}){
            $old=Get-FzTrustedCertificate $record.thumbprint
            if([bool]$old.present){
                if([string]$old.der -cne [string]$record.der){throw "Old Friendzone-owned root $($record.thumbprint) changed; it was not removed"}
                $removed+=$record
                Remove-FzTrustedCertificate $record.thumbprint $record.der
            }
        }
        $finalOwned=if(-not [bool]$current.present -or $alreadyOwned){@(@{thumbprint=$identity.thumbprint;der=$identity.der})}else{@()}
        Save-FzOwnedCertificates $StateFile $finalOwned
        $stateApplied=[Convert]::ToBase64String([IO.File]::ReadAllBytes($StateFile))
        return @{added=@($added);removed=@($removed);stateFile=$StateFile;stateBefore=$stateBefore;stateApplied=$stateApplied}
    }catch{
        $failure=$_
        $stateApplied=if(Test-Path -LiteralPath $StateFile){[Convert]::ToBase64String([IO.File]::ReadAllBytes($StateFile))}else{$null}
        try{Undo-FzCertificateTrustTransaction @{added=@($added);removed=@($removed);stateFile=$StateFile;stateBefore=$stateBefore;stateApplied=$stateApplied}}catch{throw "Friendzone CA installation failed and certificate rollback was incomplete: $($_.Exception.Message)"}
        throw $failure
    }
}
function Undo-FzSystemProxyTransaction($Transaction) {
    $changed=$false
    foreach($name in @($Transaction.written)){
        if(Test-FzSettingEqual (Get-FzInternetSetting $name) $Transaction.applied[$name]){
            Set-FzInternetSetting $name $Transaction.before[$name]
            $changed=$true
        }else{Write-Warning "Preserving externally changed Windows proxy value $name"}
    }
    if(Test-Path -LiteralPath $Transaction.backupFile){
        $current=[Convert]::ToBase64String([IO.File]::ReadAllBytes($Transaction.backupFile))
        if($current -ceq $Transaction.backupApplied){Restore-FzBackupSnapshot $Transaction.backupBefore $Transaction.backupFile}
        else{Write-Warning 'Preserving externally changed Windows proxy backup'}
    }elseif([bool]$Transaction.backupBefore.exists){Write-Warning 'Windows proxy backup disappeared; not recreating it during rollback'}
    if($changed){Notify-FzInternetSettings}
}
function Invoke-FzSystemProxy([string]$ProxyHost, [int]$ProxyPort, [string]$BackupFile, [bool]$Undo) {
    $names=@('ProxyEnable','ProxyServer','ProxyOverride')
    if($Undo){
        if(-not (Test-Path -LiteralPath $BackupFile)){return}
        $saved=Get-Content -Raw -Encoding UTF8 -LiteralPath $BackupFile | ConvertFrom-Json
        if($saved.version -ne 1 -or $null -eq $saved.settings){throw 'Unsupported Windows proxy backup; no proxy settings changed'}
        $changed=$false
        foreach($name in $names){
            $entry=$saved.settings.PSObject.Properties[$name].Value
            if($null -eq $entry){continue}
            if(Test-FzSettingEqual (Get-FzInternetSetting $name) $entry.applied){Set-FzInternetSetting $name $entry.previous;$changed=$true}
            else{Write-Warning "Preserving externally changed Windows proxy value $name"}
        }
        if($changed){Notify-FzInternetSettings}
        return
    }
    $bareHost=$ProxyHost.Trim('[',']')
    if([string]::IsNullOrWhiteSpace($ProxyHost) -or $ProxyHost -cne $ProxyHost.Trim() -or $ProxyHost.IndexOfAny(@([char]';',[char]'=',[char]'/',[char]'\',[char]'@',[char]'?',[char]'#',[char]0)) -ge 0 -or [Uri]::CheckHostName($bareHost) -eq [UriHostNameType]::Unknown -or $ProxyPort -lt 1 -or $ProxyPort -gt 65535){throw 'Invalid Friendzone Windows proxy address'}
    $hostForAuthority=if($bareHost.Contains(':')){"[$bareHost]"}else{$bareHost}
    $authority=$hostForAuthority+':'+$ProxyPort
    $currentOverride=Get-FzInternetSetting 'ProxyOverride'
    if([bool]$currentOverride.exists -and [string]$currentOverride.kind -notin @('String','ExpandString')){throw 'Existing Windows proxy bypass has an unsupported registry type; no proxy settings changed'}
    $overrideItems=if([bool]$currentOverride.exists){@(([string]$currentOverride.value).Split(';'))}else{@()}
    $seen=@{};$merged=@()
    foreach($item in @($overrideItems)+@($bareHost,$hostForAuthority,'localhost','127.0.0.1','::1','[::1]')){
        $item=$item.Trim();if(-not $item){continue};$key=$item.ToLowerInvariant();if(-not $seen.ContainsKey($key)){$seen[$key]=$true;$merged+=$item}
    }
    $applied=@{
        ProxyEnable=@{exists=$true;kind='DWord';value=1}
        ProxyServer=@{exists=$true;kind='String';value=('http='+$authority+';https='+$authority)}
        ProxyOverride=@{exists=$true;kind='String';value=($merged -join ';')}
    }
    $before=@{};foreach($name in $names){$before[$name]=Get-FzInternetSetting $name}
    $backupBefore=@{exists=(Test-Path -LiteralPath $BackupFile);base64=$null}
    if($backupBefore.exists){$backupBefore.base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($BackupFile))}
    $original=@{}
    if($backupBefore.exists){
        $saved=Get-Content -Raw -Encoding UTF8 -LiteralPath $BackupFile | ConvertFrom-Json
        if($saved.version -ne 1 -or $null -eq $saved.settings){throw 'Unsupported Windows proxy backup; no proxy settings changed'}
        foreach($name in $names){$entry=$saved.settings.PSObject.Properties[$name].Value;if($null -ne $entry){$original[$name]=$entry.previous}}
    }
    $settings=@{};foreach($name in $names){$settings[$name]=@{previous=$(if($original.ContainsKey($name)){$original[$name]}else{$before[$name]});applied=$applied[$name]}}
    Save-FzBackup @{version=1;settings=$settings} $BackupFile
    $backupApplied=[Convert]::ToBase64String([IO.File]::ReadAllBytes($BackupFile))
    $written=@()
    try{
        foreach($name in $names){if(-not (Test-FzSettingEqual $before[$name] $applied[$name])){Set-FzInternetSetting $name $applied[$name];$written+=$name}}
    }catch{
        foreach($name in $written){Set-FzInternetSetting $name $before[$name]}
        Restore-FzBackupSnapshot $backupBefore $BackupFile
        throw
    }
    if($written.Count){Notify-FzInternetSettings}
    return @{before=$before;applied=$applied;written=$written;backupFile=$BackupFile;backupBefore=$backupBefore;backupApplied=$backupApplied}
}
function Remove-FzManagedUserValue([string]$Name, [string]$AppliedValue, [string]$BackupFile) {
    if (-not (Test-Path -LiteralPath $BackupFile)) { return }
    $saved = Get-Content -Raw -Encoding UTF8 -LiteralPath $BackupFile | ConvertFrom-Json
    $property = $saved.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value.applied -cne $AppliedValue) { return }
    if ((Get-FzUserValue $Name) -ceq $AppliedValue) { Set-FzUserValue $Name $property.Value.previous }
    else { Write-Warning "Preserving externally changed user variable $Name" }
    $saved.PSObject.Properties.Remove($Name)
    $replacement = @{}
    foreach ($item in $saved.PSObject.Properties) { $replacement[$item.Name] = $item.Value }
    Save-FzBackup $replacement $BackupFile
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
    $backupBefore=@{exists=(Test-Path -LiteralPath $BackupFile);base64=$null}
    if($backupBefore.exists){$backupBefore.base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($BackupFile))}
    Save-FzBackup $backup $BackupFile
    $written = @()
    try {
        foreach ($name in $planned.Keys) {
            if ($before[$name] -cne $planned[$name]) { Set-FzUserValue $name $planned[$name]; $written += $name }
        }
    } catch {
        foreach ($name in $written) { Set-FzUserValue $name $before[$name] }
        Restore-FzBackupSnapshot $backupBefore $BackupFile
        throw
    }
}
function Invoke-FzWindowsPersistence($Values, [string]$EnvironmentBackupFile, [string]$SystemProxyBackupFile, [string]$CertificatePath, [string]$CertificateTrustStateFile, [bool]$Undo) {
    if($Undo){
        $firstError=$null
        try{Invoke-FzCertificateTrust $null $CertificateTrustStateFile $true}catch{$firstError=$_}
        try{Invoke-FzSystemProxy $null 0 $SystemProxyBackupFile $true}catch{if($null -eq $firstError){$firstError=$_}}
        try{Invoke-FzUserEnvironment $null $EnvironmentBackupFile $true}catch{if($null -eq $firstError){$firstError=$_}}
        if($null -ne $firstError){throw $firstError}
        return
    }
    $proxy=[Uri]$Values.HTTP_PROXY
    if($proxy.Scheme -cne 'http' -or -not [string]::IsNullOrEmpty($proxy.UserInfo) -or $proxy.AbsolutePath -cne '/' -or -not [string]::IsNullOrEmpty($proxy.Query) -or -not [string]::IsNullOrEmpty($proxy.Fragment)){throw 'Invalid managed HTTP_PROXY; no persistent settings changed'}
    $certificateTransaction=Invoke-FzCertificateTrust $CertificatePath $CertificateTrustStateFile $false
    try{$systemTransaction=Invoke-FzSystemProxy $proxy.DnsSafeHost $proxy.Port $SystemProxyBackupFile $false}catch{Undo-FzCertificateTrustTransaction $certificateTransaction;throw}
    try{Invoke-FzUserEnvironment $Values $EnvironmentBackupFile $false}catch{
        $failure=$_;$rollbackError=$null
        try{Undo-FzSystemProxyTransaction $systemTransaction}catch{$rollbackError=$_}
        try{Undo-FzCertificateTrustTransaction $certificateTransaction}catch{if($null-eq$rollbackError){$rollbackError=$_}}
        if($null-ne$rollbackError){throw "Windows setup failed and rollback was incomplete: $($rollbackError.Exception.Message)"}
        throw $failure
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    if (-not $BackupPath) { throw 'BackupPath is required' }
    if(-not $SystemProxyBackupPath){$SystemProxyBackupPath=Join-Path ([IO.Path]::GetDirectoryName($BackupPath)) 'system-proxy-backup.json'}
    if(-not $CertificateTrustStatePath){$CertificateTrustStatePath=Join-Path ([IO.Path]::GetDirectoryName($BackupPath)) 'certificate-trust-state.json'}
    $values = if ($Restore) { $null } else { Get-Content -Raw -Encoding UTF8 -LiteralPath $ValuesPath | ConvertFrom-Json }
    $certificatePath=if($Restore){$null}else{[string]$values.SSL_CERT_FILE}
    Invoke-FzWindowsPersistence $values $BackupPath $SystemProxyBackupPath $certificatePath $CertificateTrustStatePath ([bool]$Restore)
}