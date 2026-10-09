function Quote-FzPowerShell([string]$Value) {
    "'" + [regex]::Replace($Value, "['\u2018\u2019\u201a\u201b]", '$0$0') + "'"
}
function Get-FzPowerShellProfilePaths([string]$DocumentsDirectory) {
    if([string]::IsNullOrWhiteSpace($DocumentsDirectory)){throw 'Windows Documents directory is unavailable; use -SkipPowerShellProfile and activate the environment explicitly'}
    @((Join-Path $DocumentsDirectory 'WindowsPowerShell\profile.ps1'),(Join-Path $DocumentsDirectory 'PowerShell\profile.ps1'))
}
function Read-FzProfileFile([string]$Path) {
    $exists=[IO.File]::Exists($Path)
    $bytes=[byte[]]@()
    if($exists){$bytes=[IO.File]::ReadAllBytes($Path)}
    $encoding=New-Object Text.UTF8Encoding($true,$true)
    $offset=0
    if($bytes.Length-ge 3-and $bytes[0]-eq 239-and $bytes[1]-eq 187-and $bytes[2]-eq 191){$offset=3}
    elseif($bytes.Length-ge 2-and $bytes[0]-eq 255-and $bytes[1]-eq 254){$encoding=[Text.Encoding]::Unicode;$offset=2}
    elseif($bytes.Length-ge 2-and $bytes[0]-eq 254-and $bytes[1]-eq 255){$encoding=[Text.Encoding]::BigEndianUnicode;$offset=2}
    try{$text=$encoding.GetString($bytes,$offset,$bytes.Length-$offset)}catch{
        if($offset-ne 0){throw}
        $encoding=[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
        $text=$encoding.GetString($bytes)
    }
    @{exists=$exists;base64=[Convert]::ToBase64String($bytes);text=$text;encoding=$encoding}
}
function Write-FzProfileFile([string]$Path, [string]$Text, $Encoding) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))|Out-Null
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        [IO.File]::WriteAllText($temporary,$Text,$Encoding)
        if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
    }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Get-FzProfileRecords([string]$StateFile) {
    if(-not(Test-Path -LiteralPath $StateFile)){return @()}
    $saved=Get-Content -Raw -Encoding UTF8 -LiteralPath $StateFile|ConvertFrom-Json
    if($saved.version-ne 1-or $saved.profiles-isnot[System.Array]){throw 'Unsupported Friendzone PowerShell profile state; no profiles changed'}
    $paths=@{}
    foreach($record in @($saved.profiles)){
        if($null-eq$record-or-not[IO.Path]::IsPathRooted([string]$record.path)-or $record.blocks-isnot[System.Array]-or $record.blocks.Count-lt 1-or $record.blocks.Count-gt 2-or $record.created-isnot[bool]-or $paths.ContainsKey([string]$record.path)){
            throw 'Invalid Friendzone PowerShell profile state; no profiles changed'
        }
        foreach($block in $record.blocks){if($block-isnot[string]-or$block-cnotmatch '^(?:\r\n)?# BEGIN Friendzone proxy environment\r\nif \(Test-Path -LiteralPath .+\) \{ \. .+ \}\r\n# END Friendzone proxy environment\r\n$'){throw 'Invalid Friendzone PowerShell profile block state; no profiles changed'}}
        $paths[[string]$record.path]=$true
        $record
    }
}
function Remove-FzProfileBlock([string]$Text, [string]$Block) {
    $index=$Text.IndexOf($Block,[StringComparison]::Ordinal)
    if($index-lt 0-or $Text.IndexOf($Block,$index+$Block.Length,[StringComparison]::Ordinal)-ge 0){throw 'Friendzone PowerShell profile block was edited or duplicated; no profiles changed'}
    $Text.Remove($index,$Block.Length)
}
function Undo-FzProfileTransaction($Transaction) {
    foreach($file in @($Transaction.files)){
        $current=Read-FzProfileFile $file.path
        if($current.exists-eq$file.before.exists-and$current.base64-ceq$file.before.base64){continue}
        if($current.base64-cne$file.applied-or$current.exists-ne$file.exists){throw 'PowerShell profile changed during rollback; preserving the profile and recovery state'}
        if($file.before.exists){[IO.File]::WriteAllBytes($file.path,[Convert]::FromBase64String($file.before.base64))}
        elseif($current.exists){[IO.File]::Delete($file.path)}
    }
    Restore-FzBackupSnapshot $Transaction.stateBefore $Transaction.stateFile
}
function Invoke-FzPowerShellProfiles([string[]]$Paths, [string]$EnvironmentScript, [string]$StateFile, [bool]$Undo) {
    $owned=@(Get-FzProfileRecords $StateFile)
    if($Paths.Count-eq 0-and$owned.Count-eq 0-and-not(Test-Path -LiteralPath $StateFile)){return @{files=@();stateBefore=@{exists=$false;base64=$null};stateFile=$StateFile}}
    $planned=@();$records=@();$stagedRecords=@()
    $pathsToVisit=@($Paths)+@($owned|ForEach-Object{[string]$_.path})|Select-Object -Unique
    foreach($path in $pathsToVisit){
        if([string]::IsNullOrWhiteSpace($path)){continue}
        $before=Read-FzProfileFile $path
        $existing=@($owned|Where-Object{$_.path-ieq$path})
        $text=[string]$before.text
        if($existing.Count-and$before.exists){
            foreach($block in $existing[0].blocks){if($text.Contains([string]$block)){$text=Remove-FzProfileBlock $text ([string]$block)}}
        }
        if($text.Contains('# BEGIN Friendzone proxy environment')-or$text.Contains('# END Friendzone proxy environment')){throw 'Unmanaged or malformed Friendzone PowerShell profile block; no profiles changed'}
        $install=-not$Undo-and $Paths-contains$path
        if($install){
            $literal=Quote-FzPowerShell $EnvironmentScript
            $block="# BEGIN Friendzone proxy environment`r`nif (Test-Path -LiteralPath $literal) { . $literal }`r`n# END Friendzone proxy environment`r`n"
            $separator=if($text.Length-and-not($text.EndsWith("`n")-or$text.EndsWith("`r"))){"`r`n"}else{''}
            $block=$separator+$block
            $text+=$block
            $created=if($existing.Count){[bool]$existing[0].created}else{-not$before.exists}
            $records+=@{path=$path;blocks=@($block);created=$created}
        }
        $stagedBlocks=@()
        if($existing.Count){$stagedBlocks+=@($existing[0].blocks)}
        if($install){$stagedBlocks+=@($block)}
        $stagedBlocks=@($stagedBlocks|Select-Object -Unique)
        if($stagedBlocks.Count-gt 2){throw 'Restore the interrupted PowerShell profile change before changing its environment path'}
        if($stagedBlocks.Count){$stagedRecords+=@{path=$path;blocks=$stagedBlocks;created=if($existing.Count){[bool]$existing[0].created}else{-not$before.exists}}}
        $delete=-not$install-and $existing.Count-and [bool]$existing[0].created-and [string]::IsNullOrWhiteSpace($text)
        $planned+=@{path=$path;before=$before;text=$text;delete=$delete}
    }
    $stateBefore=@{exists=(Test-Path -LiteralPath $StateFile);base64=$null}
    if($stateBefore.exists){$stateBefore.base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($StateFile))}
    # Old and new block ownership commits before profile writes so interrupted
    # installation, path changes and opt-out can all be retried. Activation changes at
    # the next profile-enabled shell; the hook always reads the live env script.
    Save-FzBackup @{version=1;profiles=@($stagedRecords)} $StateFile
    $transaction=@{files=@();stateBefore=$stateBefore;stateFile=$StateFile}
    try{
        foreach($file in $planned){
            if(-not$file.delete-and$file.text-ceq$file.before.text){continue}
            $current=Read-FzProfileFile $file.path
            if($current.exists-ne$file.before.exists-or$current.base64-cne$file.before.base64){throw 'PowerShell profile changed during setup; preserving the external edit'}
            $applied=if($file.delete){''}else{[Convert]::ToBase64String([byte[]]($file.before.encoding.GetPreamble()+$file.before.encoding.GetBytes($file.text)))}
            $transaction.files+=@{path=$file.path;before=$file.before;applied=$applied;exists=(-not$file.delete)}
            if($file.delete){[IO.File]::Delete($file.path)}
            else{Write-FzProfileFile $file.path $file.text $file.before.encoding}
        }
        if($records.Count){Save-FzBackup @{version=1;profiles=@($records)} $StateFile}
        else{[IO.File]::Delete($StateFile)}
        return $transaction
    }catch{
        $failure=$_
        Undo-FzProfileTransaction $transaction
        throw $failure
    }
}