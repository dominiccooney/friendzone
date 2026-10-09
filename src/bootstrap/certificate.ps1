function ConvertTo-FzCertificateIdentity([string]$Text) {
    $match=[regex]::Match($Text,'\A\s*-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*\z')
    if(-not $match.Success){throw 'Friendzone CA must contain exactly one PEM certificate'}
    try{$der=[Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s',''))}catch{throw 'Friendzone CA contains invalid base64'}
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
function Get-FzTrustedCertificate([string]$Thumbprint, [ValidateSet('CurrentUser','LocalMachine')][string]$StoreLocation='CurrentUser') {
    $store=New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root',$StoreLocation
    try{
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches=@($store.Certificates|Where-Object{$_.Thumbprint -ieq $Thumbprint})
        if($matches.Count -eq 0){return @{present=$false;der=$null}}
        $der=[Convert]::ToBase64String($matches[0].RawData)
        foreach($certificate in $matches){if([Convert]::ToBase64String($certificate.RawData)-cne$der){throw "Conflicting $StoreLocation root certificates have thumbprint $Thumbprint"}}
        return @{present=$true;der=$der}
    }finally{$store.Dispose()}
}
function Add-FzTrustedCertificate([string]$Der, [ValidateSet('CurrentUser','LocalMachine')][string]$StoreLocation='CurrentUser') {
    $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Der))
    $store=New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root',$StoreLocation
    try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Add($certificate)}finally{$store.Dispose();$certificate.Dispose()}
}