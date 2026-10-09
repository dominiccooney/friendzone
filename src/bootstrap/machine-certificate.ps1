function Assert-FzMachineCertificateAccess {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Machine certificate setup requires Windows'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{
        $principal=New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        if(-not $identity.IsSystem -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
            throw 'Run certificate-only setup as LocalSystem or an already-elevated administrator. This script does not request elevation.'
        }
    }finally{$identity.Dispose()}
}
function Install-FzMachineCertificate([string]$Pem) {
    Assert-FzMachineCertificateAccess
    $identity=ConvertTo-FzCertificateIdentity $Pem
    $current=Get-FzTrustedCertificate $identity.thumbprint 'LocalMachine'
    if($current.present){
        if($current.der -cne $identity.der){throw 'Machine root store contains a different certificate with the Friendzone CA thumbprint'}
        Write-Host ('Friendzone CA '+$identity.thumbprint+' is already installed in LocalMachine\Root; skipping installation.')
        return
    }
    # Machine trust belongs to provisioning, not any user's setup or rollback.
    # The store add is the only write; reruns verify the exact installed bytes.
    Add-FzTrustedCertificate $identity.der 'LocalMachine'
    $verified=Get-FzTrustedCertificate $identity.thumbprint 'LocalMachine'
    if(-not $verified.present -or $verified.der -cne $identity.der){throw 'Friendzone CA was not installed in the machine root store'}
    Write-Host ('Installed Friendzone CA '+$identity.thumbprint+' in LocalMachine\Root. User settings were not changed.')
}