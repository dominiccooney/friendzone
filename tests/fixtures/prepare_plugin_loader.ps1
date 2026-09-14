param([Parameter(Mandatory=$true)][string]$Directory)
# Test-only dependencies in an explicitly chosen disposable directory. No npm
# install, lifecycle scripts, Cline startup, user configuration or broker calls.
$ErrorActionPreference='Stop'
if(-not [IO.Path]::IsPathRooted($Directory)){throw 'Use an absolute fixture directory'}
[IO.Directory]::CreateDirectory($Directory) | Out-Null
if((Get-ChildItem -LiteralPath $Directory -Force | Measure-Object).Count){throw 'Use an empty fixture directory'}
$commit='dd50b97192e21e08408ee2ad1c5190aaf56d610e'
$base='https://raw.githubusercontent.com/cline/cline/'+$commit+'/'
$shared=Join-Path $Directory 'node_modules/@cline/shared'
$jiti=Join-Path $Directory 'node_modules/jiti'
[IO.Directory]::CreateDirectory($shared) | Out-Null
[IO.Directory]::CreateDirectory($jiti) | Out-Null
Invoke-WebRequest ($base+'sdk/packages/core/src/extensions/plugin/plugin-module-import.ts') -OutFile (Join-Path $Directory 'plugin-module-import.ts')
# The upstream shared export is plain JS syntax; use .js so Node won't reject
# type stripping under node_modules. No replacement implementation is invented.
Invoke-WebRequest ($base+'sdk/packages/shared/src/extensions/plugin.ts') -OutFile (Join-Path $shared 'plugin.js')
[IO.File]::WriteAllText((Join-Path $shared 'package.json'),'{"name":"@cline/shared","type":"module","exports":"./plugin.js"}')
$metadata=Invoke-RestMethod 'https://registry.npmjs.org/jiti/2.7.0'
$archive=Join-Path $Directory 'jiti.tgz'
Invoke-WebRequest $metadata.dist.tarball -OutFile $archive
$hash=[Security.Cryptography.SHA512]::Create()
try{$actual=[Convert]::ToBase64String($hash.ComputeHash([IO.File]::ReadAllBytes($archive)))}finally{$hash.Dispose()}
if("sha512-$actual" -ne $metadata.dist.integrity){throw 'Jiti integrity check failed'}
& tar.exe -xzf $archive -C $jiti --strip-components=1
if($LASTEXITCODE -ne 0){throw 'Jiti extraction failed'}
Write-Output (Join-Path $Directory 'plugin-module-import.ts')