<#
.SYNOPSIS
  Comprehensive Turla Cereal pattern scanner for Windows workstations and servers.

.DESCRIPTION
  Read-only hunter covering gaps beyond AV:
  - All ESET SHA-1 IoCs (+ resolved SHA-256 from iocs\cereal-iocs.json)
  - Hijack paths, NativeImages masquerades, FallbackLog.bin
  - .NET COMIMAGE_FLAGS_NATIVE_ENTRYPOINT heuristic
  - CerealNeuron HTTP.sys URL prefixes (+ context)
  - Config MD5 key B38C96AE6643D2AB5C0BFE823D9C9017
  - Process module inspection (WmiPrvSE, EdgeTransport, Exchange Search)
  - Content string hunt (URI prefixes, RoutingAgentFactory, amsiInitFailed)
  - Optional YARA (yara\cereal.yar)

.PARAMETER FullDriveHashScan
  Hash all fixed-drive PE/dat files against IoCs (slow).

.PARAMETER SkipHttpSys
  Skip netsh HTTP.sys checks.

.PARAMETER RunYara
  Run yara\cereal.yar if yara64.exe is available.

.PARAMETER OutputJson
  Write findings JSON.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json -RunYara
#>
[CmdletBinding()]
param(
    [string[]]$Roots = @(),
    [switch]$FullDriveHashScan,
    [switch]$SkipHttpSys,
    [switch]$RunYara,
    [string]$YaraPath = "",
    [string]$OutputJson = ""
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:StartUtc = [DateTime]::UtcNow

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [string]$Category,[string]$Title,[string]$Detail,[string]$Evidence=""
    )
    $Script:Findings.Add([pscustomobject]@{
        Severity=$Severity; Category=$Category; Title=$Title; Detail=$Detail; Evidence=$Evidence
        Timestamp=[DateTime]::UtcNow.ToString('o')
    }) | Out-Null
    $color = switch ($Severity) { 'Critical'{'Red'} 'High'{'Magenta'} 'Medium'{'Yellow'} 'Low'{'Cyan'} default{'Gray'} }
    Write-Host ("[{0}] {1}: {2}" -f $Severity,$Category,$Title) -ForegroundColor $color
    if ($Detail) { Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Load IoC pack ---
$IocPath = Join-Path $ScriptDir 'iocs\cereal-iocs.json'
$IocDoc = $null
$KnownSha1 = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$KnownSha256 = @{}  # sha256 -> role
$Sha1Meta = @{}

if (Test-Path -LiteralPath $IocPath) {
    $IocDoc = Get-Content -LiteralPath $IocPath -Raw | ConvertFrom-Json
    foreach ($f in $IocDoc.files) {
        [void]$KnownSha1.Add($f.sha1.ToUpperInvariant())
        $Sha1Meta[$f.sha1.ToUpperInvariant()] = $f
        if ($f.sha256) { $KnownSha256[$f.sha256.ToUpperInvariant()] = ("{0} / {1}" -f $f.role, $f.filename) }
    }
    if ($IocDoc.additional_sha256_hunt_set) {
        foreach ($a in $IocDoc.additional_sha256_hunt_set) {
            if ($a.sha256 -and -not $KnownSha256.ContainsKey($a.sha256.ToUpperInvariant())) {
                $KnownSha256[$a.sha256.ToUpperInvariant()] = 'ESET Cereal-era SHA-256 (pairing pending)'
            }
        }
    }
    Add-Finding Info Meta 'Loaded IoC pack' $IocPath ("Files={0}; SHA256Hunt={1}" -f @($IocDoc.files).Count, $KnownSha256.Count)
} else {
    Add-Finding Medium Meta 'IoC pack missing' $IocPath 'Using embedded fallback hashes only'
}

# Embedded fallback (always)
@(
 '4A3C263977417FB6977B0E598C9E3BC5924F390C','7742C6B0AAF114335CEF7EBAB11290CB18A0B8B3','AFE448DD95494CD14438F04F0C5F6B384664A3B7',
 '4A65040646E354303F067D47AA1C953D467F65CB','D1E17520A2435EDCDCC47F582381416FBDF75F94','7AB784D0049890D9844AEE7F214BA173E3CC23BE',
 '5D80118B1EE974936322475F740AB3AEFF70B8F3','D51C58C2E95D4561848E0A5A8B9FB33C847C50A4','5B94FE76EC4FEB0B5CB6EA3BCA4C48D2FE22597B',
 '1408A8F62B09A5AD0DFF279B2878D8F59F70A330','3D1A534CE0D0C293F62ECE556CBC6D0728213104','AD85FBF2CC879D4325BCE1E6FB5F12AB59E3D387',
 '3EA03188DBA8898D97E965732C1D6A68C5437EDC','3FBA18AF966DEACF7AE09E4D4238952DD90A6D6F','EB9BA1DA5363F5D04E2F98673595FCE93F39A78E',
 '0B4E4A1CE7FEE91BFC62B2A2EC572C325642BB60','A4E477CE257F2C635401EF554E05506C080967C0','A5BE8706032A0798FD63214A9F22EFA6309355F5'
) | ForEach-Object { [void]$KnownSha1.Add($_) }

$KnownSha256['13FE1EB9B182B076A815F84D34B66365809D0CFF32DF6F5B85AA7EF4DEEE98E0'] = 'CerealLoader / Microsoft.Exchange.Data.Transport.ni.dll'
$KnownSha256['241AAC14756A0F29EDD084B858623DB259D59C77EA44889DE93431C42FF10036'] = 'CerealLoader / version.dll'
$KnownSha256['D3B6065EB001D169421FCD146F64B087055DADEBD973D8D69AE2BF97FBF288E2'] = 'CerealLoader / version.dll'
$KnownSha256['6119D25AE51D04264384F5D738C104E42596B0774609666B357A43608A48404C'] = 'CerealLoader / Microsoft.Search.Platform.dll'
$KnownSha256['41164EB06ADC72B187EDAF90D73CA73BE729D4EBFDECF57D7398561136941651'] = 'CerealLoader / Microsoft.Ceres.dll'

$ConfigKey = 'B38C96AE6643D2AB5C0BFE823D9C9017'
$SuspiciousNames = @('ncobjapi.dll','wbemcomn.dll','version.dll','iph.dat','FallbackLog.bin',
 'Microsoft.Exchange.Data.Transport.ni.dll','Microsoft.Exchange.Search.Mdb.ni.dll',
 'Microsoft.Exchange.EdgeSyncSvc.ni.exe','EdgeTransport.ni.exe','Microsoft.Search.Platform.dll','Microsoft.Ceres.dll')
$UriPatterns = @('owa/sdds','autodiscover/microsoft.exchange.proxyservice','autodiscover/integrated/api',
 'autodiscover/proxyservice','microsoft-server-activesync/integrated/api')
# High-signal only (avoid common BCL strings like HttpListener / MimeDocument)
$ContentNeedles = @($ConfigKey,'owa/sdds','RoutingAgentFactory','amsiInitFailed','FallbackLog.bin',
 'MICROSOFT.EXCHANGE.PROXYSERVICE','AUTODISCOVER/PROXYSERVICE','MICROSOFT-SERVER-ACTIVESYNC/INTEGRATED')

function Get-FileSha1([string]$Path) {
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToUpperInvariant() } catch { $null }
}
function Get-FileSha256([string]$Path) {
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant() } catch { $null }
}

function Test-PeNetNativeEntrypoint([string]$Path) {
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $br = New-Object IO.BinaryReader($fs)
            if ($br.ReadUInt16() -ne 0x5A4D) { return $false }
            $fs.Seek(0x3C,'Begin')|Out-Null
            $pe = $br.ReadUInt32(); $fs.Seek($pe,'Begin')|Out-Null
            if ($br.ReadUInt32() -ne 0x00004550) { return $false }
            $fs.Seek(2,'Current')|Out-Null
            $numSections = $br.ReadUInt16()
            $fs.Seek(12,'Current')|Out-Null
            $optSize = $br.ReadUInt16(); $fs.Seek(2,'Current')|Out-Null
            $optStart = $fs.Position
            $magic = $br.ReadUInt16()
            $isPlus = ($magic -eq 0x20B)
            $ddStart = if ($isPlus) { $optStart + 112 } else { $optStart + 96 }
            $fs.Seek($ddStart + 14*8,'Begin')|Out-Null
            $clrRva = $br.ReadUInt32(); $clrSize = $br.ReadUInt32()
            if ($clrRva -eq 0 -or $clrSize -lt 16) { return $false }
            $sectionTable = $optStart + $optSize
            $fileOffset = $null
            for ($i=0; $i -lt $numSections; $i++) {
                $fs.Seek($sectionTable + $i*40 + 8,'Begin')|Out-Null
                $vSize=$br.ReadUInt32(); $vAddr=$br.ReadUInt32(); $rSize=$br.ReadUInt32(); $rPtr=$br.ReadUInt32()
                if ($clrRva -ge $vAddr -and $clrRva -lt ($vAddr + [Math]::Max($vSize,$rSize))) {
                    $fileOffset = $rPtr + ($clrRva - $vAddr); break
                }
            }
            if ($null -eq $fileOffset) { return $false }
            $fs.Seek($fileOffset + 16,'Begin')|Out-Null
            $flags = $br.ReadUInt32()
            return (($flags -band 0x10) -ne 0)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Test-KnownHashFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $sha1 = Get-FileSha1 $Path
    $sha256 = Get-FileSha256 $Path
    if ($sha1 -and $KnownSha1.Contains($sha1)) {
        $meta = $Sha1Meta[$sha1]
        $role = if ($meta) { $meta.role } else { 'Cereal IoC' }
        Add-Finding Critical Hash ("Known Cereal SHA-1 ({0})" -f $role) $Path ("SHA1={0}; SHA256={1}" -f $sha1,$sha256)
    }
    elseif ($sha256 -and $KnownSha256.ContainsKey($sha256)) {
        Add-Finding Critical Hash ("Known Cereal SHA-256 ({0})" -f $KnownSha256[$sha256]) $Path ("SHA256={0}" -f $sha256)
    }
}

function Scan-Paths {
    Write-Host "`n== Path / masquerade / NativeImages ==" -ForegroundColor White
    foreach ($p in @(
        "$env:WINDIR\System32\wbem\ncobjapi.dll","$env:WINDIR\SysWOW64\wbem\ncobjapi.dll",
        "$env:WINDIR\System32\wbem\wbemcomn.dll","$env:WINDIR\SysWOW64\wbem\wbemcomn.dll"
    )) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        Test-KnownHashFile $p
        $item = Get-Item -LiteralPath $p
        if ($p -match 'ncobjapi\.dll$') {
            Add-Finding High Path 'ncobjapi.dll under wbem (CerealLoader hijack path)' $p ("Size={0}" -f $item.Length)
            if (Test-PeNetNativeEntrypoint $p) {
                Add-Finding Critical PE 'Native .NET entrypoint on ncobjapi.dll' $p 'COMIMAGE_FLAGS_NATIVE_ENTRYPOINT'
            }
        }
        if ($p -match 'wbemcomn\.dll$') {
            $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -ne 'Valid') {
                Add-Finding High Path 'wbemcomn.dll signature invalid' $p ("Status={0}" -f $sig.Status)
            }
            if (Test-PeNetNativeEntrypoint $p) {
                Add-Finding Critical PE 'Native .NET entrypoint on wbemcomn.dll' $p 'Hijack candidate'
            }
        }
    }

    $niNames = @('Microsoft.Exchange.Data.Transport.ni.dll','Microsoft.Exchange.Search.Mdb.ni.dll',
                 'Microsoft.Exchange.EdgeSyncSvc.ni.exe','EdgeTransport.ni.exe')
    Get-ChildItem "$env:WINDIR\assembly" -Directory -Filter 'NativeImages*' -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($n in $niNames) {
            Get-ChildItem $_.FullName -Filter $n -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Test-KnownHashFile $_.FullName
                Add-Finding High NativeImage 'Exchange-named native image present' $_.FullName ("Size={0}" -f $_.Length)
                if (Test-PeNetNativeEntrypoint $_.FullName) {
                    Add-Finding Critical PE 'Native entrypoint on planted .ni image' $_.FullName
                }
            }
        }
    }
}

function Scan-Hashes {
    Write-Host "`n== Hash scan (high-value trees) ==" -ForegroundColor White
    $dirs = @(
        "$env:WINDIR\System32\wbem","$env:WINDIR\SysWOW64\wbem","$env:WINDIR\assembly",
        "$env:WINDIR\Microsoft.NET","$env:ProgramFiles\Microsoft\Exchange Server",
        "${env:ProgramFiles(x86)}\Microsoft\Exchange Server",$env:ExchangeInstallPath
    ) + $Roots | Where-Object { $_ -and (Test-Path $_) }

    foreach ($d in $dirs) {
        Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { ($SuspiciousNames -contains $_.Name) -or $_.Extension -match '\.(dll|exe|dat|bin)$' } |
            ForEach-Object {
                if ($SuspiciousNames -contains $_.Name) {
                    Test-KnownHashFile $_.FullName
                    if ($_.Extension -match '\.(dll|exe)$' -or $_.Name -match '\.ni\.(dll|exe)$') {
                        if (Test-PeNetNativeEntrypoint $_.FullName) {
                            Add-Finding High PE 'Suspicious name + native entrypoint' $_.FullName
                        }
                    }
                }
            }
    }

    if ($FullDriveHashScan) {
        Write-Host "Full-drive IoC hash scan..." -ForegroundColor Yellow
        foreach ($drive in [IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq 'Fixed' }) {
            Get-ChildItem $drive.RootDirectory.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -lt 80MB -and ($_.Extension -match '\.(dll|exe|dat)$' -or ($SuspiciousNames -contains $_.Name)) } |
                ForEach-Object { Test-KnownHashFile $_.FullName }
        }
    }
}

function Scan-HttpSys {
    if ($SkipHttpSys) { Add-Finding Info HttpSys 'Skipped' '-SkipHttpSys'; return }
    Write-Host "`n== HTTP.sys CerealNeuron prefixes ==" -ForegroundColor White
    if (-not (Test-IsAdmin)) {
        Add-Finding Medium HttpSys 'Not Administrator' 'Elevate for full servicestate/PID visibility'
    }
    $blob = ""
    try { $blob += ((netsh http show urlacl) | Out-String) } catch {}
    try { $blob += ((netsh http show servicestate view=requestq verbose=yes) | Out-String) } catch {}
    if ([string]::IsNullOrWhiteSpace($blob)) {
        Add-Finding Low HttpSys 'Empty netsh output' 'Cannot read HTTP.sys'; return
    }
    $lower = $blob.ToLowerInvariant()
    $lines = $blob -split "`r?`n"
    foreach ($pat in $UriPatterns) {
        if ($lower.Contains($pat)) {
            Add-Finding Critical HttpSys 'CerealNeuron-like URL prefix registered' $pat
            for ($i=0; $i -lt $lines.Count; $i++) {
                if ($lines[$i].ToLowerInvariant().Contains($pat)) {
                    $ctx = ($lines[[Math]::Max(0,$i-6)..([Math]::Min($lines.Count-1,$i+6))]) -join " | "
                    Add-Finding Critical HttpSys 'URL registration context (PID hunt)' $lines[$i] $ctx
                }
            }
        }
    }
}

function Scan-Processes {
    Write-Host "`n== Process module inspection ==" -ForegroundColor White
    $names = @('EdgeTransport','WmiPrvSE','Microsoft.Exchange.Search.Service','MSExchangeFrontendTransport','powershell','RuntimeBroker')
    foreach ($n in $names) {
        $procs = Get-Process -Name $n -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            Add-Finding Info Process ("Process running: {0}" -f $n) ("PID={0}" -f $p.Id)
            try {
                $mods = $p.Modules
                $hits = $mods | Where-Object {
                    $fn = $_.FileName
                    $mn = $_.ModuleName
                    # Legitimate System32\version.dll / iphlpapi.dll are common; only flag planted paths/names
                    ($mn -match '^(ncobjapi|Microsoft\.Ceres|Microsoft\.Search\.Platform|Microsoft\.Exchange\.Data\.Transport|EdgeTransport\.ni|iph\.dat)') -or
                    ($mn -ieq 'version.dll' -and $fn -notmatch '\\Windows\\(System32|SysWOW64)\\version\.dll$') -or
                    ($fn -match 'NativeImages_.*Exchange|\\wbem\\ncobjapi|\\wbem\\wbemcomn\.dll|iph\.dat')
                }
                foreach ($m in $hits) {
                    Add-Finding High Memory ("Suspicious module in {0}" -f $n) $m.FileName ("Module={0}" -f $m.ModuleName)
                    Test-KnownHashFile $m.FileName
                }
            } catch {
                Add-Finding Low Memory ("Cannot list modules for {0} PID {1}" -f $n,$p.Id) $_.Exception.Message 'Elevation/bitness may be required'
            }
        }
    }
}

function Scan-ContentStrings {
    Write-Host "`n== Content / config-key string hunt ==" -ForegroundColor White
    # Prefer planted-path trees; full ProgramData/assembly scans are too noisy/slow for a host check
    $roots = @(
        "$env:WINDIR\System32\wbem","$env:WINDIR\SysWOW64\wbem",$env:ExchangeInstallPath,
        "$env:ProgramFiles\Microsoft\Exchange Server","${env:ProgramFiles(x86)}\Microsoft\Exchange Server",$env:TEMP
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -lt 8MB -and $_.Extension -match '\.(dll|exe|config|json|xml|bin|dat|txt|log)$' } |
            Select-Object -First 1500 |
            ForEach-Object {
                foreach ($needle in $ContentNeedles) {
                    try {
                        $hit = Select-String -LiteralPath $_.FullName -Pattern $needle -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($hit) {
                            $sev = if ($needle -eq $ConfigKey -or $needle -match 'owa/sdds|PROXYSERVICE|RoutingAgentFactory') { 'High' } else { 'Medium' }
                            Add-Finding $sev Content ("String hit: {0}" -f $needle) $_.FullName ("Line={0}" -f $hit.LineNumber)
                        }
                    } catch {}
                }
            }
    }

    foreach ($root in @("$env:WINDIR\System32\wbem","$env:ProgramData",$env:TEMP,$env:ExchangeInstallPath) | Where-Object { $_ -and (Test-Path $_) }) {
        Get-ChildItem $root -Filter 'FallbackLog.bin' -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object -First 30 | ForEach-Object {
                Add-Finding Medium Artifact 'FallbackLog.bin (CerealSprinter-style)' $_.FullName ("Size={0}" -f $_.Length)
            }
    }
}

function Scan-Yara {
    if (-not $RunYara) { return }
    Write-Host "`n== YARA ==" -ForegroundColor White
    $rule = Join-Path $ScriptDir 'yara\cereal.yar'
    $exe = $YaraPath
    if (-not $exe) {
        foreach ($c in @((Join-Path $ScriptDir 'tools\yara64.exe'), "$env:ProgramFiles\YARA\yara64.exe", 'yara64.exe')) {
            if (Get-Command $c -ErrorAction SilentlyContinue) { $exe = $c; break }
            if (Test-Path $c) { $exe = $c; break }
        }
    }
    if (-not $exe -or -not (Test-Path $rule)) {
        Add-Finding Info YARA 'YARA not executed' 'Install yara64.exe under .\tools or pass -YaraPath; rules ready in yara\cereal.yar'
        return
    }
    $targets = @("$env:WINDIR\System32\wbem","$env:WINDIR\assembly",$env:ExchangeInstallPath) | Where-Object { $_ -and (Test-Path $_) }
    foreach ($t in $targets) {
        try {
            $out = & $exe -r -w $rule $t 2>$null
            foreach ($line in $out) { Add-Finding High YARA 'Rule match' $line }
        } catch {
            Add-Finding Low YARA 'YARA failed' $_.Exception.Message
        }
    }
}

function Scan-ExchangeContext {
    Write-Host "`n== Exchange context ==" -ForegroundColor White
    $paths = @(
        "$env:ExchangeInstallPath\Bin\EdgeTransport.exe",
        "$env:ProgramFiles\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe"
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path $p)) { Add-Finding Info Exchange 'EdgeTransport.exe present' $p }
    }
    if (Get-Command Get-TransportAgent -ErrorAction SilentlyContinue) {
        try {
            $agents = @(Get-TransportAgent)
            Add-Finding Info Exchange 'Transport agents enumerated' ("Count={0}" -f $agents.Count) 'CerealBox may leave this list unchanged'
        } catch {}
    }
}

# --- Main ---
Write-Host "Cereal comprehensive scanner (read-only)" -ForegroundColor Cyan
Write-Host ("Host={0} User={1} Admin={2}" -f $env:COMPUTERNAME,$env:USERNAME,(Test-IsAdmin)) -ForegroundColor DarkGray
Add-Finding Info Meta 'Scan started' 'Pattern hunter for Turla Cereal; complements AV/EDR; in-memory-only implants may still evade'

Scan-Paths
Scan-Hashes
Scan-HttpSys
Scan-Processes
Scan-ContentStrings
Scan-Yara
Scan-ExchangeContext

Write-Host "`n== Summary ==" -ForegroundColor White
foreach ($g in 'Critical','High','Medium','Low','Info') {
    $c = @($Script:Findings | Where-Object Severity -eq $g).Count
    Write-Host ("  {0,-8} {1}" -f $g,$c)
}
$bad = @($Script:Findings | Where-Object Severity -in 'Critical','High')
if ($bad.Count) {
    Write-Host "`nActionable hits:" -ForegroundColor Red
    $bad | ForEach-Object { Write-Host (" - [{0}] {1} :: {2}" -f $_.Severity,$_.Title,$_.Detail) }
    $code = 2
} else {
    Write-Host "`nNo Critical/High hits." -ForegroundColor Green
    $code = 0
}

if ($OutputJson) {
    [pscustomobject]@{
        Scanner='Scan-Cereal.ps1'; Host=$env:COMPUTERNAME
        StartedUtc=$Script:StartUtc.ToString('o'); EndedUtc=[DateTime]::UtcNow.ToString('o')
        Sha256Resolved=$KnownSha256.Count; Findings=$Script:Findings
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
    Write-Host ("JSON: {0}" -f $OutputJson) -ForegroundColor Cyan
}
exit $code
