<#
.SYNOPSIS
  Exchange-focused deep checks for CerealNeuron / CerealBox patterns.

.DESCRIPTION
  Run elevated on Exchange servers. Complements Scan-Cereal.ps1 with:
  - HTTP.sys URL groups + owning PIDs
  - EdgeTransport loaded modules
  - Transport agent inventory
  - Config key string hits under Exchange paths
  - Optional YARA scan of Exchange Bin + NativeImages

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Scan-Exchange-Cereal-Deep.ps1 -OutputJson .\exchange-cereal.json
#>
[CmdletBinding()]
param(
    [string]$OutputJson = "",
    [switch]$RunYara,
    [string]$YaraPath = ""
)

$ErrorActionPreference = 'Continue'
$Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param($Severity,$Category,$Title,$Detail,$Evidence="")
    $Findings.Add([pscustomobject]@{
        Severity=$Severity; Category=$Category; Title=$Title; Detail=$Detail; Evidence=$Evidence
        Timestamp=[DateTime]::UtcNow.ToString('o')
    }) | Out-Null
    Write-Host ("[{0}] {1}: {2}" -f $Severity,$Category,$Title)
    if ($Detail) { Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$uriNeedles = @(
    'owa/sdds',
    'autodiscover/microsoft.exchange.proxyservice',
    'autodiscover/integrated/api',
    'autodiscover/proxyservice',
    'microsoft-server-activesync/integrated/api'
)

Write-Host "Exchange Cereal deep check" -ForegroundColor Cyan
Write-Host ("Admin={0} Host={1}" -f (Test-IsAdmin), $env:COMPUTERNAME) -ForegroundColor DarkGray

if (-not (Test-IsAdmin)) {
    Add-Finding 'Medium' 'Meta' 'Not elevated' 'Re-run as Administrator for complete HTTP.sys and module visibility'
}

# --- HTTP.sys with PID mapping ---
Write-Host "`n== HTTP.sys request queues ==" -ForegroundColor White
$svc = ""
try { $svc = (netsh http show servicestate view=requestq verbose=yes) | Out-String } catch {}
if ($svc) {
    $lower = $svc.ToLowerInvariant()
    foreach ($n in $uriNeedles) {
        if ($lower.Contains($n)) {
            Add-Finding 'Critical' 'HttpSys' 'CerealNeuron-like URL registration' $n 'Inspect owning process below'
        }
    }
    # Parse rough PID lines near registered URLs
    $lines = $svc -split "`r?`n"
    for ($i=0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match 'Request queue name|Controller process ID|Process IDs|Registered URL') {
            # emit context window for analyst
        }
        foreach ($n in $uriNeedles) {
            if ($line.ToLowerInvariant().Contains($n)) {
                $ctx = ($lines[[Math]::Max(0,$i-8)..([Math]::Min($lines.Count-1,$i+8))]) -join "`n"
                Add-Finding 'Critical' 'HttpSys' 'URL match context' $line $ctx
            }
        }
    }
} else {
    Add-Finding 'Low' 'HttpSys' 'Empty netsh servicestate' 'Unable to read HTTP.sys state'
}

# --- EdgeTransport modules ---
Write-Host "`n== EdgeTransport process modules ==" -ForegroundColor White
$et = Get-Process -Name EdgeTransport -ErrorAction SilentlyContinue
if (-not $et) {
    Add-Finding 'Info' 'Exchange' 'EdgeTransport not running' 'CerealBox requires injection into EdgeTransport.exe'
} else {
    foreach ($p in $et) {
        Add-Finding 'Info' 'Exchange' 'EdgeTransport running' ("PID={0}" -f $p.Id)
        try {
            $mods = $p.Modules | Select-Object ModuleName, FileName, Size
            $suspicious = $mods | Where-Object {
                $fn = $_.FileName; $mn = $_.ModuleName
                ($mn -match '^(ncobjapi|Microsoft\.Ceres|Microsoft\.Search\.Platform|Microsoft\.Exchange\.Data\.Transport|EdgeTransport\.ni|iph\.dat)') -or
                ($mn -ieq 'version.dll' -and $fn -notmatch '\\Windows\\(System32|SysWOW64)\\version\.dll$') -or
                ($fn -match 'NativeImages_.*Exchange|\\wbem\\ncobjapi|iph\.dat')
            }
            foreach ($m in $suspicious) {
                Add-Finding 'High' 'Memory' 'Suspicious module in EdgeTransport' $m.FileName ("Module={0}; Size={1}" -f $m.ModuleName, $m.Size)
            }
            # Count of modules for baseline
            Add-Finding 'Info' 'Memory' 'EdgeTransport module count' ("PID={0}; Modules={1}" -f $p.Id, @($mods).Count)
        } catch {
            Add-Finding 'Medium' 'Memory' 'Cannot enumerate EdgeTransport modules' $_.Exception.Message 'Likely need elevation / same bitness'
        }
    }
}

# --- Transport agents (if Exchange cmdlets available) ---
Write-Host "`n== Transport agents ==" -ForegroundColor White
try {
    if (Get-Command Get-TransportAgent -ErrorAction SilentlyContinue) {
        $agents = Get-TransportAgent
        Add-Finding 'Info' 'Exchange' 'Transport agents listed' (("Count={0}" -f @($agents).Count))
        # CerealBox does NOT register a new agent; unexpected agents still worth listing
        $agents | ForEach-Object {
            Add-Finding 'Info' 'Exchange' 'TransportAgent' ("{0} Enabled={1}" -f $_.Identity, $_.Enabled) $_.TransportAgentFactory
        }
        Add-Finding 'Info' 'Exchange' 'Note' 'CerealBox hijacks existing RoutingAgentFactory handlers in memory; Get-TransportAgent may look normal'
    } else {
        Add-Finding 'Info' 'Exchange' 'Get-TransportAgent unavailable' 'Load Exchange Management Shell on an Exchange server for agent inventory'
    }
} catch {
    Add-Finding 'Low' 'Exchange' 'Transport agent query failed' $_.Exception.Message
}

# --- Config key string hunt under Exchange ---
Write-Host "`n== Config key / URI string hunt ==" -ForegroundColor White
$roots = @(
    $env:ExchangeInstallPath,
    "$env:ProgramFiles\Microsoft\Exchange Server",
    "$env:WINDIR\assembly",
    "$env:WINDIR\System32\wbem"
) | Where-Object { $_ -and (Test-Path $_) }

$patterns = @('B38C96AE6643D2AB5C0BFE823D9C9017','owa/sdds','RoutingAgentFactory','FallbackLog.bin')
foreach ($root in $roots) {
    foreach ($pat in $patterns) {
        try {
            Get-ChildItem -Path $root -Recurse -Include *.dll,*.exe,*.config,*.json,*.xml,*.bin,*.dat -ErrorAction SilentlyContinue |
                Select-Object -First 4000 |
                ForEach-Object {
                    try {
                        $hit = Select-String -LiteralPath $_.FullName -Pattern $pat -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($hit) {
                            Add-Finding 'High' 'Content' ("String hit: {0}" -f $pat) $_.FullName ("Line={0}" -f $hit.LineNumber)
                        }
                    } catch {}
                }
        } catch {}
    }
}

# --- YARA optional ---
if ($RunYara) {
    $yaraExe = $YaraPath
    if (-not $yaraExe) {
        $yaraExe = @(
            "$PSScriptRoot\tools\yara64.exe",
            "$env:ProgramFiles\YARA\yara64.exe",
            "yara64.exe"
        ) | Where-Object { $_ -and (Get-Command $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
    }
    $rule = Join-Path $PSScriptRoot 'yara\cereal.yar'
    if ($yaraExe -and (Test-Path $rule)) {
        $scanRoots = @($env:ExchangeInstallPath, "$env:WINDIR\System32\wbem", "$env:WINDIR\assembly") | Where-Object { $_ -and (Test-Path $_) }
        foreach ($r in $scanRoots) {
            Write-Host ("YARA scan: {0}" -f $r) -ForegroundColor Yellow
            try {
                $yr = & $yaraExe -r -w $rule $r 2>$null
                foreach ($line in $yr) {
                    Add-Finding 'High' 'YARA' 'Rule match' $line
                }
            } catch {
                Add-Finding 'Low' 'YARA' 'YARA execution failed' $_.Exception.Message
            }
        }
    } else {
        Add-Finding 'Info' 'YARA' 'YARA not available' 'Place yara64.exe in .\tools or pass -YaraPath; rules are in .\yara\cereal.yar'
    }
}

Write-Host "`n== Summary ==" -ForegroundColor White
$Findings | Group-Object Severity | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name, $_.Count) }
if ($OutputJson) {
    [pscustomobject]@{ Host=$env:COMPUTERNAME; EndedUtc=[DateTime]::UtcNow.ToString('o'); Findings=$Findings } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
    Write-Host ("JSON: {0}" -f $OutputJson) -ForegroundColor Cyan
}

if (@($Findings | Where-Object Severity -in 'Critical','High').Count -gt 0) { exit 2 } else { exit 0 }
