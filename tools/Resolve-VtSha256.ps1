<#
.SYNOPSIS
  Refresh iocs\cereal-iocs.json and iocs\hash-map.csv from verified SHA-1↔SHA-256 pairs.
#>
[CmdletBinding()]
param(
    [string]$IocJson = ""
)
if (-not $IocJson) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $here) { $here = 'D:\CerealBox\tools' }
    $IocJson = Join-Path $here '..\iocs\cereal-iocs.json'
}

# VirusTotal UI verified pairs only
$known = @{
    '4A3C263977417FB6977B0E598C9E3BC5924F390C' = '13FE1EB9B182B076A815F84D34B66365809D0CFF32DF6F5B85AA7EF4DEEE98E0'
    '7742C6B0AAF114335CEF7EBAB11290CB18A0B8B3' = '241AAC14756A0F29EDD084B858623DB259D59C77EA44889DE93431C42FF10036'
    'AFE448DD95494CD14438F04F0C5F6B384664A3B7' = 'D3B6065EB001D169421FCD146F64B087055DADEBD973D8D69AE2BF97FBF288E2'
    '4A65040646E354303F067D47AA1C953D467F65CB' = '6119D25AE51D04264384F5D738C104E42596B0774609666B357A43608A48404C'
    'D1E17520A2435EDCDCC47F582381416FBDF75F94' = '41164EB06ADC72B187EDAF90D73CA73BE729D4EBFDECF57D7398561136941651'
}

$doc = Get-Content -LiteralPath $IocJson -Raw | ConvertFrom-Json
foreach ($f in $doc.files) {
    $s1 = $f.sha1.ToUpperInvariant()
    if ($known.ContainsKey($s1)) {
        $f.sha256 = $known[$s1]
        $f.sha256_verified = 'virustotal'
        $f.vt = "https://www.virustotal.com/gui/file/$($known[$s1].ToLowerInvariant())"
        $f.hybrid_analysis = "https://hybrid-analysis.com/sample/$($known[$s1].ToLowerInvariant())"
    }
}
$doc.updated = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
$doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $IocJson -Encoding UTF8

$rows = foreach ($f in $doc.files) {
    [pscustomobject]@{
        Role = $f.role
        Filename = $f.filename
        SHA1 = $f.sha1
        SHA256 = $f.sha256
        Verified = $f.sha256_verified
        ESET = $f.eset
        VT = $f.vt
        HA = $f.hybrid_analysis
    }
}
if ($doc.additional_sha256_hunt_set) {
    foreach ($a in $doc.additional_sha256_hunt_set) {
        $rows += [pscustomobject]@{
            Role = 'ESET-batch-hunt'
            Filename = $null
            SHA1 = $null
            SHA256 = $a.sha256
            Verified = 'hunt-set'
            ESET = $null
            VT = "https://www.virustotal.com/gui/file/$($a.sha256.ToLowerInvariant())"
            HA = "https://hybrid-analysis.com/sample/$($a.sha256.ToLowerInvariant())"
        }
    }
}
$csv = Join-Path (Split-Path $IocJson) 'hash-map.csv'
$rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
Write-Host "Updated $IocJson"
Write-Host "Wrote $csv"
$resolved = @($rows | Where-Object { $_.SHA1 -and $_.SHA256 }).Count
Write-Host "Verified SHA-1→SHA-256 pairs: $resolved / $(@($doc.files).Count)"
$rows | Where-Object SHA1 | Format-Table Role, Filename, SHA1, SHA256, Verified -AutoSize
