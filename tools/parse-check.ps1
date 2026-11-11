$files = @(
    'D:\CerealBox\Scan-Cereal.ps1',
    'D:\CerealBox\Scan-Exchange-Cereal-Deep.ps1',
    'D:\CerealBox\tools\Resolve-VtSha256.ps1'
)
$fail = $false
foreach ($f in $files) {
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
    if ($err -and $err.Count) {
        Write-Host "FAIL $f"
        $err | ForEach-Object { Write-Host $_.Message }
        $fail = $true
    } else {
        Write-Host "OK   $f"
    }
}
if ($fail) { exit 1 } else { exit 0 }
