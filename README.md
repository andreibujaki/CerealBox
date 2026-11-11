# CerealBox — Turla Cereal host detection kit

Read-only PowerShell hunters for **Turla Cereal** patterns described in ESET Research (*Exchange for breakfast: Turla’s Cereal tricks are not for kids*). Complements antivirus/EDR; does not replace memory forensics.

## Contents

| Path | Purpose |
|------|---------|
| `Scan-Cereal.ps1` | Main host pattern scanner |
| `Scan-Exchange-Cereal-Deep.ps1` | Exchange deep check (HTTP.sys PIDs, EdgeTransport, agents, YARA) |
| `iocs/cereal-iocs.json` | IoC pack (SHA-1/SHA-256, URI prefixes, config key) |
| `iocs/hash-map.csv` | Flat hash map for SIEM / spreadsheets |
| `yara/cereal.yar` | Optional YARA rules |
| `tools/` | IoC resolve helpers |

## Quick start (elevated PowerShell)

```powershell
cd path\to\CerealBox
powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json
```

Exchange mailbox servers:

```powershell
.\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json
```

Exit codes: `0` = no Critical/High, `2` = Critical/High findings.

### Optional YARA

`yara64.exe` is **not** included in this repository. Download it from the official YARA releases: https://github.com/VirusTotal/yara/releases

Then either:

- place `yara64.exe` in `.\tools\`, or
- install under `C:\Program Files\YARA\`, or
- put it on PATH, or
- pass `-YaraPath C:\path\to\yara64.exe`

Without it, all PowerShell checks still run; only `-RunYara` is skipped.

```powershell
.\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json -RunYara
.\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json
```

## What it checks

- ESET Cereal SHA-1 IoCs + verified / hunt-set SHA-256
- `wbem` hijack paths (`ncobjapi.dll`, anomalous `wbemcomn.dll`)
- Exchange-named files under .NET `NativeImages_*`
- PE native entrypoint heuristic (CerealLoader-style)
- HTTP.sys URL prefixes used by CerealNeuron (`owa/sdds`, Autodiscover/ActiveSync-style paths)
- Config key `B38C96AE6643D2AB5C0BFE823D9C9017`
- Suspicious modules in `WmiPrvSE` / `EdgeTransport`
- Optional YARA (`-RunYara` if `yara64.exe` is available)

## Limits

- Pattern hunter, not full memory forensics. In-memory-only components may leave little on disk.
- CerealNeuron / CerealBox have no published durable file hashes in the public research — covered by URI/config/process checks.
- Authorized defensive use only on systems you own or are contracted to assess.
- Do not probe CerealNeuron URI prefixes on production hosts.

## Research credit

Cereal discovery and technical description: [ESET Research — Exchange for breakfast](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/). IoCs: [eset/malware-ioc](https://github.com/eset/malware-ioc).

## License

Defensive tooling for authorized use. No warranty.
