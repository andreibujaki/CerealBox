# Cereal pattern scanner (Windows)

Read-only PowerShell hunter for **Turla Cereal** host artifacts described in ESET’s white paper *Exchange for breakfast: Turla’s Cereal tricks are not for kids*. It does **not** depend on antivirus detections.

## Layout

| Path | Purpose |
|------|---------|
| `Scan-Cereal.ps1` | Main workstation/server pattern scanner |
| `Scan-Exchange-Cereal-Deep.ps1` | Exchange-focused deep check (HTTP.sys PIDs, EdgeTransport modules, agents, YARA) |
| `iocs/cereal-iocs.json` | Full IoC pack (18 SHA-1 + verified/pending SHA-256 + URI/config indicators) |
| `iocs/hash-map.csv` | Flat hash map for spreadsheets / SIEM import |
| `yara/cereal.yar` | YARA rules (hashes, URI strings, config key, transport hooks) |
| `tools/Resolve-VtSha256.ps1` | Refresh JSON/CSV from known VT mappings |

## What it looks for

| Check | Why |
|--------|-----|
| All 18 ESET SHA-1 IoCs + resolved / hunt-set SHA-256 | CerealLoader / Runner / Sprinter / Hermit / Iron / Moth / bootstrappers |
| Extra ESET `turla/samples.sha256` Cereal-era batch | Hunt even when SHA-1 pairing is still pending |
| `ncobjapi.dll` / anomalous `wbemcomn.dll` under `System32\wbem` | DLL search-order hijack chain |
| Exchange-named files under `NativeImages_*` | Abuse of .NET native image cache |
| `.NET` PE with **native entrypoint** flag | CerealLoader mixed-mode / VTable Fixups style |
| HTTP.sys URL prefixes (`owa/sdds`, Autodiscover/ActiveSync-style paths) + context | CerealNeuron passive listener |
| Config key `B38C96AE6643D2AB5C0BFE823D9C9017` | CerealNeuron / CerealBox config dictionary |
| Process modules (`WmiPrvSE`, `EdgeTransport`, Exchange Search) | Loader / Box injection surface |
| Content strings (`RoutingAgentFactory`, `amsiInitFailed`, URI fragments) | In-memory implant leftovers on disk |
| `FallbackLog.bin` | CerealSprinter-style logging |
| Optional YARA (`-RunYara`) | Same patterns as rules file |

## Run

Open an **elevated** PowerShell (needed for full HTTP.sys visibility):

```powershell
cd D:\CerealBox
powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json
```

With YARA (requires `yara64.exe` on PATH or under `.\tools`):

```powershell
.\Scan-Cereal.ps1 -RunYara -OutputJson .\cereal-findings.json
```

Slow full-disk hash pass (optional):

```powershell
.\Scan-Cereal.ps1 -FullDriveHashScan -OutputJson .\cereal-findings.json
```

On Exchange servers:

```powershell
.\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json
```

Exit codes: `0` = no Critical/High hits, `2` = Critical/High findings.

## Verified SHA-256 pairs (VirusTotal)

| SHA-1 | SHA-256 | Role / name |
|-------|---------|-------------|
| `4A3C2639…` | `13FE1EB9…` | CerealLoader / `Microsoft.Exchange.Data.Transport.ni.dll` |
| `7742C6B0…` | `241AAC14…` | CerealLoader / `version.dll` |
| `AFE448DD…` | `D3B6065E…` | CerealLoader / `version.dll` |
| `4A650406…` | `6119D25A…` | CerealLoader / `Microsoft.Search.Platform.dll` |
| `D1E17520…` | `41164EB0…` | CerealLoader / `Microsoft.Ceres.dll` |

Remaining SHA-1↔SHA-256 pairs: ESET publishes SHA-1 only; many companion SHA-256 values from `eset/malware-ioc` are not on public VirusTotal. They remain in `additional_sha256_hunt_set` and the scanner still matches them by hash.

## Limits

- Pattern hunter, not full memory forensics. **In-memory-only** CerealRunner / CerealBox / CerealNeuron may leave little on disk.
- Legitimate Exchange native images and `wbemcomn.dll` exist; severity rises with hash match, bad signature, or native-entrypoint flag.
- No public Romanian / operator IPs (passive C2 on the victim Exchange server).
- CerealNeuron and CerealBox have **no published file hashes** — covered by URI / config / process checks and YARA.

## Related public samples

- https://hybrid-analysis.com/sample/13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0
- https://www.virustotal.com/gui/file/13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0
- https://github.com/eset/malware-ioc/blob/master/turla/samples.sha256

## LinkedIn article / translations

- English: `LinkedIn-Cereal-Detection-Article.md`
- Romanian: `LinkedIn-Cereal-Detection-Article-RO.md`
- Romanian README: `README-Cereal-Scanner-RO.md`
