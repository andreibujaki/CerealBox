# Scanner de tipare Cereal (Windows)

Instrument PowerShell, doar citire, pentru artefacte gazdă **Turla Cereal** descrise în lucrarea ESET *Exchange for breakfast: Turla’s Cereal tricks are not for kids*. **Nu** depinde de detecții antivirus.

## Structură

| Cale | Scop |
|------|------|
| `Scan-Cereal.ps1` | Scanner principal pentru stații/servere |
| `Scan-Exchange-Cereal-Deep.ps1` | Verificare profundă Exchange (PID-uri HTTP.sys, module EdgeTransport, agenți, YARA) |
| `iocs/cereal-iocs.json` | Pachet IoC complet (18 SHA-1 + SHA-256 verificate/în așteptare + URI/config) |
| `iocs/hash-map.csv` | Hartă de hash-uri pentru foi de calcul / import SIEM |
| `yara/cereal.yar` | Reguli YARA (hash-uri, șiruri URI, cheie config, cârlige transport) |
| `tools/Resolve-VtSha256.ps1` | Reîmprospătare JSON/CSV din mapări VT cunoscute |

## Ce caută

| Verificare | De ce |
|--------|-----|
| Toate cele 18 IoC SHA-1 ESET + SHA-256 rezolvate / set de vânătoare | CerealLoader / Runner / Sprinter / Hermit / Iron / Moth / bootstrapperi |
| Lot suplimentar ESET `turla/samples.sha256` din era Cereal | Vânează chiar dacă împerecherea SHA-1 încă lipsește |
| `ncobjapi.dll` / `wbemcomn.dll` anomal sub `System32\wbem` | Lanț de hijack DLL search-order |
| Fișiere cu nume Exchange sub `NativeImages_*` | Abuz al cache-ului de imagini native .NET |
| PE `.NET` cu steag **native entrypoint** | Stil CerealLoader mixed-mode / VTable Fixups |
| Prefixuri URL HTTP.sys (`owa/sdds`, căi Autodiscover/ActiveSync) + context | Ascultător pasiv CerealNeuron |
| Cheie config `B38C96AE6643D2AB5C0BFE823D9C9017` | Dicționar config CerealNeuron / CerealBox |
| Module de proces (`WmiPrvSE`, `EdgeTransport`, Exchange Search) | Suprafață de injecție Loader / Box |
| Șiruri de conținut (`RoutingAgentFactory`, `amsiInitFailed`, fragmente URI) | Urme pe disc ale implanturilor din memorie |
| `FallbackLog.bin` | Jurnalizare stil CerealSprinter |
| YARA opțional (`-RunYara`) | Aceleași tipare ca în fișierul de reguli |

## Rulare

Deschideți un PowerShell **ridicat** (necesar pentru vizibilitate completă HTTP.sys):

```powershell
cd D:\CerealBox
powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json
```

Cu YARA (necesită `yara64.exe` pe PATH sau în `.\tools`):

```powershell
.\Scan-Cereal.ps1 -RunYara -OutputJson .\cereal-findings.json
```

Trecere lentă pe tot discul (opțional):

```powershell
.\Scan-Cereal.ps1 -FullDriveHashScan -OutputJson .\cereal-findings.json
```

Pe servere Exchange:

```powershell
.\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json
```

Coduri de ieșire: `0` = fără rezultate Critical/High, `2` = rezultate Critical/High.

## Perechi SHA-256 verificate (VirusTotal)

| SHA-1 | SHA-256 | Rol / nume |
|-------|---------|-------------|
| `4A3C2639…` | `13FE1EB9…` | CerealLoader / `Microsoft.Exchange.Data.Transport.ni.dll` |
| `7742C6B0…` | `241AAC14…` | CerealLoader / `version.dll` |
| `AFE448DD…` | `D3B6065E…` | CerealLoader / `version.dll` |
| `4A650406…` | `6119D25A…` | CerealLoader / `Microsoft.Search.Platform.dll` |
| `D1E17520…` | `41164EB0…` | CerealLoader / `Microsoft.Ceres.dll` |

Restul perechilor SHA-1↔SHA-256: ESET publică doar SHA-1; multe valori SHA-256 însoțitoare din `eset/malware-ioc` nu sunt pe VirusTotal public. Rămân în `additional_sha256_hunt_set`, iar scannerul le potrivește totuși după hash.

## Limite

- Vânător de tipare, nu forensic de memorie complet. CerealRunner / CerealBox / CerealNeuron **doar în memorie** pot lăsa puțin pe disc.
- Există imagini native Exchange legitime și `wbemcomn.dll` legitim; severitatea crește la potrivire de hash, semnătură invalidă sau steag native-entrypoint.
- Nu există IP-uri publice românești / de operator (C2 pasiv pe Exchange-ul victimei).
- CerealNeuron și CerealBox **nu au hash-uri de fișier publicate** — acoperite prin verificări URI / config / proces și YARA.

## Mostre publice conexe

- https://hybrid-analysis.com/sample/13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0
- https://www.virustotal.com/gui/file/13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0
- https://github.com/eset/malware-ioc/blob/master/turla/samples.sha256

## Articol LinkedIn

- Engleză: `LinkedIn-Cereal-Detection-Article.md`
- Română: `LinkedIn-Cereal-Detection-Article-RO.md`
