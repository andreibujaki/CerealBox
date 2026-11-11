# When Breakfast Is Served on Your Own Exchange Server: Building a Practical Detection Tool for Turla’s Cereal

**A long-form article about a read-only Windows hunter for Turla Cereal patterns—what ESET published, what our tool checks, how to deploy it, and where it helps.**

---

## Opening: the mail server that became the command post

Most security stories about advanced persistent threats follow a familiar script. An implant phones home. Analysts map domains and IP addresses. Blocklists grow. Infrastructure is seized. Everyone moves on.

ESET Research’s November 2026 report, *Exchange for breakfast: Turla’s Cereal tricks are not for kids*, breaks that script in a way that should make every on-premises Microsoft Exchange owner uncomfortable. The Russia-aligned group Turla (also known as Snake) fielded a modular .NET toolset—nicknamed Cereal because of its heavy use of serialization—that does not need a separate attacker-controlled command-and-control server. The victim’s own internet-facing Exchange box *is* the control plane. Operators send HTTPS requests to paths that look like Outlook Web Access, Autodiscover, or ActiveSync. A passive listener named CerealNeuron waits. If the request fails validation, the malware can redirect toward a legitimate-looking Exchange error page. If it succeeds, an in-memory command runs.

There is no beacon to catch on the way out. There is little for classic egress anomaly detection to chew on. And the mail-theft component, CerealBox, does not even register a new Exchange transport agent. It is injected into `EdgeTransport.exe` and wraps handlers that are already loaded in memory, so `Get-TransportAgent` can look completely normal while selected messages with Office or PDF attachments are copied aside for later pickup.

That combination—passive inbound control, deep Exchange internals, and .NET execution tricks that defeat casual decompilation—is exactly the kind of problem where “we have antivirus” is not a complete answer. Antivirus products matter. ESET’s own detections and telemetry are what brought Cereal into public view. But defenders who run Exchange still need something they can *run on the host*: a readable, auditable, read-only check that looks for the specific footprints Cereal leaves when it is forced to touch disk, HTTP.sys, process modules, or configuration strings.

That is why we built **CerealBox**—a small detection kit centered on `Scan-Cereal.ps1`, with an Exchange-focused companion script, a JSON indicator pack, a CSV hash map, and optional YARA rules. This article explains the threat in plain language, walks through how the tool works check by check, describes practical deployment patterns, and discusses who benefits and what the tool deliberately does *not* claim to do.

If you operate Exchange, defend government or defense networks, or simply want a concrete response to a public APT write-up instead of a vague “monitor for anomalous behavior” slide, this is for you.

---

## Part I — What Cereal is, without the folklore

### Attribution and victims, in one paragraph

ESET attributes Cereal to Turla with high confidence, citing concurrent use of another Turla-linked component and conceptual similarities to Neuron, a Turla family documented earlier by the UK NCSC. Confirmed victims in the public reporting include governmental organizations in Kazakhstan (detected late November 2025) and Romania (compromise from late December 2025). In the Romanian case, CerealBox was configured to care about mail involving NATO and EU addresses. That geopolitical framing matters for prioritization: if you are a ministry, a diplomatic mission, a defense contractor with on-prem Exchange, or a national CER that still sees Exchange CAPS in production, this is not abstract.

### The modular cast

Cereal is not one EXE with a command menu. It is a toolkit:

- **CerealLoader** — the main on-disk .NET face. It uses uncommon .NET features (including unmanaged entry points / VTable Fixups) so that native code can run before ordinary managed analysis expects anything interesting. Operators planted it as names such as `ncobjapi.dll` or `wbemcomn.dll` under `C:\Windows\System32\wbem\`, and as fake files in the .NET native image cache named like Exchange assemblies (`Microsoft.Exchange.Data.Transport.ni.dll`, `EdgeTransport.ni.exe`, and similar).
- **CerealRunner / CerealSprinter / CerealMoth** — packaging and execution helpers. Commands often arrive as disposable compiled assemblies rather than as strings inside a monolithic backdoor.
- **CerealNeuron** — passive HTTPS listener on Exchange-looking URI prefixes. No built-in command set; it executes delivered assemblies.
- **CerealHermit** — Neuron-like fallback without network listening; encrypted command files on disk.
- **CerealIron** — injector that helps get .NET assemblies into processes that are not naturally .NET hosts.
- **CerealBox** — email filter and collector inside the transport pipeline after injection into EdgeTransport.

ESET publishes SHA-1 hashes for eighteen files in its malware-ioc repository and white paper. CerealNeuron and CerealBox themselves are not handed to defenders as neat permanent file hashes, because so much of their life is in memory or encrypted containers. That asymmetry is the design challenge for any host scanner: you must hunt *patterns*, not only *sample digests*.

### Why “no C2 infrastructure” changes hunting

Security operations centers are trained to pivot on domains. Cereal denies that pivot. Operators may arrive through anonymization, through other compromised hosts, or through paths that look like mail traffic on port 443. ESET reported being unable to identify ingress operator IPs. For defenders, the implication is blunt: **hunt the host and the HTTP.sys registration surface**, not only the threat-intel feed of bad destinations.

A second implication: IIS logs may not save you. When HTTP.sys routes a request to a non-IIS request queue owned by malware, the worker process that would normally write W3SVC logs may never see the request. Zero hits in IIS logs is not a clean bill of health for CerealNeuron-style listeners. Asking HTTP.sys itself—with elevated `netsh http show servicestate`—is closer to the truth.

### .NET tricks that defeat “open it in dnSpy and look”

CerealLoader’s managed entry point can look empty. The real work starts earlier, through native entrypoint flags and VTable Fixups. Native image cache abuse means the runtime may load a planted `.ni.dll` briefly enough for malicious native code to run, then fall back to the genuine assembly for normal behavior. Search-order hijacks under `wbem` mean legitimate processes such as `WmiPrvSE.exe` become loaders. Any detection program that only greps for a hard-coded C2 string inside a single PE will miss most of this story.

### CerealBox and the polite lie of Get-TransportAgent

Exchange administrators often check transport agents after suspicious activity. CerealBox’s novelty, as ESET describes it, is that it does not need to appear as a new agent. It wraps existing handlers in memory. Configuration inventory can be honest and still useless. That is why our Exchange deep script still lists agents—as context—and then spends more energy on HTTP.sys ownership, EdgeTransport modules, and string/config indicators.

---

## Part II — Design principles of the CerealBox detection kit

We set a few non-negotiable rules before writing a line of PowerShell.

### 1. Read-only by default

The scanner does not quarantine files, does not unload modules, does not restart Exchange, and does not send network probes to CerealNeuron URI prefixes on production hosts. Probing a possible implant with live requests can tip operators and create incident noise. Collection and comparison first; remediation under IR control later.

### 2. Complement antivirus; do not pretend to replace it

ESET detections such as `MSIL/Agent.YCC`, `MSIL/Agent.YCA`, `MSIL/Agent.YBZ`, and `Win32/Agent.AIOQ` are part of the public story. Our tool assumes you may already have EDR. It exists for the gaps: pattern checks that map one-to-one onto the public technical narrative, runnable offline, inspectable by a human who does not trust opaque cloud verdicts alone.

### 3. Prefer high-signal artifacts over “suspicious everything”

Early drafts of the scanner flagged legitimate `System32\version.dll` and `iphlpapi.dll` because the module filter was too loose. That kind of false positive destroys trust. We tightened process-module matching so planted names and planted paths matter more than ubiquitous Windows DLLs. Content string hunting was narrowed away from common BCL strings such as bare `HttpListener` hits across the GAC. Severity only rises to Critical/High when evidence aligns with Cereal’s published playbook.

### 4. Make indicators portable

Hashes and URI prefixes live in `iocs/cereal-iocs.json`, not only inside the script body. A CSV export (`hash-map.csv`) supports SIEM or spreadsheet workflows. Optional YARA (`yara/cereal.yar`) mirrors the same ideas for teams that already run `yara64` in forensics pipelines.

### 5. Separate “any Windows host” from “Exchange deep dive”

`Scan-Cereal.ps1` is the general hunter. `Scan-Exchange-Cereal-Deep.ps1` spends more time on HTTP.sys PID context, EdgeTransport modules, transport agent enumeration, and Exchange path string hunts. Operators can run the general tool widely and reserve the deep script for mailbox servers.

### 6. Honest limits in the README and in the exit model

Exit code `0` means no Critical/High findings—not “Turla was never here.” Exit code `2` means actionable pattern hits. In-memory-only stages can still evade. That honesty is part of usefulness: executives and IR leads get a tool that does not overclaim.

---

## Part III — How the detection tool works, check by check

Think of `Scan-Cereal.ps1` as a short pipeline. It loads indicators, walks seven families of checks (plus a PE heuristic used inside path/hash work), accumulates findings with severity, prints a summary, and optionally writes JSON.

### Stage 0 — Load the IoC pack

On start, the script reads `iocs/cereal-iocs.json` when present. That pack includes:

- All eighteen public ESET SHA-1 IoCs, with roles (CerealLoader, CerealRunner, CerealSprinter, CerealHermit, CerealIron, CerealMoth, bootstrappers).
- VirusTotal-verified SHA-256 pairs where public resolution succeeded (for example, Loader samples named like `Microsoft.Exchange.Data.Transport.ni.dll`, `version.dll`, `Microsoft.Search.Platform.dll`, `Microsoft.Ceres.dll`).
- An `additional_sha256_hunt_set` drawn from the Cereal-era batch in ESET’s `turla/samples.sha256` list, so the hunter can still match digests even when a perfect SHA-1↔SHA-256 pairing is not yet published on VirusTotal.
- Non-file indicators: the configuration dictionary key `B38C96AE6643D2AB5C0BFE823D9C9017`, CerealNeuron URI prefix fragments, and known hijack paths.

If the JSON is missing, the script falls back to an embedded SHA-1 list so a copied script alone still has baseline coverage.

### Check 1 — Path and masquerade hunt (`Scan-Paths`)

The scanner looks for:

- `ncobjapi.dll` under `System32\wbem` and `SysWOW64\wbem` — a planted name ESET associated with WMI Provider Host loading.
- `wbemcomn.dll` under those same folders — legitimate `wbemcomn.dll` normally lives elsewhere under System32; a copy under `wbem` with a bad Authenticode status or a native .NET entrypoint is elevated.
- Exchange-named files under `NativeImages_*` directories — the native image cache abuse pattern.

For candidate PE files, it runs a lightweight PE parser looking for the CLR directory and `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` (0x10). That heuristic targets CerealLoader-style mixed-mode behavior without requiring a full reverse-engineering lab on every host.

### Check 2 — Hash hunt (`Scan-Hashes`)

High-value trees are walked: `wbem`, `assembly`, Microsoft.NET folders, Exchange install paths, and any extra roots the operator passes. Suspicious filenames (Loader masquerades, `iph.dat`, `FallbackLog.bin`, and related) are hashed with SHA-1 and SHA-256 and compared to the IoC sets. An optional `-FullDriveHashScan` switch extends hashing across fixed drives for incident response when time allows. This is deliberately optional: full-drive hashing is slow and should be a conscious choice, not a default that makes the tool unusable in a maintenance window.

### Check 3 — HTTP.sys CerealNeuron prefixes (`Scan-HttpSys`)

Using `netsh http show urlacl` and `netsh http show servicestate view=requestq verbose=yes`, the scanner searches for fragments such as:

- `owa/sdds`
- `autodiscover/microsoft.exchange.proxyservice`
- `autodiscover/integrated/api`
- `autodiscover/proxyservice`
- `microsoft-server-activesync/integrated/api`

A match is Critical. Nearby lines are captured as evidence so analysts can chase owning PIDs. Without Administrator rights, the tool warns that visibility may be incomplete—another honest signal rather than a silent miss.

This check is the heart of “the Exchange server is the C2.” It does not need operator IPs. It asks the kernel HTTP stack who registered Exchange-looking prefixes that CerealNeuron is known to use.

### Check 4 — Process module inspection (`Scan-Processes`)

Processes of interest include `EdgeTransport`, `WmiPrvSE`, Exchange Search, related transport names, and a few hosts that appear in Loader narratives. Module lists are filtered for planted names and planted paths—not for every `version.dll` on Windows. Suspicious modules are hashed against IoCs. Elevation and bitness mismatches can prevent module enumeration; those failures are recorded as Low/Info rather than inventing Critical hits.

### Check 5 — Content and config-key string hunt (`Scan-ContentStrings`)

Targeted trees (wbem, Exchange paths, temp) are scanned for high-signal strings: the config MD5 key, URI fragments, `RoutingAgentFactory`, `amsiInitFailed`, `FallbackLog.bin`, and related Autodiscover/ActiveSync path pieces. A separate pass looks for `FallbackLog.bin` by name. The scope is intentionally capped so the tool finishes in a useful time window on ordinary servers.

### Check 6 — Optional YARA (`Scan-Yara`)

With `-RunYara`, if `yara64.exe` is available and `yara/cereal.yar` exists, recursive scans run over wbem, assembly, and Exchange paths. Rules cover known SHA-256 digests, URI fragments, the config key, transport-hook string clusters, Sprinter-oriented hints, and wbem hijack path strings. YARA is optional because not every admin box has it installed; the PowerShell checks still stand alone.

### Check 7 — Exchange context (`Scan-ExchangeContext`)

The general scanner notes whether `EdgeTransport.exe` is present and, if Exchange Management Shell cmdlets exist, enumerates transport agents while reminding the analyst that CerealBox may leave that list unchanged.

### Companion — `Scan-Exchange-Cereal-Deep.ps1`

On mailbox servers, the deep script expands HTTP.sys context windows for PID hunting, inspects EdgeTransport modules more carefully, inventories agents, hunts config/URI strings under Exchange roots, and can run the same YARA pack. It is the “you are on the actual mail server” mode.

### Output model

Findings carry severity, category, title, detail, evidence, and timestamp. Console coloring helps during interactive runs. JSON output supports ticket systems and offline review. Exit `2` on Critical/High gives automation a simple gate for “page a human.”

---

## Part IV — Mapping tool checks to Cereal tradecraft

A detection tool is only as credible as its mapping to the threat. Here is the correspondence in one place.

1. Cereal behavior: Passive HTTPS on OWA/Autodiscover/ActiveSync-like prefixes
   What defenders often miss: Egress-only hunting; IIS-only log review
   CerealBox check: HTTP.sys prefix + context

2. Cereal behavior: Loader as `ncobjapi.dll` / `wbemcomn.dll` under `wbem`
   What defenders often miss: Assuming System32 DLLs are always Microsoft’s
   CerealBox check: Path + signature + hash + native entrypoint

3. Cereal behavior: Fake NativeImages named like Exchange assemblies
   What defenders often miss: Treating all `.ni.dll` as performance cache
   CerealBox check: NativeImages name hunt + hash + entrypoint

4. Cereal behavior: Unmanaged .NET entrypoint / VTable Fixups
   What defenders often miss: Managed-only triage
   CerealBox check: PE native entrypoint flag

5. Cereal behavior: Config dictionary key shared across Neuron/Box samples
   What defenders often miss: Waiting for a file hash for Neuron/Box
   CerealBox check: String hunt + YARA key rule

6. Cereal behavior: CerealBox in EdgeTransport without new agent
   What defenders often miss: Trusting `Get-TransportAgent` alone
   CerealBox check: Process modules + agent note + string hints

7. Cereal behavior: Sprinter logging name `FallbackLog.bin`
   What defenders often miss: Ignoring odd bin files
   CerealBox check: Artifact name hunt

8. Cereal behavior: Known Loader/Runner/etc. samples
   What defenders often miss: Incomplete SHA-256 coverage in some feeds
   CerealBox check: SHA-1 set + verified SHA-256 + hunt-set SHA-256

This mapping is also a teaching device. When you brief a CISO, you can point to each row and say: “ESET described this; our tool looks here.” That is more persuasive than a generic endpoint dashboard screenshot.

---

## Part V — How to deploy it

### Package contents you should treat as a unit

Copy the folder as a unit so relative paths resolve:

- `Scan-Cereal.ps1`
- `Scan-Exchange-Cereal-Deep.ps1`
- `iocs/cereal-iocs.json`
- `iocs/hash-map.csv` (optional for humans/SIEM)
- `yara/cereal.yar`
- `README-Cereal-Scanner.md`
- Optional: `tools/yara64.exe` if you want `-RunYara` without a system install

### Deployment pattern A — Manual IR on a suspect Exchange server

1. Obtain change approval and snapshot/memory capture guidance from IR before any cleanup.
2. Copy the kit to a local path (for example `C:\ProgramData\CerealBox` or a forensics USB).
3. Open an elevated PowerShell.
4. Run:

```powershell
cd C:\ProgramData\CerealBox
powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json -RunYara
powershell -ExecutionPolicy Bypass -File .\Scan-Exchange-Cereal-Deep.ps1 -OutputJson .\exchange-cereal.json -RunYara
```

5. Preserve the JSON outputs with the case ID.
6. If Critical/High hits appear, isolate per IR playbook; do not “clean in place” and destroy memory evidence.

### Deployment pattern B — Estate-wide scheduled task (detection, not prevention)

Create a scheduled task as SYSTEM or a privileged service account on Exchange servers (and optionally on jump hosts):

- Weekly or daily off-peak run of `Scan-Cereal.ps1 -OutputJson \\secure\share\%COMPUTERNAME%-cereal.json`
- Forward JSON to a SIEM via a collector, or use a simple wrapper that alerts on exit code `2`
- Keep `-FullDriveHashScan` off for routine runs; enable it only for confirmed incidents

Scheduled hunting is where honesty about false positives matters. Our severity model and tightened module filters exist so nightly runs do not cry wolf about every `version.dll`.

### Deployment pattern C — GPO or ConfigMgr package

Wrap the folder in an application package. Use a detection rule based on exit codes or on the presence of a stamped “last run” JSON. Prefer pull from an internal share over shipping the kit through untrusted channels.

### Deployment pattern D — Forensic workstation offline review

If you cannot run scripts on the Exchange server, collect:

- Output of `netsh http show servicestate view=requestq verbose=yes`
- SHA-1/SHA-256 inventories of `wbem` and `NativeImages`
- Memory image of EdgeTransport / WmiPrvSE

Then use the IoC JSON, CSV, and YARA pack on the forensic workstation. The live scripts automate that collection; the indicators still work offline.

### Deployment pattern E — Purple-team lab validation

Build a lab with synthetic artifacts: a dummy URL reservation string in a saved netsh transcript, a test file whose SHA-1 matches a published IoC in a safe directory, a PE with the native entrypoint flag. Confirm the scanner returns exit `2` and clear titles. This is how you earn trust before production.

### Privileges and execution policy

- Elevation improves HTTP.sys and module visibility.
- `-ExecutionPolicy Bypass` is for controlled IR use; prefer signed scripts in long-term enterprise deployments if your policy requires it.
- Constrained Language Mode environments may need adjustment; test before a crisis.

### What not to deploy

Do not wire the scanner to automatically delete `NativeImages` or `wbem` DLLs. Exchange search and WMI breakage is a real operational risk. Detection first; change control for remediation.

---

## Part VI — Who finds this useful, and how

### Exchange administrators

You get a concrete checklist that speaks your language: HTTP.sys, EdgeTransport, transport agents, native images. You can run it after patch weekends, after suspicious OWA behavior, or as a monthly hygiene control. Usefulness is not “find Turla every time.” Usefulness is “prove you looked for the public Cereal footprints and kept artifacts.”

### SOC analysts

JSON findings with severity and categories map into tickets. HTTP.sys context lines give PIDs to pivot in EDR. Hash matches give VirusTotal and Hybrid Analysis links already present in the IoC pack. The tool shortens the distance between “I read the WeLiveSecurity post” and “I have host evidence.”

### Incident responders

Read-only collection fits early IR. Exit codes gate automation. The deep Exchange script concentrates time on the process that matters for CerealBox. The README’s limits section helps you brief counsel and executives without overclaiming eradication.

### National CERTs and sector SOCs

Governmental Exchange estates remain common. Cereal’s public victims were governmental. A portable PowerShell kit travels better across ministries than a single-vendor console dependency. Share the IoC JSON as a living document as new SHA-256 pairs are verified.

### Security engineers building detections

Use the mapping table to write SIEM analytics: alert on HTTP.sys registrations containing `owa/sdds`; alert on `ncobjapi.dll` under `wbem`; alert on EdgeTransport loading modules from unexpected NativeImages paths. The script is a reference implementation of those ideas.

### Leadership and risk owners

The story is strategic: a capable actor used the organization’s own mail server as infrastructure and filtered NATO/EU-related mail in at least one public case. Investing in host-level Exchange hunting is proportionate. The tool is a low-cost control relative to rebuilding an Exchange server after a late discovery.

---

## Part VII — A narrative walkthrough: morning after the blog drops

Imagine a European ministry SOC on the day ESET’s post lands. Analysts forward the article in chat. Someone asks whether Romania-like targeting could apply. Someone else asks for “the IoCs.” Hashes land in a ticket. An Exchange admin asks whether they should reboot.

Instead of chaos, a prepared team copies CerealBox to the mailbox servers, runs elevated scans, and within minutes has either:

- Clean Critical/High results, with Info-level context that EdgeTransport is present and HTTP.sys was readable, or
- A Critical HTTP.sys hit with a URL fragment and a PID, or a Critical hash match under NativeImages, or a High module finding in EdgeTransport.

That difference—hours of uncertainty versus a structured host pass—is the practical usefulness of a purpose-built pattern hunter. It does not replace ESET’s research, memory forensics, or full IR. It creates a first actionable layer that matches the public technical story.

---

## Part VIII — How to talk about this without overclaiming

**Stakes:** mail that should be confidential is copied inside the transport pipeline. The C2 is your own certificate and your own hostname.

**Discipline:** you do not claim the scanner sees every in-memory Runner. You claim it hunts the footprints that ESET made public and that operators must leave if they persist Loaders or register Neuron prefixes.

**Practical next steps for defenders:**

1. Read ESET’s public post and white paper.
2. Inventory internet-facing Exchange.
3. Run a read-only HTTP.sys and Loader-path hunt this week.
4. Preserve memory before cleanup if you hit Critical findings.

---

## Part IX — Deep dive: HTTP.sys as the detective’s friend

.NET `HttpListener` sits on HTTP.sys. CerealNeuron’s prefixes therefore appear in kernel HTTP state. That is an elegant defensive coincidence. Attackers wanted to blend with Exchange HTTPS. To do so on Windows, they inherited a registration model defenders can query.

Practical tips when the scanner flags a prefix:

- Map the request queue’s controller process ID with `tasklist` / EDR.
- An IIS worker owning a site binding can be normal; an unexpected process owning an OWA subpath is not.
- Compare against a known-clean Exchange server on the same cumulative update.
- Do not send test POSTs to the prefix on production to “see what happens.”

Our scanner automates the string search and context capture so analysts spend time on PID attribution rather than on remembering which five prefixes ESET listed.

---

## Part X — Deep dive: native images and the temptation to delete

Exchange servers accumulate legitimate native images. Deleting by filename pattern is how you create a self-inflicted outage. The scanner flags Exchange-named native images as High for review and Critical when hashes or native entrypoints confirm malice. Remediation should be hash-grounded and IR-led, ideally after memory capture, and often ends in rebuild rather than surgical DLL deletion—especially when Box and Neuron may already be memory-resident.

---

## Part XI — Deep dive: indicators that will age

SHA-1 sets age when Turla recompiles. URI prefixes may rotate. The config key may change. That is why the kit keeps indicators in JSON. Update the pack when ESET’s malware-ioc repository grows. Re-run `tools/apply_vt_mappings.py` or `Resolve-VtSha256.ps1` when new VirusTotal mappings are verified. Treat the PowerShell as a stable engine and the JSON as the living brain.

Teams that fork the kit should keep a changelog of IoC updates. That discipline turns a one-off blog response into a maintained control.

---

## Part XII — Integrating with EDR and SOAR

Suggested SOAR sketch:

1. Ticket created from threat intel mentioning Cereal / Turla Exchange.
2. Automation copies kit or invokes remote PowerShell on Exchange servers in scope.
3. Parse JSON; if any Critical/High, create a Sev-1 IR case and isolate network per playbook.
4. Attach netsh context and hash hits to the case.
5. Human IR decides memory acquisition and rebuild.

EDR-side detections can mirror the same logic continuously: module load of `ncobjapi.dll` from `wbem`; script-block or command-line around suspicious `netsh` only if attackers use it (they usually do not—they register programmatically). Prefer EDR telemetry for continuous detection and the PowerShell kit for explicit, auditable hunts and air-gapped environments.

---

## Part XIII — Legal, ethical, and operational boundaries

- Run only on systems you are authorized to assess.
- Do not use the kit as a pretext to attack third-party Exchange servers.
- Do not include exploit code, implant samples, or live Neuron probes in the kit. Ours does not.
- Coordinate with privacy and legal teams when mail content may have been staged; CerealBox implies possible mail theft, which triggers notification analysis in many jurisdictions.
- Attribute carefully: a hash hit is a strong lead; URI registration deserves investigation; neither alone is a courtroom narrative without corroboration.

---

## Part XIV — Limitations, restated so nobody misses them

1. In-memory CerealRunner / CerealBox / CerealNeuron may leave sparse disk evidence.
2. Legitimate Exchange native images exist; context matters.
3. No public operator IP list accompanies CerealNeuron in the research.
4. CerealNeuron and CerealBox lack published durable file hashes in the same way Loaders do.
5. Full-drive hashing is slow; optional for a reason.
6. Without elevation, HTTP.sys and module views can be incomplete.
7. YARA needs a binary present; PowerShell checks do not.

A tool that states these limits is more useful than a product brochure that promises omniscience.

---

## Part XV — Extending the kit (ideas for builders)

Without changing the read-only ethos, future improvements could include:

- Sigma rules exporting the same HTTP.sys and path logic
- A tiny collector that only dumps netsh + hashes for offline parsing on Linux forensics hosts
- Continuous integration tests with synthetic fixtures
- Signed PowerShell and checksums for the kit itself to prevent tampering of the hunter

These are engineering next steps, not promises. The current kit already answers the immediate need created by the public report.

---

## Part XVI — Why PowerShell, deliberately

Enterprise Exchange servers already speak PowerShell. IR teams can read the script in a text editor during change review. There is no opaque driver. There is no cloud dependency for the core checks. In contested or classified networks, that matters. Creativity here is restraint: the flashy move would be a large agent platform; the useful move is a transparent script that maps onto a white paper.

---

## Part XVII — Connecting Romania, Kazakhstan, and your estate

You may not be a national government. Cereal’s techniques still transfer. Any organization with internet-facing Exchange, sensitive mail flow, and slow patch cycles shares the relevant attack surface. Turla’s targeting preferences explain *why* ESET found what it found; the techniques explain *why you should still hunt*. Use the geopolitical story for prioritization and executive attention. Use the technical story for engineering work.

---

## Part XVIII — A field guide to severity interpretation

- **Critical:** known hash; CerealNeuron-like HTTP.sys registration; native entrypoint on a planted hijack path.
- **High:** suspicious module path in EdgeTransport/WmiPrvSE; config key or URI string in an unexpected file; YARA rule match; Exchange-named native image requiring review with strong secondary signals.
- **Medium:** artifacts like FallbackLog.bin by name; incomplete elevation warnings paired with partial evidence.
- **Low/Info:** context (process running, agent count, scan started). Useful for reports; not page-worthy alone.

Train analysts on this ladder so exit code `2` remains meaningful.

---

## Part XIX — Communication templates you can reuse

**To Exchange ops:** “We will run a read-only PowerShell hunter for Turla Cereal footprints published by ESET. No mail flow changes. Elevated rights needed for HTTP.sys. JSON will be stored under the IR share.”

**To CISO:** “Public reporting shows Turla using victim Exchange as passive C2 and in-memory mail collection. We deployed a host pattern scanner aligned to those techniques. It complements EDR; it does not replace rebuild decisions if we confirm compromise.”

**To IR lead:** “If Critical HTTP.sys or hash hits appear, preserve memory for EdgeTransport and WmiPrvSE before remediation. Assume possible mail staging and credential access based on ESET’s command list description.”

---

## Part XX — Closing: breakfast, revisited

ESET’s title is memorable because it is slightly absurd: breakfast, Exchange, tricks that are not for kids. The absurdity encodes a serious idea. Espionage tooling has moved into the boring center of enterprise IT—the mail server everyone still needs, the HTTPS everyone must allow, the .NET runtime Exchange itself depends on.

Our detection kit is a sober response to that idea. It loads public indicators, asks Windows the questions the white paper implies, writes findings a human can defend, and refuses to pretend that in-memory ghosts are always visible.

If you take one action after reading: pick one Exchange server, run `Scan-Cereal.ps1` elevated with JSON output, and read the summary. If it is clean, you have a baseline artifact. If it is not, you have a head start that threat-intel slides alone would not have given you.

The operators who built Cereal invested deeply in Exchange internals and .NET obscurity. Defenders can answer with equal seriousness: not panic, not denial, but structured hunting on the host that was turned into breakfast.

---

## References and further reading

- Matías Porolli, ESET Research — *Exchange for breakfast: Turla’s Cereal tricks are not for kids* (WeLiveSecurity, 10 Nov 2026): https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
- ESET white paper — Turla Cereal tricks (technical deep dive accompanying the blog)
- ESET malware-ioc — `turla` IoCs on GitHub (SHA-1 tables and sample hash lists)
- UK NCSC — historical Neuron/Nautilus context as cited in ESET’s comparison narrative
- This repository’s `README-Cereal-Scanner.md`, `Scan-Cereal.ps1`, `Scan-Exchange-Cereal-Deep.ps1`, `iocs/cereal-iocs.json`, and `yara/cereal.yar`

---

## About the tool (short summary)

**CerealBox** is a read-only PowerShell detection kit for Windows that hunts Turla Cereal patterns described in ESET’s public research: Loader hijack paths, native image masquerades, native .NET entrypoint heuristics, CerealNeuron HTTP.sys URI prefixes, config-key strings, process module anomalies, optional YARA, and an Exchange deep-check companion. It is designed for authorized defenders, IR teams, and Exchange operators who need a concrete, inspectable host pass after reading the public report.


---

## Part XXI — A longer origin story for the kit (creative nonfiction framing)

Every detection project starts with a sentence that will not leave you alone. For us, that sentence was not “Turla is back.” It was: the victim’s Exchange server is the C2.

Once you accept that sentence, a cascade of uncomfortable questions follows. What does your SOC do when there is no domain to sinkhole? What does your firewall team block when the destination is your own VIP? What does your Exchange admin check when transport agents look pristine? What does your IR lead collect when the most important process is the same EdgeTransport.exe that has been running since the last reboot?

We did not try to answer all of those questions with a product platform. We answered them with a folder.

That choice sounds small. It is not. A folder you can copy onto a forensics USB, open in Notepad, and explain to a change board is a different kind of security control from a dashboard that only three people can authenticate into. During an APT-shaped week, the number of people who must understand the control grows: Exchange, SOC, IR, CISO staff, sometimes national CERT liaisons. Transparency becomes a feature.

The kit’s name—CerealBox—is a deliberate double meaning. In ESET’s taxonomy, CerealBox is the mail-collection module. In our kit, CerealBox is also the box of tools you carry to look for Cereal. The pun is intentional: one name for the threat component and for the defensive folder that hunts it.

Building the first version felt like translating a white paper into verbs. “Passive listener” became “query HTTP.sys.” “Native image cache abuse” became “walk NativeImages and flag Exchange-named files.” “Unmanaged entrypoint” became “parse PE CLR flags.” “No new transport agent” became “still list agents, but do not trust them as the sole signal.” Each translation discarded poetry and kept mechanism.

We also translated absence. CerealNeuron has no published durable sample hash in the same way Loaders do. That absence became string hunts, URI prefix checks, and YARA rules that look for configuration keys and path fragments. Detection engineering is often the art of turning “we do not have a hash” into “we still have a place to look.”

There were false starts. An early module filter treated ordinary Windows networking libraries as suspicious because a short pattern matched too broadly. The console lit up with High findings on healthy machines. That is how tools die in enterprises: not from missing malware, but from training humans to ignore them. We fixed the filter, reduced content-hunt noise, and re-ran until a clean lab host stayed clean. Only then did we trust Critical to mean Critical.

If you adopt the kit, you inherit that philosophy. Tune before you schedule. Baseline before you alarm. Treat the first production run as a dress rehearsal, not as a verdict on your organization’s past year.

---

## Part XXII — Tabletop exercise: four hours with CerealBox

Use this exercise with SOC, Exchange, and IR in one room (or one call).

### Hour 0 — Brief (20 minutes)

Read aloud three facts from ESET’s public reporting: (1) no external C2 observed; (2) CerealBox can collect mail without a new transport agent; (3) Loader persistence used wbem paths and NativeImages. Agree that the exercise is authorized on a lab or a designated non-production twin if possible. If you must use production, agree that the scripts are read-only and that no remediation happens during the tabletop.

### Hour 1 — Run the general scanner (40 minutes)

Execute Scan-Cereal.ps1 with JSON output elevated. Project the console. Pause on each category header. Ask the Exchange admin to explain what HTTP.sys means in their environment. Ask the SOC analyst how they would ticket a Critical URI hit. Capture questions on a shared note.

### Hour 2 — Run the Exchange deep script (40 minutes)

Execute Scan-Exchange-Cereal-Deep.ps1. Compare JSON outputs. Discuss whether EdgeTransport module enumeration succeeded. If it failed due to permissions, assign an action item—do not argue with the error; fix the access model.

### Hour 3 — Inject synthetic signals in lab only (40 minutes)

On a lab host, plant a harmless file with a known test hash or feed a saved netsh transcript containing a Cereal-like prefix into an offline review. Confirm the tool’s reaction. The point is confidence calibration, not malware handling.

### Hour 4 — Decision tree (40 minutes)

Walk the IR decision tree: memory first, isolate, assume mail exposure, assume credential exposure based on ESET’s described command types, rebuild versus clean-in-place. End with owners and dates for estate-wide scheduled hunts.

A tabletop like this turns written guidance into muscle memory.

---

## Part XXIII — Interpreting example finding shapes (illustrative)

The following examples are illustrative shapes, not screenshots from a real victim. They show how to read output.

### Shape A — Critical HTTP.sys

Severity Critical, category HttpSys, title mentioning a CerealNeuron-like URL registration, detail containing owa/sdds, evidence showing nearby Controller process ID lines.

Meaning: Something registered a prefix matching public CerealNeuron patterns.

Next: Identify PID, capture memory, compare to IIS worker expectations, escalate IR.

Not yet proven: That Turla operators are online right now.

### Shape B — Critical hash on NativeImages

Severity Critical, category Hash, path under NativeImages_v4.0.30319_64, SHA-1 matching a CerealLoader IoC.

Meaning: A published malicious digest is present where Exchange-related native images live.

Next: Preserve the file, memory of related services, do not delete ad hoc.

Watch-out: Other servers on the same CU should be compared.

### Shape C — High module in EdgeTransport

Severity High, category Memory, module path pointing at an unexpected NativeImages Exchange-named binary.

Meaning: Transport process loaded something that deserves explanation.

Next: Hash it, compare to IoCs, check Authenticode, consider dump.

Watch-out: Some environments have unusual but legitimate add-ins—prove malice.

### Shape D — Info only

EdgeTransport running, agent count listed, scan started.

Meaning: Context for the report.

Next: None for paging. Keep in the JSON for audit.

Teaching analysts these shapes prevents both panic and complacency.

---

## Part XXIV — Deployment at scale: a sample operating model

### Roles

Detection owner: maintains IoC JSON and script versions.

Exchange owner: approves elevated runs and interprets false positives related to CU-specific native images.

SOC owner: tickets Critical/High and monitors scheduled exit codes.

IR owner: defines memory capture and isolation steps.

### Cadence

Monthly: all internet-facing Exchange servers, general plus deep scripts.

Weekly: Tier-0 / government / defense mailbox servers.

Ad hoc: within 24 hours of relevant public intel.

Post-change: after major Exchange CU installs (new native images appear; baselines shift).

### Storage

Store JSON under a path like an IR share organized by year, month, and hostname, with ACL limited to IR and SOC. Retain at least 180 days so you can prove historical hunting if asked by auditors or partners.

### Metrics that matter

Percentage of Exchange servers scanned in the last 30 days.

Mean time from public intel to first estate scan.

False positive rate on Critical (target: near zero after tuning).

Time from Critical finding to memory capture.

Avoid vanity metrics like lines of script.

---

## Part XXV — Comparing approaches (without tribalism)

EDR only. Excellent for process genealogy and memory-backed detections if content packs exist. May lag on brand-new technique combinations. Our kit is a specialized lens.

Manual checklist. Print ESET’s IoCs and hunt by hand. Works for one server; fails across thirty. The script is the checklist executed.

Full disk imaging every time. Gold standard for IR confirmation; too heavy for monthly hygiene. Use after Critical hits.

Network IDS alone. Weak against passive inbound C2 on allowed 443 to your own VIP. Keep it for other threats; do not rely on it for CerealNeuron.

Our kit. Narrow, transparent, cheap to run, aligned to one public toolset. Best as a bridge between reading and responding.

The mature answer is all of the above, in layers, with CerealBox as the Exchange-shaped layer.

---

## Part XXVI — Frequently asked questions

Q: Will this find Cereal if only CerealBox is in memory and Loader was removed?

A: Maybe not. That is why memory forensics and EDR matter. The kit still looks for Neuron prefixes, config strings, and modules.

Q: Can we run it on Exchange Online?

A: No. This is for on-premises Windows hosts where you can query HTTP.sys and local disks. Cloud mailbox abuse is a different problem class.

Q: Is SHA-1 obsolete for this?

A: ESET published SHA-1. We match SHA-1 and SHA-256. Cryptographic collision concerns for APTs of this type are not the practical issue; coverage is.

Q: Why not probe the URI prefixes?

A: You might be talking to an implant on a production mail server. Collect, do not poke.

Q: Does a clean scan mean we were never compromised?

A: No. It means these pattern checks did not fire at this time.

Q: Can attackers detect the scanner?

A: They can notice PowerShell and netsh if they are live and watching. Prefer out-of-band IR discipline; still better than blind hope.

Q: How do we update IoCs?

A: Edit cereal-iocs.json, refresh CSV with the mapping tools, keep a git history if possible.

Q: May we share the kit with peer ministries?

A: Yes if your license and policy allow; keep it defensive and authorized. Credit ESET for the research.

---

## Part XXVII — Building a culture that can use tools like this

Tools fail in cultures that punish clean reports and reward only heroic compromises. If the first clean Cereal scan is treated as wasted time, teams will stop running it. Leadership should praise evidence of hunting—JSON baselines included.

Likewise, cultures that demand certainty before action will stall on HTTP.sys Critical hits. Train decision-makers: Critical pattern hits are enough to start IR, not enough to write the final attribution statement.

Cereal is a patience weapon. It is built for long-term espionage. Your hunting culture must also be patient: monthly passes, updated IoCs, post-CU baselines, and refusal to confuse “no Critical today” with “no risk this year.”

---

## Part XXVIII — Creative sidebar: five metaphors that help non-experts

1. The restaurant that takes orders at the kitchen door. CerealNeuron does not call a supplier; it waits at a side entrance labeled like a normal service corridor (OWA and Autodiscover paths).

2. The librarian who photocopies letters before mailing them. CerealBox watches the mail cart (transport pipeline) and copies interesting envelopes without adding a new clerk to the org chart (no new transport agent).

3. The spare key hidden in a jar labeled sugar. CerealLoader sits under names and folders administrators expect to be boring (wbem, NativeImages).

4. The disposable sticky note commands. CerealRunner deliveries are small purpose-built programs, not one giant remote-control app.

5. The breakfast that eats you. The title’s joke flipped: your Exchange was supposed to serve mail; it was made to serve operators.

Use metaphors in executive briefings; use hashes and PIDs in IR channels.

---

## Part XXIX — Sample internal email announcing estate deployment

Subject: Authorized monthly Turla Cereal pattern hunt on Exchange

We are deploying a read-only detection script aligned to ESET’s public Turla Cereal research. It queries HTTP.sys, hashes high-value paths, and inspects key processes. It does not change mail flow. Elevated rights are required. Outputs are JSON on the IR share. Critical/High findings open a Sev-1 IR case. First run window: insert date. Contacts: SOC, Exchange, IR. Please do not delete NativeImages or wbem files based on filenames alone.

Short emails survive. Link the long article for volunteers who want depth.

---

## Part XXXI — Hardening ideas that pair with detection (still not the scanner’s job)

Detection without hardening is incomplete. Consider, under normal change control:

Reduce internet exposure of Exchange; use modern publishing patterns and remember that a WAF may not see non-IIS HTTP.sys queues the way you hope.

Privileged access workstations for admin.

Faster CU cadence.

EDR on mailbox servers with tamper protection.

Mail flow monitoring for unusual staging directories.

Separate monitoring of HTTP.sys URL reservations if your tooling supports it.

The scanner tells you about Cereal footprints. Hardening shrinks the window in which those footprints can be planted.

---

## Part XXXII — What useful means in numbers your CFO understands

Approximate relative costs (illustrative, not a quote):

One advanced persistent compromise involving governmental mail: career-level and diplomatic cost—not cleanly priced.

Rebuild of an Exchange server and credential rotation: days to weeks of engineering time.

Monthly run of a read-only script across a small Exchange estate: minutes per host.

You do not buy CerealBox as software glamour. You buy a reduction in time-to-first-evidence after a public APT disclosure. That is a rational control even when the probability of Turla specifically choosing your organization is low, because the techniques generalize and the script cost is small.

---

## Part XXXIII — Extended technical appendix: PE native entrypoint in one accessible explanation

Ordinary managed DLLs rely on the CLR to start managed code. A mixed-mode assembly can advertise a native entrypoint. CerealLoader abuses uncommon metadata arrangements so that native code runs first and later crosses into managed methods that static managed views under-emphasize. Our scanner does not re-implement a full CLR. It checks whether a PE has a CLR directory and whether the flags field includes the native entrypoint bit. That is a coarse but useful filter when combined with location (wbem, NativeImages) and hash matching. Think of it as a smoke alarm, not a laboratory mass spectrometer.

Analysts who want deeper intuition should read ESET’s white paper sections on VTable Fixups and then compare a clean managed DLL with a mixed-mode sample in a lab. The scanner exists so that every Exchange admin does not need to become a .NET runtime expert before the first hunt.

---

## Part XXXV — Extended appendix: why Autodiscover-looking paths are psychologically perfect

Autodiscover exists to help clients find endpoints. Operators abuse that expectation. Defenders reviewing 443 logs see path shapes they have been trained to treat as plumbing. CerealNeuron’s public prefixes live in that psychological blind spot. The scanner’s value is partly emotional: it forces a deliberate search for strings your eyes would skip.

The same psychology applies to ActiveSync-looking integrated API paths. Mobile mail is noisy. Noise is camouflage. A dedicated string hunt against HTTP.sys state cuts through that camouflage without requiring you to read every proxy log line by eye.

---

## Part XXXVI — A week-one adoption plan you can copy

Day 1: Read ESET’s WeLiveSecurity article. Skim the white paper’s IoC and Neuron prefix sections. Inventory internet-facing Exchange servers.

Day 2: Copy the CerealBox folder to a lab Exchange or a test Windows Server. Run Scan-Cereal.ps1 elevated. Confirm exit 0 on a clean host.

Day 3: Peer-review the script with Exchange ops. Agree on JSON retention path and who gets Critical pages.

Day 4: Run on one production mailbox server during a change window. Save JSON. Discuss findings—even Info findings—for fifteen minutes.

Day 5: Schedule monthly tasks for the estate. Document the operating model. Draft the internal announcement email.

Day 6: Optional YARA enablement if yara64 is approved in your environment.

Day 7: Present a one-slide summary to leadership: what Cereal is, what you ran, what you will run monthly, what you will do on Critical.

This is how articles become programs.

---

## Part XXXVII — Closing reprise (for readers who scrolled)

Turla’s Cereal toolset, as documented by ESET Research in November 2026, turned compromised Exchange servers into passive control points and silent mail filters. Our CerealBox detection kit answers with a read-only PowerShell hunter: IoC-loaded checks for Loader paths, hashes, HTTP.sys prefixes, process modules, config strings, optional YARA, and an Exchange deep companion. Deploy it elevated, schedule it on mailbox servers, tune false positives seriously, and escalate Critical findings to IR with memory preservation. It will not see every ghost in RAM. It will give you a structured, explainable pass that matches the public technical story—and that is a solid day’s work in a world where breakfast is served from your own mail server.

If you write an internal follow-up, describe your first clean baseline or your first tabletop—not a boast about catching a nation-state on day one. Credibility compounds slower than malware spreads, but it compounds.

---

## Appendix A — Quick command card

General host hunt:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json

With YARA:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -RunYara -OutputJson .\cereal-findings.json

Incident full hash pass:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -FullDriveHashScan -OutputJson .\cereal-findings.json

Exchange deep:

powershell -ExecutionPolicy Bypass -File .\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json

Exit codes: 0 = no Critical/High; 2 = Critical/High present.

---

## Appendix B — Glossary for mixed audiences

Turla / Snake: Russia-aligned APT group, long-running espionage actor.

Cereal: ESET’s name for this modular Exchange-focused toolset.

CerealNeuron: Passive HTTPS backdoor component.

CerealBox: In-memory mail collection component inside EdgeTransport.

CerealLoader: On-disk .NET loader using advanced execution tricks.

HTTP.sys: Windows kernel HTTP stack used by IIS and HttpListener.

NativeImages: .NET precompiled assembly cache.

IoC: Indicator of compromise (hash, path, string, pattern).

IR: Incident response.

CU: Exchange Cumulative Update.

---

## Appendix D — Ethical closing note

Public APT reporting exists so defenders can act. Acting means authorized hunting, careful communication, and respect for victims—including governments that already had a bad year. Use this article and this tool in that spirit. Credit researchers. Share improvements. Do not turn someone else’s intrusion into engagement bait without purpose.

---

*End of article draft.*


---

## Part XXXVIII — A defender’s reading of ESET’s key points (paraphrased for action)

This section does not reproduce ESET’s article. It converts public key points into defender actions that CerealBox supports.

Key point: an undocumented modular toolset appeared at a governmental organization, then another.  
Action: treat Cereal as estate-relevant for government and adjacent sectors; run estate hunts, not single-host curiosity.

Key point: long-term cyberespionage design on Exchange.  
Action: schedule recurring hunts; one scan is a sample, not a program.

Key point: no external network infrastructure observed; passive backdoor on Exchange.  
Action: prioritize HTTP.sys and inbound path analysis over egress domain blocklists for this threat class.

Key point: commands arrive as separate executables with similar structure.  
Action: expect hash diversity; keep IoC packs updated; do not rely on a single SHA-256 forever.

Key point: automated email collection via injection into Exchange transport.  
Action: EdgeTransport module inspection and memory readiness; do not trust agent lists alone.

Key point: .NET tricks including unmanaged entry points and native image cache abuse.  
Action: PE native entrypoint heuristic plus NativeImages path hunting.

Each bullet is a bridge from journalism to operations. CerealBox is the scaffolding under those bridges.

---

## Part XXXIX — Final invitation

If you have read this far, you are the audience that actually runs the scripts. Thank you for that patience. The industry produces more screenshots than hunts. Be the exception this month: elevate, run, save JSON, schedule the next one, and teach one colleague what HTTP.sys has to do with a breakfast metaphor.

When the next Exchange-centered APT write-up arrives—and it will—you will already own a pattern for response: read, map, script, baseline, escalate. CerealBox is one instance of that pattern. Steal the pattern even if you replace every line of PowerShell with your own.

The operators who built Cereal were creative inside the Windows and Exchange manuals almost nobody reads for fun. Meeting that creativity requires defenders who can be creative without being reckless: read-only first, evidence-preserving always, and humble about the ghosts that only memory will show.

Then go scan an Exchange server you are authorized to defend.

---



---

## Part XLI — Workshop script: teaching CerealBox in ninety minutes

Minute 0-10: Show ESET headline and the sentence about Exchange as C2. Ask the room what their current hunt would be. Write answers on a board. Most rooms list domains, IDS, and antivirus. Circle the gaps.

Minute 10-25: Walk the component diagram at a high level: Loader, Neuron, Box, Iron, Runner. No need for full white-paper depth. Stop when everyone can say which component is passive and which steals mail.

Minute 25-40: Live demo on a lab VM. Run Scan-Cereal.ps1. Show JSON. Show exit code. Intentionally run without elevation once to show the Medium warning about HTTP.sys. Teach honesty about privileges.

Minute 40-55: Break into pairs. Each pair gets a printed finding shape (Critical HTTP.sys, Critical hash, High module, Info only). They must write the next three IR actions. Reconvene and compare.

Minute 55-70: Exchange deep script demo. Discuss Get-TransportAgent limitations. Ask an Exchange admin to react in real time. Capture myths.

Minute 70-85: Draft a thirty-day adoption plan on sticky notes: who owns IoCs, who approves elevation, where JSON lives, what Sev-1 means.

Minute 85-90: Closing: credit ESET, restate limits, assign a date for the first production baseline scan.

Workshops create shared language. Shared language makes Critical findings pageable without panic.

---

## Part XLII — Risk register language you can paste into GRC tools

Risk title: On-premises Exchange abuse by passive APT tooling similar to Turla Cereal.

Description: A capable actor may turn internet-facing Exchange into a passive command channel and may collect mail from the transport pipeline without registering a new transport agent.

Existing controls: EDR, antivirus, CU process, network monitoring, admin tiering.

Control enhancement: Monthly read-only CerealBox pattern hunts on mailbox servers; IoC updates within seven days of public intel; IR playbook for Critical HTTP.sys or Loader hash hits including memory capture before remediation.

Residual risk: In-memory-only stages may evade host pattern hunting; residual risk accepted with compensating EDR and network publishing reductions.

Owner: insert role. Review cycle: quarterly.

GRC teams appreciate concrete control statements. Give them one.

---

## Part XLIII — Notes for translators and local CERTs

If you translate this article, keep technical identifiers unchanged: file names, URI fragments, hash algorithms, script names, and ESET detection names. Translate metaphors carefully; breakfast jokes do not land equally in every language. Always keep the authorization warning: defensive use only on systems you own or are contracted to assess.

National CERTs may wish to distribute the IoC JSON through existing sector channels. Pair distribution with the limits section so recipients do not treat a clean scan as a certificate of health for political reporting.

---

## Part XLIV — Afterword

Detection engineering is a craft of attention. Cereal rewards attackers who pay attention to Exchange internals. CerealBox is our attempt to pay attention back—with scripts that can be read, mapped, scheduled, and improved. If this long article helped you see the shape of that attention clearly enough to run a single elevated scan this week, it did its job. If it also helped you teach someone else why HTTP.sys matters when a blog says there is no C2 server, it did something rarer.

Thank you for reading carefully. Now go defend a mail server.


*Document complete.*


---

## Part XLV — A second closing for the people who skim

Skimmers: here is the article in twelve lines.

1. ESET published Turla Cereal research in November 2026.
2. Exchange can be the passive C2.
3. CerealBox (malware) steals mail inside EdgeTransport without a new agent.
4. CerealLoader persists via wbem paths and NativeImages tricks.
5. We built CerealBox (tool): read-only PowerShell hunting.
6. It loads IoCs from JSON and optional YARA.
7. It checks paths, hashes, HTTP.sys, modules, strings, Exchange context.
8. Deep script exists for mailbox servers.
9. Deploy elevated; schedule monthly; keep JSON.
10. Exit 2 means Critical or High—start IR, preserve memory.
11. Limits: in-memory ghosts may hide; clean is not never-compromised.
12. Credit ESET; hunt authorized hosts only.

If you only needed those twelve lines, you still need to run the tool. Skimming is not scanning.

---

## Part XLVI — Acknowledgments style paragraph you may customize

We thank ESET Research, especially the public work by Matias Porolli and colleagues, for documenting Cereal with enough technical clarity that defenders can build host checks. We thank Exchange administrators who review detection scripts before production, SOC analysts who demand low false positives, and IR leads who insist on memory-first discipline. Any errors in this article are ours. The threat belongs to the operators who built Cereal. The responsibility to hunt belongs to those of us who keep mail flowing for everyone else.

---

## Part XLVII — Versioning note for the article and the tool

Articles age. Tools age faster. When you circulate an updated version, state the date and the tool version or commit if you have one. When IoCs update, issue a short follow-up rather than silently rewriting history in ways readers cannot see. Detection content deserves the same change hygiene as code.

Suggested footer: Published November 2026. Tool path: Scan-Cereal.ps1 with cereal-iocs.json. Research basis: ESET WeLiveSecurity Cereal article and white paper. Defensive use only.



---

## Part XLVIII — One last practical inventory before you leave the page

Ask yourself, on paper:

How many internet-facing Exchange servers do we still run?

Who can elevate on them this week?

Where would JSON hunt results be stored so IR can find them in a year?

Which EDR console would we open if HTTP.sys returned a Neuron-like prefix tomorrow?

Have we told leadership that Get-TransportAgent can look normal during CerealBox-style abuse?

Do we have a memory capture method that works on EdgeTransport at our scale?

Is our CU process fast enough that NativeImages baselines are even knowable?

Who updates IoCs when ESET’s malware-ioc repository changes?

Who is allowed to say the word rebuild without a three-week argument?

If you cannot answer two or more of these, the article’s next reader should be your Exchange owner, not a marketing channel. Estate clarity comes first.

When those answers exist, CerealBox becomes easy to deploy: a folder, a schedule, a severity model, and a habit of looking where the public research said to look. That habit—more than any single script—is what turns breakfast metaphors into defended mail.



---

## End matter

This long-form article is intended for authorized defenders, detection engineers, Exchange operators, and security leaders. It summarizes public ESET Research findings on Turla's Cereal toolset and describes a read-only PowerShell detection kit—CerealBox—including how the scanner works, how it can be deployed, and why it is useful as a complement to antivirus and EDR. It does not provide malware, exploits, or attack instructions. Always validate scripts in a lab, follow your change process, and preserve forensic evidence before remediation. For the primary public research narrative, read ESET's WeLiveSecurity article and the accompanying white paper. For operational commands and file layout, see README-Cereal-Scanner.md in the kit folder.

Stay curious. Stay authorized. Keep the mail flowing for the right people only.





If you improve the kit, document your changes, test on clean hosts, and share defensive improvements with trusted peers. The goal is shorter time from public research to host evidence—not louder marketing. Run the scanner, read the JSON, and keep Exchange boring again.
