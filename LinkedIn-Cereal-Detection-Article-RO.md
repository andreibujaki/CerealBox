# Când micul dejun este servit pe propriul server Exchange: construirea unui instrument practic de detectare pentru Cereal de la Turla

**Un articol de lungă durată despre un vânător doar-în-citire Windows pentru tiparele Turla Cereal—ce a publicat ESET, ce verifică instrumentul nostru, cum se implementează și unde este util.**

---

## Deschidere: serverul de e-mail care a devenit postul de comandă

Cele mai multe povești de securitate despre amenințările persistente avansate urmează un scenariu familiar. Un implant se conectează la sursă. Analiștii cartografiază domeniile și adresele IP. Listele de blocare cresc. Infrastructura este preluată. Toată lumea trece mai departe.

Raportul din noiembrie 2026 al ESET Research, *Exchange for breakfast: Turla’s Cereal tricks are not for kids*, rupe acel scenariu într-un mod care ar trebui să-i facă pe toți proprietarii de Microsoft Exchange on-premises să se simtă inconfortabil. Grupul Turla, aliniat Rusiei (cunoscut și ca Snake), a lansat un set de instrumente modulare .NET — poreclit Cereal datorită utilizării intense a serializării — care nu necesită un server de comandă și control separat, controlat de atacator. Propriul server Exchange al victimei, expus pe internet, *este* planul de control. Operatorii trimit cereri HTTPS către căi care arată ca Outlook Web Access, Autodiscover sau ActiveSync. Un ascultător pasiv numit CerealNeuron așteaptă. Dacă cererea eșuează la validare, malware-ul poate redirecționa către o pagină de eroare Exchange cu aspect legitim. Dacă reușește, rulează o comandă în memorie.

Nu există niciun beacon de interceptat la ieșire. Detecția clasică a anomaliilor de egress are puțin la ce să se agațe. Iar componenta de furt de corespondență, CerealBox, nici măcar nu înregistrează un agent de transport Exchange nou. Este injectată în `EdgeTransport.exe` și înfășoară handleri deja încărcați în memorie, astfel încât `Get-TransportAgent` poate părea complet normal în timp ce mesajele selectate cu atașamente Office sau PDF sunt copiate pentru ridicare ulterioară.

Această combinație — control inbound pasiv, adâncime în componentele interne Exchange și trucuri de execuție .NET care înfrâng decompilarea casuală — este exact genul de problemă pentru care „avem antivirus” nu este un răspuns complet. Produsele antivirus contează. Detectările și telemetria proprii ESET sunt cele care au adus Cereal în vizibilitatea publică. Dar apărătorii care rulează Exchange au în continuare nevoie de ceva ce pot *rula pe gazdă*: o verificare lizibilă, auditabilă, doar în citire, care caută urmele specifice pe care Cereal le lasă când este forțat să atingă discul, HTTP.sys, modulele de proces sau șirurile de configurare.

De aceea am construit **CerealBox** — un kit mic de detecție centrat pe `Scan-Cereal.ps1`, cu un script companion axat pe Exchange, un pachet de indicatori JSON, o hartă CSV de hash-uri și reguli YARA opționale. Acest articol explică amenințarea într-un limbaj clar, parcurge modul în care funcționează instrumentul verificare cu verificare, descrie modele practice de implementare și discută cine beneficiază și ce instrumentul pretinde în mod deliberat că *nu* face.

Dacă operați Exchange, apărați rețele guvernamentale sau de apărare sau pur și simplu doriți un răspuns concret la o prezentare publică APT în loc de un slide vag „monitorizați comportamentele anormale”, acest lucru este pentru dvs.

---

## Partea I — Ce este Cereal, fără folclor

### Atribuiri și victime, într-un singur paragraf

ESET atribuie Cereal lui Turla cu un grad mare de încredere, citând utilizarea concurentă a unui alt component legat de Turla și asemănări conceptuale cu Neuron, o familie Turla documentată anterior de NCSC din Marea Britanie. Victimele confirmate în rapoartele publice includ organizații guvernamentale din Kazakhstan (detectate la sfârșitul lui noiembrie 2025) și Romania (compromitere de la sfârșitul lui decembrie 2025). În cazul Romania, CerealBox a fost configurat să urmărească corespondența implicând NATO și adrese din UE. Această încadrare geopolitică contează pentru prioritizare: dacă sunteți un minister, o misiune diplomatică, un contractor de apărare cu Exchange local sau un CER național care încă vede CAPS Exchange în producție, acesta nu este un concept abstract.

### Distribuția modulară

Cereal nu este un singur EXE cu un meniu de comenzi. Este un set de instrumente:

- **CerealLoader** — principala față .NET de pe disc. Folosește caracteristici .NET neobișnuite (inclusiv puncte de intrare negestionate / VTable Fixups) astfel încât codul nativ să poată rula înainte ca analiza gestionată obișnuită să aștepte ceva interesant. Operatorii l-au plantat sub nume precum `ncobjapi.dll` sau `wbemcomn.dll` sub `C:\Windows\System32\wbem\`, și ca fișiere false în cache-ul de imagini native .NET cu nume de ansambluri Exchange (`Microsoft.Exchange.Data.Transport.ni.dll`, `EdgeTransport.ni.exe` și altele similare).
- **CerealRunner / CerealSprinter / CerealMoth** — ajutoare pentru ambalare și execuție. Comenzile sosesc adesea ca ansambluri compilate de unică folosință, mai degrabă decât ca șiruri într-un backdoor monolitic.
- **CerealNeuron** — ascultător pasiv HTTPS pe prefixe URI cu aspect Exchange. Fără set de comenzi încorporat; execută ansamblurile livrate.
- **CerealHermit** — variantă de tip Neuron fără ascultare în rețea; fișiere de comandă criptate pe disc.
- **CerealIron** — injector care ajută la introducerea de ansambluri .NET în procese care nu sunt, în mod natural, gazde .NET.
- **CerealBox** — filtru și colector de e-mail în pipeline-ul de transport după injectarea în EdgeTransport.

ESET publică hash-urile SHA-1 pentru optsprezece fișiere în repository-ul său malware-ioc și în white paper. CerealNeuron și CerealBox ele însele nu sunt oferite apărătorilor ca hash-uri de fișiere permanente și ordonate, deoarece o mare parte din viața lor este în memorie sau în containere criptate. Această asimetrie este provocarea de proiectare pentru orice scanner de gazdă: trebuie să cauți *tipare*, nu doar *digest-uri de eșantion*.

### De ce „fără infrastructură C2” schimbă modul de vânătoare

Centrele de operațiuni de securitate sunt instruite să pivoteze pe domenii. Cereal neagă acel pivot. Operatorii pot ajunge prin anonimizare, prin alte gazde compromise sau prin căi care arată ca trafic de email pe portul 443. ESET a raportat incapacitatea de a identifica adresele IP ale operatorilor care intră. Pentru apărători, implicația este clară: **vânează gazda și suprafața de înregistrare a HTTP.sys**, nu doar fluxul de informații despre destinațiile periculoase.

O a doua implicație: jurnalele IIS s-ar putea să nu te salveze. Când HTTP.sys direcționează o cerere către o coadă de cereri non-IIS deținută de malware, procesul de lucru care în mod normal ar scrie jurnalele W3SVC s-ar putea să nu vadă niciodată cererea. Zero înregistrări în jurnalele IIS nu reprezintă un certificat de sănătate curat pentru ascultătorii de tip CerealNeuron. Întrebarea direct la HTTP.sys—cu `netsh http show servicestate` ridicat—se apropie mai mult de adevăr.

### Trucuri .NET care înfruntă “deschide-l în dnSpy și uită-te”Punctul de intrare gestionat al CerealLoader poate părea gol. Munca reală începe mai devreme, prin semnalele punctului de intrare nativ și VTable Fixups. Abuzul cache-ului de imagini native înseamnă că timpul de rulare poate încărca temporar un `.ni.dll` implantat suficient pentru ca codul nativ malițios să ruleze, apoi să revină la ansamblul autentic pentru comportamentul normal. Preluările ordinii de căutare sub `wbem` înseamnă că procesele legitime precum `WmiPrvSE.exe` devin încărcătoare. Orice program de detectare care doar caută un șir C2 codificat într-un singur PE va pierde majoritatea acestei istorii.

### CerealBox și minciuna politicoasă a lui Get-TransportAgentExchange administratorii verifică adesea agenții de transport după activități suspecte. Noutatea lui CerealBox, așa cum o descrie ESET, este că nu trebuie să apară ca un agent nou. Învelește handlerii existenți în memorie. Inventarul de configurare poate fi sincer și totuși inutil. De aceea scriptul nostru profund Exchange încă listează agenții—ca context—și apoi petrece mai multă energie pe proprietatea HTTP.sys, modulele EdgeTransport și indicatorii de șir/config.

## Partea a II-a — Principiile de proiectare ale kitului de detectare CerealBox

Am stabilit câteva reguli netransigente înainte de a scrie o linie de PowerShell.

### 1. Numai citire în mod implicit

Scannerul nu pune fișierele în carantină, nu descarcă module, nu repornește Exchange și nu trimite probe de rețea către prefixele URI CerealNeuron pe gazdele de producție. Testarea unui posibil implant cu cereri live poate alerta operatorii și crea zgomot de incident. Colectarea și compararea mai întâi; remedierea sub controlul IR ulterior.

### 2. Completează antivirusul; nu pretinde că îl înlocuieșteESET detectări precum `MSIL/Agent.YCC`, `MSIL/Agent.YCA`, `MSIL/Agent.YBZ` și `Win32/Agent.AIOQ` fac parte din povestea publică. Instrumentul nostru presupune că este posibil să aveți deja EDR. Acesta există pentru lacune: verificări de tipar care se potrivesc unul-la-unul cu narațiunea tehnică publică, rulabile offline, inspectabile de un om care nu se bazează doar pe verdicturile opace ale cloud-ului.

### 3. Preferă artefactele cu semnal puternic în locul abordării „suspect totul”Primele variante ale scannerului marcau "System32\version.dll" și "iphlpapi.dll" legitime pentru că filtrul modulului era prea slab. Acest tip de fals pozitiv distruge încrederea. Am consolidat potrivirea proces-modul, astfel încât numele plantate și căile plantate contează mai mult decât omniprezentele Windows DLL. Vânătoarea de șiruri de conținut a fost restrâns de la șirurile comune BCL, cum ar fi lovituri goale "HttpListener" pe GAC. Severitatea crește la Critic/Ridicat doar când dovezile se aliniază cu manualul publicat al Cereal. 

### 4. Fă indicatorii portabili

Hash-urile și prefixele URI trăiesc în 'iocs/cereal-iocs.json', nu doar în interiorul corpului scriptului. Un export CSV ('hash-map.csv') suportă fluxuri de lucru SIEM sau foi de calcul. Opțional YARA ('yara/cereal.yar') reflectă aceleași idei pentru echipele care deja rulează 'yara64' în pipeline-urile criminalistice. 

### 5. Separă "orice gazdă Windows" de "scufundare adâncă Exchange"`Scan-Cereal.ps1` este vânătorul general. `Scan-Exchange-Cereal-Deep.ps1` petrece mai mult timp pe contextul PID HTTP.sys, modulele EdgeTransport, enumerarea agenților de transport și căutările de șiruri de cale Exchange. Operatorii pot folosi instrumentul general pe scară largă și pot rezerva scriptul detaliat pentru serverele de poștă.

### 6. Limite oneste în README și în modelul de ieșire

Codul de ieșire `0` înseamnă că nu au fost găsite probleme Critice/Înalte — nu „Turla nu a fost niciodată aici.” Codul de ieșire `2` înseamnă că au fost detectate tipare acționabile. Etapele doar în memorie pot să scape în continuare. Acea onestitate face parte din utilitate: executivii și liderii IR au un instrument care nu exagerază.

## Partea a III-a — Cum funcționează instrumentul de detectare, verificare cu verificare

Gândește-te la `Scan-Cereal.ps1` ca la o conductă scurtă. Încarcă indicatori, parcurge șapte familii de verificări (plus o euristică PE folosită în cadrul lucrului cu cale/hash), acumulează constatări cu severitate, afișează un rezumat și, opțional, scrie JSON.

### Etapa 0 — Încarcă pachetul IoC

La pornire, scriptul citește `iocs/cereal-iocs.json` dacă este prezent. Acest pachet include:

- Toate cele optsprezece ESET SHA-1 IoC publice, cu rolurile lor (CerealLoader, CerealRunner, CerealSprinter, CerealHermit, CerealIron, CerealMoth, bootstrappers).
- Perechi SHA-256 verificate VirusTotal unde rezoluția publică a avut succes (de exemplu, eșantioane Loader numite ca `Microsoft.Exchange.Data.Transport.ni.dll`, `version.dll`, `Microsoft.Search.Platform.dll`, `Microsoft.Ceres.dll`).- Un 'additional_sha256_hunt_set' extras din lotul Cereal din lista 'turla/samples.sha256' a lui ESET, astfel încât vânătorul să poată potrivi digestele chiar și atunci când o pereche perfectă SHA-1↔SHA-256 nu este încă publicată pe VirusTotal. 
- Indicatori non-fișier: cheia dicționarului de configurare 'B38C96AE6643D2AB5C0BFE823D9C9017', fragmentele prefixului URI CerealNeuron și căile cunoscute de deturnare. 

Dacă JSON lipsește, scriptul revine la o listă încorporată SHA-1, astfel încât un script copiat singur are totuși acoperire de bază. 

### Verificare 1 — Vânătoare de trasee și măști ('Scan-Paths')

Scanerul caută: 

- 'ncobjapi.dll' sub 'System32\wbem' și 'SysWOW64\wbem' — un nume plantat ESET asociat cu încărcarea WMI Provider Host.- `wbemcomn.dll` sub aceleași foldere — `wbemcomn.dll` legitim trăiește de obicei în altă parte sub System32; o copie sub `wbem` cu un status Authenticode defect sau un punct de intrare .NET nativ este ridicată.
- Fișierele denumite Exchange din directoarele `NativeImages_*` — tiparul de abuz al cache-ului de imagini native.

Pentru fișierele candidate PE, rulează un parser PE ușor căutând directorul CLR și `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` (0x10). Această euristică vizează comportamentul în modul mixt de tip CerealLoader fără a necesita un laborator complet de inginerie inversă pe fiecare gazdă.

### Verificarea 2 — Vânătoarea de hash-uri (`Scan-Hashes`)Arborii de valoare ridicată sunt parcurși: folderele `wbem`, `assembly`, Microsoft.NET, Exchange căi de instalare și orice rădăcini suplimentare pe care le furnizează operatorul. Numele de fișiere suspecte (Loader mascare, `iph.dat`, `FallbackLog.bin` și altele asemănătoare) sunt hash-uite cu SHA-1 și SHA-256 și comparate cu seturile IoC. Un comutator opțional `-FullDriveHashScan` extinde hash-uirea pe unitățile fixe pentru răspuns la incidente atunci când timpul permite. Aceasta este intenționat opțional: hash-uirea întregului disc este lentă și ar trebui să fie o alegere conștientă, nu un implicit care face instrumentul inutilizabil în fereastra de întreținere.

### Verificarea 3 — prefixe HTTP.sys CerealNeuron (`Scan-HttpSys`)

Folosind `netsh http show urlacl` și `netsh http show servicestate view=requestq verbose=yes`, scanerul caută fragmente precum:

- `owa/sdds`
- `autodiscover/microsoft.exchange.proxyservice`
- `autodiscover/integrated/api`
- `autodiscover/proxyservice`- `microsoft-server-activesync/integrated/api`

O potrivire este critică. Liniile din apropiere sunt capturate ca dovezi, astfel încât analiștii să poată urmări PID-urile responsabile. Fără drepturi de Administrator, instrumentul avertizează că vizibilitatea poate fi incompletă — un alt semnal sincer în locul unei omiteri silențioase.

Această verificare este inima „serverului Exchange este C2.” Nu are nevoie de adrese IP ale operatorilor. Întreabă stiva HTTP a nucleului cine a înregistrat prefixele ce seamănă cu Exchange pe care se știe că le folosește CerealNeuron.

### Verificarea 4 — Inspectarea modulelor procesului (`Scan-Processes`)Procesele de interes includ `EdgeTransport`, `WmiPrvSE`, Exchange Search, nume de transport asociate și câțiva gazde care apar în narațiunile Loader. Listele de module sunt filtrate pentru numele și căile plantate — nu pentru fiecare `version.dll` pe Windows. Modulele suspecte sunt hash-uite împotriva IoC. Nepotrivirile de elevare și de bitness pot împiedica enumerarea modulelor; acele eșecuri sunt înregistrate ca Low/Info în loc să se creeze hit-uri Critical.

### Verificarea 5 — Căutarea șirurilor de conținut și cheie de config (`Scan-ContentStrings`)

Arborii vizați (wbem, căile Exchange, temp) sunt scanate pentru șiruri cu semnal ridicat: cheia MD5 a config-ului, fragmente URI, `RoutingAgentFactory`, `amsiInitFailed`, `FallbackLog.bin`, și bucăți de cale Autodiscover/ActiveSync asociate. O trecere separată caută `FallbackLog.bin` după nume. Domeniul este intenționat limitat astfel încât instrumentul să se finalizeze într-un interval de timp util pe servere obișnuite.### Verificarea 6 — Opțional YARA (`Scan-Yara`)

Cu `-RunYara`, dacă `yara64.exe` este disponibil și `yara/cereal.yar` există, scanările recursive se rulează pe calea wbem, assembly și Exchange. Regulile acoperă digesturile SHA-256 cunoscute, fragmentele URI, cheia de configurare, clușterele de șiruri transport-hook, indicii orientați către Sprinter și șirurile de căi de deturnare wbem. YARA este opțional deoarece nu toate calculatoarele administrate îl au instalat; verificările PowerShell rămân însă independente.

### Verificarea 7 — Context Exchange (`Scan-ExchangeContext`)

Scanerul general notează dacă `EdgeTransport.exe` este prezent și, dacă există cmdlet-uri Exchange Management Shell, enumeră agenții de transport în timp ce reamintește analistului că CerealBox poate lăsa acea listă neschimbată.

### Companion — `Scan-Exchange-Cereal-Deep.ps1`Pe serverele de poștă, scriptul aprofundat extinde HTTP.sys ferestre de context pentru vânătoarea PID, inspectează EdgeTransport module mai atent, inventariază agenți, caută șiruri de configurare/URI sub Exchange rădăcini și poate rula același YARA pachet. Este modul „te afli pe serverul real de mail”.

### Model de ieșire

Descoperirile includ severitate, categorie, titlu, detaliu, dovezi și marcaj temporal. Colorarea consolei ajută în rulările interactive. Ieșirea JSON suportă sistemele de ticketing și revizuirea offline. Ieșirea `2` la Critical/High oferă automatizării o metodă simplă de a „alerta un om.”

---

## Partea a IV-a — Corelarea verificărilor instrumentului cu tactica Cereal

Un instrument de detectare este credibil doar în măsura în care corespunde amenințării. Iată corespondența într-un singur loc.

1. Comportament Cereal: HTTPS pasiv pe prefixe de tip OWA/Autodiscover/ActiveSync
   Ce ratează adesea apărătorii: Vânătoare doar pe ieșire; revizuirea jurnalelor doar IIS
   Verificare CerealBox: Prefix HTTP.sys + context

2. Comportament Cereal: Loader ca `ncobjapi.dll` / `wbemcomn.dll` sub `wbem`
   Ce ratează adesea apărătorii: Presupunerea că DLL-urile din System32 sunt întotdeauna de la Microsoft
   Verificare CerealBox: Cale + semnătură + hash + punct de intrare nativ

3. Comportament Cereal: NativeImages false cu nume de ansambluri Exchange
   Ce ratează adesea apărătorii: Tratarea tuturor `.ni.dll` ca fișiere cache de performanță
   Verificare CerealBox: Căutare nume NativeImages + hash + punct de intrare

4. Comportament Cereal: Punct de intrare .NET neadministrat / VTable Fixups
   Ce ratează adesea apărătorii: Triere doar pe partea managed
   Verificare CerealBox: Flag punct de intrare nativ PE

5. Comportament Cereal: Cheie de dicționar de configurare partajată între mostre Neuron/Box
   Ce ratează adesea apărătorii: Așteptarea unui hash de fișier pentru Neuron/Box
   Verificare CerealBox: Vânătoare de șiruri + regulă YARA pentru cheie

6. Comportament Cereal: CerealBox în EdgeTransport fără agent nou
   Ce ratează adesea apărătorii: Se bazează doar pe `Get-TransportAgent`
   Verificare CerealBox: Module de proces + notă agent + indicii din șiruri

7. Comportament Cereal: Numele de jurnalizare Sprinter `FallbackLog.bin`
   Ce ratează adesea apărătorii: Ignorarea fișierelor binare ciudate
   Verificare CerealBox: Vânătoare de nume de artefact

8. Comportament Cereal: Mostre cunoscute Loader/Runner/etc.
   Ce ratează adesea apărătorii: Acoperire SHA-256 incompletă în unele fluxuri
   Verificare CerealBox: Set SHA-1 + SHA-256 verificat + set de vânătoare SHA-256

Această mapare este, de asemenea, un instrument didactic. Când faci un briefing pentru CISO, poți indica fiecare rând și să spui: „ESET a descris asta; instrumentul nostru caută aici.” Aceasta este mai convingătoare decât o captură generică de ecran de pe dashboard-ul endpoint-ului.
---

## Partea V — Cum să-l implementați

### Conținutul pachetului pe care ar trebui să-l tratați ca un unitate

Copiați folderul ca un întreg astfel încât căile relative să se rezolve:

- `Scan-Cereal.ps1`
- `Scan-Exchange-Cereal-Deep.ps1`
- `iocs/cereal-iocs.json`
- `iocs/hash-map.csv` (opțional pentru persoane/SIEM)
- `yara/cereal.yar`
- `README-Cereal-Scanner.md`
- Opțional: `tools/yara64.exe` dacă doriți `-RunYara` fără o instalare de sistem

### Model de implementare A — IR manual pe un server suspect Exchange

1. Obțineți aprobarea pentru modificări și ghidajul pentru capturarea snapshot/memorie de la IR înainte de orice curățare.
2. Copiați kitul pe o cale locală (de exemplu `C:\ProgramData\CerealBox` sau un USB pentru investigații criminalistice).
3. Deschideți un PowerShell cu privilegii ridicate.
4. Rulați:

```powershell
cd C:\ProgramData\CerealBox
powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json -RunYara
powershell -ExecutionPolicy Bypass -File .\Scan-Exchange-Cereal-Deep.ps1 -OutputJson .\exchange-cereal.json -RunYara
```

5. Păstrați ieșirile JSON cu ID-ul cazului.
6. Dacă apar alerte Critice/Ridicate, izolați conform ghidului IR; nu „curățați la fața locului” și nu distrugeți dovezile din memorie.

### Model de implementare B — Sarcină programată pe întreaga proprietate (detecție, nu prevenire)

Creați o sarcină programată ca SYSTEM sau ca cont de serviciu privilegiat pe serverele Exchange (și opțional pe hosturile jump):

- Rulare săptămânală sau zilnică în afara orelor de vârf a `Scan-Cereal.ps1 -OutputJson \secure\share\%COMPUTERNAME%-cereal.json`
- Trimiteți JSON către un SIEM printr-un colector sau folosiți un wrapper simplu care alertează la codul de ieșire `2`
- Țineți -FullDriveHashScan oprit pentru rulările de rutină; activați-l doar pentru incidente confirmate

Vânătoarea programată este locul unde onestitatea în privința falselor pozitive contează. Modelul nostru de severitate și filtrele modulelor restrânse există pentru ca rulările nocturne să nu alarmeze inutil pentru fiecare `version.dll`.

### Model de implementare C — Pachet GPO sau ConfigMgrÎmpachetați folderul într-un pachet de aplicații. Folosiți o regulă de detectare bazată pe codurile de ieșire sau pe prezența unui „last run” ștampilat JSON. Preferabil trageți de pe un share intern în loc să trimiteți kitul prin canale neîncredere.

### Model de implementare D — Revizuire offline pe stație de lucru criminalistică

Dacă nu puteți rula scripturi pe serverul Exchange, colectați:

- Ieșirea comenzii `netsh http show servicestate view=requestq verbose=yes`
- Inventarele SHA-1/SHA-256 ale `wbem` și NativeImages
- Imaginea memoriei EdgeTransport / WmiPrvSE

Apoi folosiți pachetul IoC JSON, CSV și YARA pe stația de lucru criminalistică. Scripturile live automatizează acea colectare; indicatorii funcționează în continuare offline.

### Model de implementare E — Validarea în laborator a echipei purpleConstruiește un laborator cu artefacte sintetice: un șir de rezervare URL fals într-o transcriere netsh salvată, un fișier de test al cărui SHA-1 se potrivește cu un IoC publicat într-un director sigur, un PE cu flag-ul punctului de intrare nativ. Confirmă că scannerul returnează exit `2` și titluri clare. Așa câștigi încredere înainte de producție.

### Privilegii și politica de execuție

- Elevarea îmbunătățește vizibilitatea HTTP.sys și a modulului.
- `-ExecutionPolicy Bypass` este pentru utilizare controlată IR; preferă scripturi semnate în implementările enterprise pe termen lung dacă politica ta o cere.
- Medii Constrained Language Mode pot necesita ajustări; testează înainte de o criză.

### Ce să nu implementezi

Nu conecta scannerul pentru a șterge automat `NativeImages` sau DLL `wbem`. Căutarea Exchange și stricăciunea WMI reprezintă un risc operațional real. Detecția mai întâi; controlul modificărilor pentru remediere.

---

## Partea VI — Cine găsește acest lucru util și cum

### Exchange administratori

Primești o listă de verificare concretă care vorbește limba ta: HTTP.sys, EdgeTransport, agenți de transport, imagini native. O poți rula după weekend-uri de patch-uri, după comportamente OWA suspecte sau ca un control de igienă lunar. Utilitatea nu este „găsește Turla de fiecare dată.” Utilitatea este „dovedește că ai căutat urmele publice Cereal și ai păstrat artefactele.”  

### Analiști SOC

Descoperirile JSON cu severitate și categorii se transformă în tichete. Liniile de context HTTP.sys oferă PID-uri pentru a pivota în EDR. Potrivirea hash-urilor oferă VirusTotal și linkuri Hybrid Analysis deja prezente în pachetul IoC. Instrumentul scurtează distanța dintre „Am citit postarea WeLiveSecurity” și „Am dovezile pe host.”  

### Responders la incidenteColecția numai pentru citire se potrivește devreme IR. Codurile de ieșire controlează automatizarea accesului. Scriptul profund Exchange concentrează timpul pe procesul care contează pentru CerealBox. Secțiunea de limite din README te ajută să informezi consilierii și directorii fără a exagera eradicarea.

### CERT naționale și SOC-uri de sector

Moșiile guvernamentale Exchange rămân comune. Victimele publice ale Cereal erau guvernamentale. Un kit portabil PowerShell se deplasează mai bine între ministere decât o dependență de consolă de la un singur furnizor. Distribuie IoC JSON ca un document viu pe măsură ce noile perechi SHA-256 sunt verificate.

### Ingineri de securitate care construiesc detecții

Folosește tabela de mapare pentru a scrie analytics SIEM: alertă la înregistrările HTTP.sys care conțin `owa/sdds`; alertă la `ncobjapi.dll` sub `wbem`; alertă la EdgeTransport care încarcă module din căi NativeImages neașteptate. Scriptul este o implementare de referință a acestor idei.

### Conducere și deținători de riscPovestea este strategică: un actor capabil a folosit propriul server de mail al organizației ca infrastructură și a filtrat NATO/mail legat de UE într-un caz public cel puțin. Investiția în vânătoarea de Exchange la nivel de gazdă este proporțională. Instrumentul este un control cu cost redus în comparație cu reconstrucția unui server Exchange după o descoperire târzie.

## Partea VII — O prezentare narativă: dimineața după apariția blogului

Imaginează-ți un SOC al unui minister european în ziua în care postarea ESET apare. Analiștii redirecționează articolul în chat. Cineva întreabă dacă țintirea de tip Romania s-ar putea aplica. Altcineva întreabă după „IoC-urile.” Hash-urile ajung într-un tichet. Un administrator Exchange întreabă dacă ar trebui să repornească.

În loc de haos, o echipă pregătită copiază CerealBox pe serverele de poștă, rulează scanări elevate și, în câteva minute, are fie:

- Rezultate Critice/Înalte curate, cu context la nivel de Informație că EdgeTransport este prezent și HTTP.sys era lizibil, sau
- Un hit Critic HTTP.sys cu un fragment de URL și un PID, sau o potrivire Critică de hash sub NativeImages, sau o descoperire de modul Înaltă în EdgeTransport.Acea diferență—ore de incertitudine versus un permis structurat pentru gazdă—reprezintă utilitatea practică a unui căutător de tipare construit special. Nu înlocuiește cercetarea lui ESET, analizele forensic ale memoriei sau întregul IR. Creează un prim strat acționabil care corespunde poveștii tehnice publice.

## Partea VIII — Cum să vorbim despre asta fără exagerări

**Mize:** corespondența care ar trebui să fie confidențială este copiată în interiorul conductei de transport. C2-ul este propriul certificat și propriul nume de gazdă.

**Disciplină:** nu afirmi că scanner-ul vede fiecare Runner din memorie. Afirmi că acesta caută urmele pe care ESET le-a făcut publice și pe care operatorii trebuie să le lase dacă persistă Loaders sau înregistrează prefixe Neuron.

**Pași practici pentru apărători:**

1. Citiți postarea publică și white paper-ul lui ESET.  
2. Faceți inventarul Exchange care sunt expuse pe internet.  
3. Rulați un HTTP.sys doar pentru citire și o căutare a căii Loader săptămâna aceasta.  
4. Păstrați memoria înainte de curățare dacă întâlniți descoperiri critice.

---

## Partea IX — Explorare detaliată: HTTP.sys ca prieten al detectivului

.NET `HttpListener` stă pe HTTP.sys. Prefixele lui CerealNeuron apar, așadar, în starea HTTP a nucleului. Aceasta este o coincidență defensivă elegantă. Atacatorii doreau să se amestece cu Exchange HTTPS. Pentru a face acest lucru pe Windows, au moștenit un model de înregistrare pe care apărătorii îl pot interoga.

Sfaturi practice când scannerul semnalează un prefix:

- Cartografiați ID-ul procesului controller al cozii de cereri cu `tasklist` / EDR.
- Un lucrător IIS care deține o legătură de site poate fi normal; un proces neașteptat care deține un subpath OWA nu este.
- Comparați cu un server Exchange cunoscut-curat pe aceeași actualizare cumulativă.
- Nu trimiteți POST-uri de test la prefix pe producție pentru a „vedea ce se întâmplă”.

Scannerul nostru automatizează căutarea șirurilor și capturarea contextului, astfel încât analiștii să petreacă timp pe atribuirea PID-ului în loc să își amintească care sunt cele cinci prefixe enumerate de ESET.

---

## Partea X — Analiză detaliată: imagini native și tentația de a șterge

Exchange servere acumulează imagini native legitime. Ștergerea după tiparul numelui de fișier este modul în care creezi o pană autoindusă. Scannerul marchează imaginile native cu numele Exchange ca fiind de revizuire Majoră și Critică atunci când hash-urile sau punctele de intrare native confirmă rău intenționat. Remedierea ar trebui să se bazeze pe hash și condusă de IR, ideal după capturarea memoriei, și adesea se încheie cu reconstrucție în loc de ștergere chirurgicală DLL — mai ales când Box și Neuron pot fi deja în memorie.

## Partea XI — Analiză aprofundată: indicatori care se vor învechi

SHA-1 se îmbătrânește când Turla se recompilează. Prefixele URI se pot roti. Cheia de configurare se poate schimba. De aceea kitul păstrează indicatorii în JSON. Actualizează pachetul când repository-ul malware-ioc al ESET crește. Rulează din nou `tools/apply_vt_mappings.py` sau `Resolve-VtSha256.ps1` când noi mapări VirusTotal sunt verificate. Tratează PowerShell ca un motor stabil și JSON ca creierul viu.

Echipele care fac fork la kit ar trebui să păstreze un jurnal al actualizărilor IoC. Această disciplină transformă un răspuns de blog ocazional într-un control întreținut.

## Partea XII — Integrarea cu EDR și SOAR

Schiță sugerată pentru SOAR:

1. Ticket creat din informații despre amenințări menționând Cereal / Turla Exchange.
2. Automatizarea copiază kit-ul sau invocă PowerShell la distanță pe serverele Exchange din domeniu.
3. Analizați JSON; dacă există Critical/High, creați un caz Sev-1 IR și izolați rețeaua conform playbook-ului.
4. Atașați contextul netsh și hit-urile de hash la caz.
5. Un IR uman decide achiziția de memorie și reconstrucția.

Detectările pe partea EDR pot reflecta aceeași logică continuu: încărcarea modulului `ncobjapi.dll` din `wbem`; script-block sau linie de comandă în jurul `netsh` suspect doar dacă atacatorii îl folosesc (de obicei nu—îl înregistrează programatic). Se preferă telemetria EDR pentru detecție continuă și kit-ul PowerShell pentru vânători explicite, auditable și în medii izolate.

## Partea XIII — Limitele legale, etice și operaționale

- Rulează doar pe sistemele pe care ai autorizarea de a le evalua.
- Nu folosi kitul ca pretext pentru a ataca serverele terților Exchange.
- Nu include cod de exploatare, mostre de implanturi sau sonde active Neuron în kit. Al nostru nu include.
- Coordonează-te cu echipele de confidențialitate și juridice atunci când conținutul mailurilor poate fi falsificat; CerealBox sugerează posibil furt de mailuri, ceea ce declanșează analiza notificărilor în multe jurisdicții.
- Atribuie cu atenție: o potrivire de hash este un indiciu puternic; înregistrarea URI merită investigată; niciuna singură nu constituie o narațiune pentru instanță fără coroborare.

---

## Partea XIV — Limitări, reluate astfel încât nimeni să nu le rateze

1. În memorie CerealRunner / CerealBox / CerealNeuron pot lăsa urme sporadice pe disc.
2. Există imagini native legitime Exchange; contextul contează.
3. Nicio listă publică de IP-uri ale operatorilor nu însoțește CerealNeuron în cercetare.
4. CerealNeuron și CerealBox nu au hash-uri de fișiere durabile publicate în același mod ca Loaders.
5. Hash-uirea întregului disc este lentă; opțională dintr-un motiv.
6. Fără drepturi de administrare, HTTP.sys și vizualizările modulului pot fi incomplete.
7. YARA necesită un binar prezent; verificările PowerShell nu.

Un instrument care specifică aceste limite este mai util decât o broșură de produs care promite omnisciență.

---

## Partea XV — Extinderea kitului (idei pentru constructori)

Fără a schimba etosul de doar citire, îmbunătățirile viitoare ar putea include:

- Sigma reguli exportând aceeași logică HTTP.sys și cale
- Un mic colector care doar descarcă netsh + hash-uri pentru analiza offline pe gazdele de criminalistică Linux
- Teste de integrare continuă cu echipamente sintetice
- PowerShell semnat și sume de control pentru kit în sine pentru a preveni modificarea vânătorului

Acestea sunt pași de inginerie următori, nu promisiuni. Kitul actual răspunde deja nevoii imediate create de raportul public.

---

## Partea XVI — De ce PowerShell, deliberat

Serverele Enterprise Exchange vorbesc deja PowerShell. Echipele IR pot citi scriptul într-un editor de text în timpul revizuirii modificărilor. Nu există un driver opac. Nu există dependență de cloud pentru verificările de bază. În rețele contestate sau clasificate, asta contează. Creativitatea aici este reținerea: mișcarea spectaculoasă ar fi o platformă mare de agenți; mișcarea utilă este un script transparent care se transpune într-un white paper.

## Partea XVII — Conectarea Romania, Kazakhstan și a patrimoniului tău

S-ar putea să nu fii un guvern național. Tehnicile Cereal se transferă în continuare. Orice organizație cu Exchange expus la internet, flux de corespondență sensibil și cicluri lente de patch-uri împărtășește suprafața de atac relevantă. Preferințele de țintire ale Turla explică *de ce* ESET a găsit ceea ce a găsit; tehnicile explică *de ce ar trebui să continui să cauți*. Folosește povestea geopolitică pentru prioritizare și atenția executivă. Folosește povestea tehnică pentru munca de inginerie.

## Partea XVIII — Un ghid de teren pentru interpretarea severității

- **Critic:** hash cunoscut; înregistrare similară CerealNeuron-HTTP.sys; punct de intrare nativ pe o cale de deturnare plantată.
- **Ridicat:** cale de modul suspectă în EdgeTransport/WmiPrvSE; cheie de configurare sau șir URI într-un fișier neașteptat; potrivire regulă YARA; imagine nativă denumită Exchange care necesită revizuire cu semnale secundare puternice.
- **Mediu:** artefacte precum FallbackLog.bin după nume; avertismente de ridicare incomplete asociate cu dovezi parțiale.
- **Scăzut/Info:** context (proces în execuție, număr de agenți, scanare începută). Util pentru rapoarte; nu suficient pentru pagină singur.

Instruiți analiștii pe această scară astfel încât codul de ieșire `2` să rămână semnificativ.

---

## Partea XIX — Șabloane de comunicare pe care le poți reutiliza

**Către Exchange operațiuni:** „Vom rula un hunter PowerShell doar în citire pentru urmele Turla Cereal publicate de ESET. Nu se fac modificări în fluxul de mail. Sunt necesare drepturi ridicate pentru HTTP.sys. JSON va fi stocat în share-ul IR.”

**Către CISO:** „Rapoartele publice arată că Turla folosește victima Exchange ca C2 pasiv și colectare de mail în memorie. Am implementat un scanner de modele pe gazdă aliniat cu aceste tehnici. Completează EDR; nu înlocuiește deciziile de refacere dacă confirmăm compromiterea.”

**Către liderul IR:** „Dacă apar Critical HTTP.sys sau rezultate hash, păstrează memoria pentru EdgeTransport și WmiPrvSE înainte de remediere. Presupune acces posibil la mail și acreditări pe baza descrierii listei de comenzi a ESET.”

## Partea XX — Concluzie: mic dejun, revizitat

Titlul ESET este memorabil pentru că este ușor absurd: mic dejun, Exchange, trucuri care nu sunt pentru copii. Absurdul ascunde o idee serioasă. Instrumentele de spionaj s-au mutat în centrul plictisitor al IT-ului de întreprindere — serverul de mail de care toată lumea încă are nevoie, HTTPS pe care toată lumea trebuie să-l permită, runtime-ul .NET de care Exchange depinde.

Kitul nostru de detectare este un răspuns sobru la acea idee. Încarcă indicatori publici, pune Windows întrebările pe care le sugerează white paper-ul, scrie constatările pe care un om le poate apăra și refuză să pretindă că fantomele din memorie sunt întotdeauna vizibile.

Dacă faci o singură acțiune după ce ai citit: alege un server Exchange, rulează `Scan-Cereal.ps1` cu privilegii ridicate și cu ieșire JSON, și citește rezumatul. Dacă este curat, ai un artefact de referință. Dacă nu este, ai un avantaj pe care doar slide-urile de threat-intel nu ți l-ar fi oferit.Operatorii care au construit Cereal au investit profund în componentele interne Exchange și în obscuritatea .NET. Apărătorii pot răspunde cu aceeași seriozitate: nu panică, nu negare, ci vânătoare structurată pe gazda care a fost transformată în mic dejun.

---

## Referințe și lecturi suplimentare

- Matías Porolli, ESET Cercetare — *Exchange la micul dejun: trucurile Cereal ale Turla nu sunt pentru copii* (WeLiveSecurity, 10 nov 2026): https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
- ESET white paper — trucuri Turla Cereal (analiză tehnică detaliată ce însoțește blogul)
- ESET malware-ioc — `turla` IoCs pe GitHub (SHA-1 tabele și liste de hash de probă)
- UK NCSC — context istoric Neuron/Nautilus așa cum este citat în narațiunea de comparație a ESET
- `README-Cereal-Scanner.md`, `Scan-Cereal.ps1`, `Scan-Exchange-Cereal-Deep.ps1`, `iocs/cereal-iocs.json`, și `yara/cereal.yar` din acest depozit

---

## Despre instrument (rezumat scurt)

**CerealBox** este un kit de detectare doar pentru citire PowerShell pentru Windows care caută modele Turla Cereal descrise în cercetarea publică a ESET: căi de deturnare a loader-ului, mascare a imaginilor native, euristici pentru punctele de intrare .NET native, prefixe de URI CerealNeuron HTTP.sys, șiruri de chei de configurare, anomalii ale modulelor proceselor, YARA opțional și un companion de verificare aprofundată Exchange. Este proiectat pentru apărători autorizați, echipe IR și operatori Exchange care au nevoie de o verificare concretă și inspectabilă a gazdei după ce au citit raportul public.

---

## Partea XXI — O poveste de origine mai lungă pentru kit (cadru non-ficțiune creativă)

Fiecare proiect de detectare începe cu o propoziție care nu te lasă în pace. Pentru noi, acea propoziție nu a fost „Turla s-a întors.” A fost: serverul Exchange al victimei este C2.

Odată ce accepți această propoziție, urmează un lanț de întrebări incomode. Ce face SOC-ul tău atunci când nu există un domeniu pe care să îl blochezi? Ce blochează echipa ta de firewall când destinația este propriul tău VIP? Ce verifică administratorul tău Exchange când agenții de transport par impecabili? Ce colectează conducătorul IR când cel mai important proces este același EdgeTransport.exe care rulează de la ultimul reboot?

Nu am încercat să răspundem la toate aceste întrebări cu o platformă de produs. Le-am răspuns cu un folder.Acea alegere pare mică. Nu este. Un dosar pe care îl poți copia pe un USB de criminalistică, deschide în Notepad și explica unui consiliu de schimbări este un tip diferit de control de securitate față de un tablou de bord în care se pot autentifica doar trei persoane. În timpul unei săptămâni în formă de APT, numărul persoanelor care trebuie să înțeleagă controlul crește: Exchange, SOC, IR, personal CISO, uneori legați naționali CERT. Transparența devine o caracteristică.

Numele kitului—CerealBox—are un sens dublu deliberat. În taxonomia lui ESET, CerealBox este modulul de colectare a corespondenței. În kitul nostru, CerealBox este, de asemenea, cutia de instrumente pe care o porți pentru a căuta Cereal. Jocul de cuvinte este intenționat: un singur nume atât pentru componenta amenințării, cât și pentru dosarul defensiv care o vânează.

Construirea primei versiuni a fost ca și cum ai traduce un document tehnic în verbe. „Ascultător pasiv” a devenit „interogare HTTP.sys.” „Abuzul cache-ului de imagini native” a devenit „parcurgere NativeImages și fișiere cu nume etichetate Exchange.” „Punct de acces neadministrat” a devenit „analizează steagurile PE CLR.” „Fără agent de transport nou” a devenit „în continuare listează agenții, dar nu te baza pe ei ca singurul semnal.” Fiecare traducere a eliminat poezia și a păstrat mecanismul.

De asemenea, am tradus absența. CerealNeuron nu are niciun hash de probă durabil publicat în același mod în care au Loader-ele. Acea absență a devenit căutări de șiruri, verificări de prefix URI și reguli YARA care caută chei de configurare și fragmente de cale. Ingineria detecției este adesea arta de a transforma „nu avem un hash” în „încă avem un loc unde să căutăm.”Au existat încercări eșuate. Un filtru de modul timpuriu trata bibliotecile obișnuite de rețea Windows ca fiind suspecte, deoarece un tipar scurt se potrivea prea larg. Consola se ilumina cu alerte de nivel Înalt pe calculatoare sănătoase. Așa mor instrumentele în întreprinderi: nu din cauza lipsei de malware, ci din cauza instruirii oamenilor să le ignore. Am corectat filtrul, am redus zgomotul de căutare a conținutului și am reluat procesul până când un gazdă de laborator curată a rămas curată. Abia atunci am avut încredere că Critic înseamnă Critic.

Dacă adoptați kitul, moșteniți acea filozofie. Ajustați înainte de a programa. Stabiliți o bază de referință înainte de a alarma. Tratați prima execuție în producție ca o repetiție generală, nu ca un verdict asupra organizației dumneavoastră din anul trecut.

---

## Partea XXII — Exercițiu simulat: patru ore cu CerealBox

Folosiți acest exercițiu cu SOC, Exchange și IR în aceeași încăpere (sau într-un apel comun).

### Ora 0 — Briefing (20 de minute)

Citiți cu voce tare trei fapte din raportările publice ale ESET: (1) nu s-a observat C2 extern; (2) CerealBox poate colecta mail fără un agent de transport nou; (3) persistența Loader a folosit căile wbem și NativeImages. Conveniți că exercițiul este autorizat pe un laborator sau pe un twin desemnat non-producție, dacă este posibil. Dacă trebuie să folosiți producția, conveniți că scripturile sunt doar pentru citire și că nu se efectuează nicio remediere în timpul exercițiului simulat.

### Ora 1 — Rulați scanerul general (40 de minute)Executați Scan-Cereal.ps1 cu JSON ieșire ridicată. Proiectați consola. Faceți pauză la fiecare antet de categorie. Întrebați administratorul Exchange să explice ce înseamnă HTTP.sys în mediul lor. Întrebați analistul SOC cum ar crea un tichet pentru un URI critic detectat. Capturați întrebările într-o notă partajată.

### Ora 2 — Rulați scriptul profund Exchange (40 de minute)

Executați Scan-Exchange-Cereal-Deep.ps1. Comparați ieșirile JSON. Discutați dacă enumerarea modulului EdgeTransport a reușit. Dacă a eșuat din cauza permisiunilor, atribuiți un element de acțiune — nu argumentați cu eroarea; remediați modelul de acces.

### Ora 3 — Injectați semnale sintetice doar în laborator (40 de minute)

Pe un gazdă de laborator, plantați un fișier inofensiv cu un hash de test cunoscut sau introduceți o transcriere netsh salvată care conține un prefix de tip Cereal într-o revizuire offline. Confirmați reacția instrumentului. Scopul este calibrarea încrederii, nu manipularea malware-ului.### Ora 4 — Arbori decizionali (40 de minute)

Parcurgeți arborele decizional IR: memorie mai întâi, izolați, presupuneți expunerea prin e-mail, presupuneți expunerea credențialelor pe baza tipurilor de comenzi descrise la ESET, reconstruiți versus curățare la fața locului. Încheiați cu proprietarii și datele pentru vânătorile programate la nivel de întreg patrimoniu.

Un exercițiu de tip tabletop ca acesta transformă îndrumarea scrisă în memorie musculară.

---

## Partea XXIII — Interpretarea exemplului de identificare a formelor (ilustrativ)

Următoarele exemple sunt forme ilustrative, nu capturi de ecran de la o victimă reală. Ele arată cum să se interpreteze rezultatul.

### Forma A — Critică HTTP.sys

Severitate Critică, categorie HttpSys, titlu menționând o înregistrare URL de tip CerealNeuron, detaliu conținând owa/sdds, dovezi arătând liniile ID de proces Controller din apropiere.

Sens: Ceva a înregistrat un prefix care se potrivește cu tiparele publice CerealNeuron.

Următorul pas: Identifică PID-ul, capturează memoria, compară cu așteptările lucrătorului IIS, escaladează IR.

Încă neconfirmat: Că operatorii Turla sunt online chiar acum.

### Forma B — Hash critic pe NativeImages

Severitate Critică, categorie Hash, cale sub NativeImages_v4.0.30319_64, SHA-1 potrivindu-se cu un CerealLoader IoC.

Sens: Este prezent un digest malițios publicat acolo unde trăiesc imaginile native legate de Exchange.Următor: Păstrați fișierul, memoria serviciilor asociate, nu ștergeți ad-hoc.

Atenție: Alți serveri pe același CU ar trebui comparați.

### Forma C — Modul ridicat în EdgeTransport

Gravitate Ridicată, categorie Memorie, calea modulului indicând către un binar neașteptat NativeImages cu numele Exchange.

Semnificație: Procesul de transport a încărcat ceva care merită o explicație.

Următor: Hasați-l, comparați cu IoC, verificați Authenticode, luați în considerare dump.

Atenție: Unele medii au add-in-uri neobișnuite dar legitime—dovediți răuvoința.

### Forma D — Doar informație

EdgeTransport rulează, numărul de agenți listat, scanare începută.

Semnificație: Context pentru raport.

Următor: Niciunul pentru paginare. Păstrați în JSON pentru audit.

Învățând analiștii aceste forme previne atât panica, cât și nepăsarea.

## Partea XXIV — Implementare la scară largă: un model de operare exemplar

### Roluri

Proprietar detecție: menține IoC JSON și versiunile scripturilor.

Proprietar Exchange: aprobă rulările elevate și interpretează alarmele false legate de imaginile native specifice CU.

Proprietar SOC: gestionează tichetele Critice/Înalt și monitorizează codurile de ieșire programate.

Proprietar IR: definește pașii de captură a memoriei și izolare.

### Ritm

Lunar: toate serverele Exchange expuse la internet, scripturi generale și detaliate.

Săptămânal: servere Tier-0 / guvernamentale / de poștă pentru apărare.

Ad hoc: în termen de 24 de ore de la informații publice relevante.

Post-modificare: după instalările majore Exchange CU (apar noi imagini native; bazele de referință se schimbă).

### Stocare

Stocați JSON sub un traseu precum un share IR organizat pe ani, luni și nume de gazdă, cu ACL limitat la IR și SOC. Păstrați cel puțin 180 de zile pentru a putea demonstra istoricul vânătorii dacă este solicitat de auditori sau parteneri.

### Măsurători importanteProcentajul de Exchange servere scanate în ultimele 30 de zile.

Timpul mediu de la informațiile publice la prima scanare a sitului.

Rata de rezultate fals pozitive pentru Critical (țintă: aproape zero după reglare).

Timpul de la descoperirea Critical la captarea memoriei.

Evitați metrici de vanitate precum numărul de linii de script.

---

## Partea XXV — Compararea abordărilor (fără tribalism)

EDR doar. Excelent pentru genealogia proceselor și detectări sprijinite de memorie dacă există pachete de conținut. Poate avea întârziere la combinații de tehnici complet noi. Kitul nostru este un instrument specializat.

Lista de verificare manuală. Tipăriți ESET’s IoC și căutați manual. Funcționează pentru un singur server; eșuează pe treizeci. Scriptul este lista de verificare executată.

Imaginea completă a discului de fiecare dată. Standardul de aur pentru confirmarea IR; prea greu pentru igienă lunară. Folosiți după lovituri critice.

IDS de rețea singur. Slab împotriva C2 pasiv inbound pe 443 permis către propriul VIP. Păstrați-l pentru alte amenințări; nu vă bazați pe el pentru CerealNeuron.

Kitul nostru. Îngust, transparent, ieftin de rulat, aliniat la un singur set de instrumente public. Cel mai bun ca punte între citire și răspuns.

Răspunsul matur este toate cele de mai sus, în straturi, cu CerealBox ca strat în formă de Exchange.

---

## Partea XXVI — Întrebări frecvente

Î: Va găsi acest lucru Cereal dacă doar CerealBox este în memorie și Loader a fost eliminat?

R: Poate nu. De aceea contează analiza memoriei și EDR. Kitul tot caută prefixe Neuron, șiruri de configurare și module.

Î: Putem să-l rulăm pe Exchange Online?

R: Nu. Acesta este pentru gazde Windows on-premises unde poți interoga HTTP.sys și discurile locale. Abuzul de căsuțe poștale în cloud este o clasă de probleme diferită.

Î: Este SHA-1 depășit pentru asta?

R: ESET a publicat SHA-1. Potrivim SHA-1 și SHA-256. Problemele criptografice de coliziune pentru APT de acest tip nu sunt problema practică; acoperirea este.

Î: De ce să nu probezi prefixele URI?

R: S-ar putea să vorbești cu un implant pe un server de mail în producție. Colectează, nu te juca.

Î: Înseamnă un scan curat că nu am fost niciodată compromiși?

R: Nu. Înseamnă că aceste verificări de tipar nu s-au declanșat în acest moment.

Î: Pot atacatorii să detecteze scannerul?A: Ei pot observa PowerShell și netsh dacă sunt online și urmăresc. Preferă disciplina IR în afara benzii; totuși mai bine decât speranța oarbă.

Î: Cum actualizăm IoC-urile?

R: Editează cereal-iocs.json, reîmprospătează CSV-ul cu instrumentele de mapare, păstrează istoricul git dacă este posibil.

Î: Putem împărtăși kitul cu ministere partenere?

R: Da, dacă licența și politica voastră permit; păstrați-l defensiv și autorizat. Menționați ESET pentru cercetare.

---

## Partea XXVII — Construirea unei culturi care poate folosi instrumente precum acesta

Instrumentele eșuează în culturi care pedepsesc rapoartele curate și recompensează doar compromisurile eroice. Dacă prima scanare curată Cereal este considerată timp pierdut, echipele vor înceta să o mai ruleze. Conducerea ar trebui să laude dovezile de vânătoare—JSON bazele de referință incluse.

În mod similar, culturile care cer certitudine înainte de acțiune vor întârzia în privința HTTP.sys loviturilor critice. Instruiește factorii de decizie: loviturile critice pe modele sunt suficiente pentru a începe IR, dar nu suficiente pentru a scrie declarația finală de atribuire.

Cereal este o armă a răbdării. Este concepută pentru spionaj pe termen lung. Cultura ta de vânătoare trebuie să fie de asemenea răbdătoare: permise lunare, IoC actualizate, baze de referință post-CU și refuzul de a confunda „niciun Critic astăzi” cu „niciun risc în acest an.”

## Partea XXVIII — Complement creativ: cinci metafore care ajută neexperții

1. Restaurantul care preia comenzi la ușa bucătăriei. CerealNeuron nu sună un furnizor; stă la o intrare laterală etichetată ca un coridor de serviciu normal (OWA și Autodiscover trasee).

2. Bibliotecarul care fotocopiază scrisori înainte de a le trimite. CerealBox urmărește căruciorul poștal (conducta de transport) și copiază plicurile interesante fără a adăuga un nou angajat în organigramă (fără agent de transport nou).

3. Cheia de rezervă ascunsă într-un borcan etichetat zahăr. CerealLoader stă sub nume și dosare pe care administratorii se așteaptă să fie plictisitoare (wbem, NativeImages).

4. Notițele lipicioase de unică folosință. CerealRunner livrările sunt programe mici construite pentru un scop specific, nu o aplicație uriașă de control de la distanță.

5. Micul dejun care te mănâncă. Gluma din titlu inversată: Exchange trebuia să servească poștă; a fost făcut să servească operatorii.Folosește metafore în prezentările executive; folosește hash-uri și PID-uri în canalele IR.

## Partea XXIX — Exemplu de email intern care anunță implementarea în cadrul proprietății

Subiect: Vânătoare autorizată lunară Turla Cereal pe Exchange

Implementăm un script de detectare în modul doar-citire, aliniat la cercetarea publică Turla Cereal a ESET. Acesta interoghează HTTP.sys, calculează hash-uri pentru căile de valoare mare și inspectează procesele cheie. Nu modifică fluxul de mailuri. Sunt necesare drepturi elevate. Rezultatele sunt JSON pe share-ul IR. Descoperirile critice/majore deschid un caz Sev-1 IR. Fereastra primei rulări: introduceți data. Contacte: SOC, Exchange, IR. Vă rugăm să nu ștergeți fișiere NativeImages sau wbem doar pe baza numelor lor.

Emailurile scurte supraviețuiesc. Includeți link-ul articolului lung pentru voluntarii care doresc detalii.

## Partea XXXI — Consolidarea ideilor care se potrivesc cu detectarea (încă nu este treaba scannerului)

Detectarea fără consolidare este incompletă. Luați în considerare, în cadrul controlului obișnuit al schimbărilor:

Reduceți expunerea la internet a Exchange; folosiți modele moderne de publicare și amintiți-vă că un WAF s-ar putea să nu vadă cozi HTTP.sys non-IIS așa cum vă doriți.

Stații de lucru cu acces privilegiat pentru administratori.

Cadenta CU mai rapidă.

EDR pe serverele de căsuțe poștale cu protecție împotriva manipulării.

Monitorizarea fluxului de mail pentru directoare de stadiu neobișnuite.

Monitorizare separată a rezervărilor URL HTTP.sys dacă uneltele dvs. o suportă.

Scannerul vă spune despre urmele Cereal. Consolidarea reduce fereastra în care acele urme pot fi plantate.

## Partea XXXII — Ce mijloace utile în cifre înțelege CFO

Costuri relative aproximative (ilustrative, nu estimative precise):

Un compromis persistent avansat care implică corespondența guvernamentală: cost la nivel de carieră și diplomatic - nu are un preț clar.

Reconstrucția unui server Exchange și rotirea acreditărilor: zile până la săptămâni de timp ingineresc.

Rularea lunară a unui script doar pentru citire pe un mic domeniu Exchange: minute pe gazdă.

Nu cumpărați CerealBox pentru strălucirea software-ului. Cumpărați o reducere a timpului până la prima dovadă după o divulgare publică APT. Aceasta este o măsură rațională chiar și atunci când probabilitatea ca Turla să vă aleagă organizația specifică este scăzută, pentru că tehnicile se generalizează și costul scriptului este mic.

---

## Partea XXXIII — Anexă tehnică extinsă: PE punct de intrare nativ într-o explicație accesibilă

DLL-urile gestionate obișnuite se bazează pe CLR pentru a porni codul gestionat. O asamblare în mod mixt poate să declare un punct de intrare nativ. CerealLoader abuzează de aranjamente de metadate neobișnuite astfel încât codul nativ să ruleze prima dată și ulterior să treacă în metode gestionate pe care vizualizările statice gestionate le subestimează. Scannerul nostru nu re-implementează un CLR complet. Verifică dacă un PE are un director CLR și dacă câmpul de flaguri include bitul punctului de intrare nativ. Acesta este un filtru grosier, dar util, atunci când este combinat cu locația (wbem, NativeImages) și potrivirea hash-ului. Gândiți-vă la el ca la un detector de fum, nu la un spectrometru de laborator.Analiștii care doresc o intuiție mai profundă ar trebui să citească secțiunile din documentul alb al ESET despre VTable Fixups și apoi să compare un DLL gestionat curat cu un eșantion în modul mixt într-un laborator. Scannerul există pentru ca fiecare administrator Exchange să nu fie nevoit să devină expert în runtime-ul .NET înainte de prima căutare.

## Partea XXXV — Anexă extinsă: de ce căile care arată ca Autodiscover sunt perfect psihologic

Autodiscover există pentru a ajuta clienții să găsească punctele finale. Operatorii abuzează de această așteptare. Apărătorii care revizuiesc jurnalele 443 văd forme de cale pe care au fost instruiți să le trateze ca instalații. Prefixele publice ale CerealNeuron trăiesc în acel punct mort psihologic. Valoarea scanerului este parțial emoțională: forțează o căutare deliberată a șirurilor pe care ochii tăi le-ar sări.

Aceeași psihologie se aplică căilor API integrate care arată ca ActiveSync. Mail-ul mobil este zgomotos. Zgomotul este camuflaj. O vânătoare dedicată de șiruri împotriva stării HTTP.sys taie prin acel camuflaj fără a necesita să citești fiecare linie de jurnal proxy cu ochii.

## Partea XXXVI — Un plan de adoptare pentru prima săptămână pe care îl poți copia

Ziua 1: Citește articolul ESET’s WeLiveSecurity. Răsfoiește secțiunile prefix IoC și Neuron ale white paper-ului. Inventariază serverele Exchange vizibile pe internet.

Ziua 2: Copiază folderul CerealBox pe un server de laborator Exchange sau pe un server de test Windows. Rulează Scan-Cereal.ps1 cu privilegii ridicate. Confirmă exit 0 pe un host curat.

Ziua 3: Revizuiește scriptul împreună cu echipa de operațiuni Exchange. Convinge-te asupra traseului de reținere JSON și cine primește paginile Critice.

Ziua 4: Rulează pe un server de căsuță poștală de producție în timpul unei ferestre de schimbări. Salvează JSON. Discută constatările—chiar și pe cele de tip Info—timp de cincisprezece minute.

Ziua 5: Programează sarcini lunare pentru infrastructură. Documentează modelul de operare. Redactează emailul de anunț intern.

Ziua 6: Activare opțională YARA dacă yara64 este aprobat în mediul tău.Ziua 7: Prezentați conducerea un rezumat pe un singur slide: ce este Cereal, ce ați rulat, ce veți rula lunar, ce veți face pe Critical.

Așa devin articolele programe.

## Partea XXXVII — Repriză de închidere (pentru cititorii care au derulat)

Instrumentele lui Turla, așa cum au fost documentate de ESET Research în noiembrie 2026, au transformat serverele Exchange compromise în puncte de control pasive și filtre de mail silențioase. Kitul nostru de detectare CerealBox răspunde cu un vânător PowerShell doar în citire: verificări încărcate cu IoC pentru căile Loader, hash-uri, prefixe HTTP.sys, module de proces, șiruri de configurare, YARA opțional și un companion adânc Exchange. Desfășurați-l cu privilegii ridicate, programați-l pe serverele de poștă, ajustați serios fals pozitivele și escaladați constatările Critice către IR păstrând memoria. Nu va vedea fiecare fantomă din RAM. Vă va oferi o trecere structurată și explicabilă care se potrivește cu povestea tehnică publică — și acesta este o zi de muncă solidă într-o lume în care micul dejun este servit de propriul server de poștă.Dacă redactezi un follow-up intern, descrie primul tău baseline curat sau primul tău tabletop — nu te lăuda că ai prins un stat-națiune din prima zi. Credibilitatea se acumulează mai încet decât se răspândește malware-ul, dar se acumulează.

## Anexa A — Card de comenzi rapide

Căutare generală pe gazdă:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -OutputJson .\cereal-findings.json

Cu YARA:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -RunYara -OutputJson .\cereal-findings.json

Parcurgere completă a hash-ului incidentului:

powershell -ExecutionPolicy Bypass -File .\Scan-Cereal.ps1 -FullDriveHashScan -OutputJson .\cereal-findings.json

Exchange aprofundat:

powershell -ExecutionPolicy Bypass -File .\Scan-Exchange-Cereal-Deep.ps1 -RunYara -OutputJson .\exchange-cereal.json

Coduri de ieșire: 0 = fără Critic/Ridicat; 2 = Critic/Ridicat prezent.

---

## Anexa B — Glosar pentru public mixt

Turla / Snake: Grup aliniat Rusiei APT, actor de spionaj de lungă durată.

Cereal: Numele folosit de ESET pentru acest set de instrumente modular, axat pe Exchange.

CerealNeuron: Componentă de backdoor pasivă HTTPS.

CerealBox: Componentă de colectare a email-urilor în memorie, în interiorul EdgeTransport.

CerealLoader: Loader .NET pe disc, folosind trucuri avansate de execuție.

HTTP.sys: Stivă HTTP kernel Windows folosită de IIS și HttpListener.

NativeImages: Cache de asamblări .NET precompilat.

IoC: Indicator de compromitere (hash, cale, șir, model).

IR: Răspuns la incidente.

CU: Actualizare cumulativă Exchange.

---

## Anexa D — Notă de încheiere etică

Raportarea publică APT există pentru ca apărătorii să poată acționa. A acționa înseamnă vânătoare autorizată, comunicare atentă și respect față de victime — inclusiv guvernele care deja au avut un an greu. Folosește acest articol și acest instrument în acest spirit. Acordă credit cercetătorilor. Împărtășește îmbunătățirile. Nu transforma intruziunea altcuiva într-o momeală pentru angajament fără scop.

---

*Sfârșitul schiței articolului.*

## Partea XXXVIII — Lectura unui apărător asupra punctelor cheie ale ESET (parafrazate pentru acțiune)

Această secțiune nu reproduce articolul ESET. Ea transformă punctele cheie publice în acțiuni ale apărătorului pe care CerealBox le susține.

Punct cheie: un set de instrumente modulare nedocumentat a apărut într-o organizație guvernamentală, apoi într-o alta.  
Acțiune: tratați Cereal ca relevant pentru patrimoniu în guvern și sectoarele adiacente; efectuați vânătoare în cadrul patrimoniului, nu curiozitate pe un singur gazdă.

Punct cheie: design de lungă durată pentru spionaj cibernetic asupra Exchange.  
Acțiune: programați vânători recurente; o singură scanare este un eșantion, nu un program.

Punct cheie: nu a fost observată infrastructură de rețea externă; backdoor pasiv pe Exchange.  
Acțiune: prioritizați HTTP.sys și analiza căilor de intrare în locul listelor de blocare pentru domenii de ieșire pentru această clasă de amenințare.

Punct cheie: comenzile sosesc ca executabile separate cu structură similară.Acțiune: așteptați diversitatea hash-urilor; păstrați pachetele IoC actualizate; nu vă bazați pe un singur SHA-256 pentru totdeauna.

Punct cheie: colectarea automată a emailurilor prin injecție în transportul Exchange.
Acțiune: inspectarea modulului EdgeTransport și pregătirea memoriei; nu aveți încredere doar în listele de agenți.

Punct cheie: trucuri .NET, inclusiv puncte de intrare neadministrate și abuzul cache-ului pentru imagini native.
Acțiune: euristica punctului de intrare nativ PE plus vânătoare de căi NativeImages.

Fiecare punct este o punte de la jurnalism la operațiuni. CerealBox este schela de sub acele poduri.

## Partea XXXIX — Invitația finală

Dacă ai citit până aici, ești publicul care de fapt rulează scripturile. Mulțumim pentru răbdarea ta. Industria produce mai multe capturi de ecran decât vânătoare. Fii excepția în această lună: ridică, rulează, salvează JSON, programează următorul, și învață un coleg ce legătură are HTTP.sys cu o metaforă de mic dejun.

Când va sosi următoarea prezentare Exchange-centrată APT — și va sosi — vei deține deja un model pentru răspuns: citește, mapează, scrie script, stabilește baza, escaladează. CerealBox este un exemplu al acelui model. Furi modelul chiar dacă înlocuiești fiecare linie din PowerShell cu propriul tău conținut.Operatorii care au construit Cereal au fost creativi în interiorul manualelor Windows și Exchange pe care aproape nimeni nu le citește de plăcere. Întâlnirea cu acea creativitate necesită apărători care să poată fi creativi fără a fi imprudenți: întâi doar citire, întotdeauna păstrarea dovezilor și umilință în fața fantomelor pe care doar memoria le va arăta.

Apoi scanează un server Exchange pe care ești autorizat să-l aperi.

## Partea XLI — Script pentru atelier: predarea CerealBox în nouăzeci de minute

Minutele 0-10: Afișați titlul ESET și propoziția despre Exchange ca C2. Întrebați sala care ar fi vânătoarea lor actuală. Scrieți răspunsurile pe tablă. Majoritatea sălilor listează domenii, IDS și antivirus. Încercuiți golurile.

Minutele 10-25: Parcurgeți diagrama componentelor la un nivel înalt: Loader, Neuron, Box, Iron, Runner. Nu este nevoie de profunditatea unui white-paper complet. Opriți-vă când toată lumea poate spune care componentă este pasivă și care fură mailuri.

Minutele 25-40: Demonstrație live pe o mașină virtuală de laborator. Rulați Scan-Cereal.ps1. Arătați JSON. Arătați codul de ieșire. Rulați intenționat o dată fără privilegii pentru a arăta avertismentul Medium despre HTTP.sys. Învățați onestitatea în privința privilegiilor.

Minutele 40-55: Împărțiți participanții în perechi. Fiecare pereche primește o formă tipărită a constatărilor (HTTP.sys critic, hash critic, modul ridicat, doar informație). Trebuie să scrie următoarele trei acțiuni IR. Reuniți-vă și comparați.Minutele 55-70: Exchange demonstrație script profund. Discută Get-TransportAgent limitări. Roagă un Exchange administrator să reacționeze în timp real. Capturează miturile.

Minutele 70-85: Elaborează un plan de adoptare pe treizeci de zile pe notițe adezive: cine deține IoC, cine aprobă ridicarea, unde locuiește JSON, ce înseamnă Sev-1.

Minutele 85-90: Încheiere: credit ESET, reafirmă limitele, stabilește o dată pentru prima scanare a liniei de bază în producție.

Atelierele creează limbaj comun. Limbajul comun face ca constatările critice să fie accesibile fără panică.

## Partea XLII — Limbajul registrului de risc pe care îl poți lipi în unelte GRC

Titlu risc: Abuz on-premises Exchange prin unelte pasive APT similare cu Turla Cereal.

Descriere: Un actor capabil poate transforma Exchange expuse pe internet într-un canal de comandă pasiv și poate colecta e-mailuri din pipeline-ul de transport fără a înregistra un nou agent de transport.

Controale existente: EDR, antivirus, proces CU, monitorizare rețea, stratificarea administratorilor.

Extindere control: Vânători de tipare CerealBox lunar, doar pentru citire, pe serverele de căsuțe poștale; actualizări IoC în termen de șapte zile de la informații publice; playbook IR pentru hit-uri hash Critical HTTP.sys sau Loader, inclusiv capturarea memoriei înainte de remediere.

Risc rezidual: Etapele doar în memorie pot evita detectarea prin vânătoarea de tipare pe gazdă; riscul rezidual acceptat cu EDR compensator și reduceri în publicarea pe rețea.

Proprietar: inserați rol. Ciclu de revizuire: trimestrial.GRC echipele apreciază declarațiile de control concrete. Oferiți-le una.

## Partea XLIII — Note pentru traducători și local CERTs

Dacă traduceți acest articol, păstrați identificatorii tehnici neschimbați: numele fișierelor, fragmentele URI, algoritmii de hash, numele scripturilor și numele de detectare ESET. Traduceți metaforele cu atenție; glumele despre micul dejun nu au același efect în toate limbile. Păstrați întotdeauna avertizarea de autorizare: utilizare defensivă doar pe sistemele pe care le dețineți sau pe care aveți contract pentru evaluare.

Național CERTs ar putea dori să distribuie IoC JSON prin canalele sectoriale existente. Asociați distribuția cu secțiunea de limite pentru ca destinatarii să nu trateze un scan curat drept un certificat de sănătate pentru raportarea politică.

---

## Partea XLIV — Postfață

Ingineria detectării este o artă a atenției. Cereal răsplătește atacatorii care acordă atenție internelor Exchange. CerealBox este încercarea noastră de a acorda atenție înapoi—prin scripturi care pot fi citite, mapate, programate și îmbunătățite. Dacă acest articol lung te-a ajutat să vezi forma acelei atenții suficient de clar pentru a rula o singură scanare elevată săptămâna aceasta, și-a făcut treaba. Dacă te-a ajutat, de asemenea, să îi explici cuiva de ce HTTP.sys contează atunci când un blog spune că nu există un server C2, a făcut ceva mai rar.

Îți mulțumim că ai citit cu atenție. Acum mergi să aperi un server de email.

*Document complet.*

## Partea XLV — O a doua încheiere pentru cei care răsfoiesc

Răsfoitori: iată articolul în douăsprezece linii.

1. ESET a publicat Turla Cereal cercetare în noiembrie 2026.
2. Exchange poate fi pasiv C2.
3. CerealBox (malware) fură e-mailuri în EdgeTransport fără un agent nou.
4. CerealLoader persistă prin căi wbem și trucuri NativeImages.
5. Am construit CerealBox (unealtă): doar citire, vânătoare PowerShell.
6. Încarcă IoC din JSON și YARA opțional.
7. Verifică căi, hash-uri, HTTP.sys, module, șiruri, context Exchange.
8. Există script aprofundat pentru servere de căsuțe poștale.
9. Se implementează cu privilegii înalte; se programează lunar; se păstrează JSON.
10. Ieșirea 2 înseamnă Critic sau Ridicat—pornește IR, păstrează memoria.
11. Limitări: fantomele din memorie se pot ascunde; curățarea nu înseamnă niciodată compromis.
12. Credit ESET; vânați doar gazdele autorizate.

Dacă aveți nevoie doar de aceste douăsprezece linii, tot trebuie să rulați unealta. Răsfoirea nu este scanare.

## Partea XLVI — Paragraf de recunoaștere pe care îl puteți personaliza

Mulțumim cercetării ESET, în special lucrării publice realizate de Matias Porolli și colegii săi, pentru documentarea Cereal cu suficientă claritate tehnică încât apărătorii să poată construi verificări pe gazde. Mulțumim administratorilor Exchange care revizuiesc scripturile de detectare înainte de producție, analiștilor SOC care cer un nivel scăzut de alarme false și liderilor IR care insistă pe disciplina „memorie mai întâi”. Orice eroare din acest articol ne aparține. Amenințarea aparține operatorilor care au construit Cereal. Responsabilitatea de a vâna aparține celor dintre noi care mențin fluxul de e-mail pentru toți ceilalți.

---

## Partea XLVII — Notă privind versiunea articolului și a instrumentului

Articolele îmbătrânesc. Instrumentele îmbătrânesc mai repede. Când circulați o versiune actualizată, precizați data și versiunea instrumentului sau commit-ul, dacă aveți unul. Când IoC se actualizează, emiteți un scurt follow-up în loc să editați istoria în tăcere în moduri pe care cititorii nu le pot vedea. Conținutul de detectare merită aceeași igienă a modificărilor ca și codul.

Subsol sugerat: Publicat în noiembrie 2026. Calea instrumentului: Scan-Cereal.ps1 cu cereal-iocs.json. Bază de cercetare: articolul și lucrarea albă ESET WeLiveSecurity Cereal. Folosire defensivă doar.

---

## Partea XLVIII — Un ultim inventar practic înainte de a părăsi pagina

Întreabă-te pe hârtie:

Câte servere Exchange orientate spre internet mai rulăm încă?

Cine poate obține privilegii ridicate pe ele săptămâna aceasta?

Unde ar fi stocate rezultatele JSON pentru ca IR să le poată găsi peste un an?

Ce consolă EDR am deschide dacă HTTP.sys ar returna mâine un prefix de tip Neuron?

Am informat conducerea că Get-TransportAgent poate părea normal în timpul unui abuz de tip CerealBox?

Avem o metodă de captură a memoriei care funcționează pe EdgeTransport la scara noastră?

Procesul nostru CU este suficient de rapid încât NativeImages baseline-urile să fie măcar cunoscute?

Cine actualizează IoC atunci când repository-ul malware-ioc al lui ESET se schimbă?

Cine are voie să spună cuvântul reconstruire fără o ceartă de trei săptămâni?

Dacă nu puteți răspunde la două sau mai multe dintre acestea, următorul cititor al articolului ar trebui să fie proprietarul dvs. Exchange, nu un canal de marketing. Claritatea proprietății vine pe primul loc.

Când aceste răspunsuri există, CerealBox devine ușor de implementat: un dosar, un program, un model de severitate și un obicei de a privi unde cercetarea publică a spus să priviți. Acest obicei—mai mult decât orice script individual—este ceea ce transformă metaforele micului dejun în corespondență apărată.

## Note finale

Acest articol de lungă durată este destinat apărătorilor autorizați, inginerilor de detecție, Exchange operatorilor și liderilor de securitate. Rezumă constatările publice ESET privind setul de instrumente Cereal al Turla și descrie un kit de detecție doar pentru citire PowerShell—CerealBox—inclusiv modul în care funcționează scanerul, cum poate fi implementat și de ce este util ca însoțitor al antivirusului și EDR. Nu oferă malware, exploit-uri sau instrucțiuni de atac. Verificați întotdeauna scripturile într-un laborator, urmați procesul de modificare și păstrați probele judiciare înainte de remediere. Pentru narațiunea principală a cercetării publice, citiți articolul WeLiveSecurity al ESET și documentul alb însoțitor. Pentru comenzile operaționale și structura fișierelor, consultați README-Cereal-Scanner.md în folderul kitului.

Rămâneți curioși. Rămâneți autorizați. Păstrați corespondența să circule doar către persoanele potrivite.

Dacă îmbunătățiți kitul, documentați schimbările, testați pe gazde curate și împărtășiți îmbunătățirile defensive cu colegi de încredere. Scopul este un timp mai scurt de la cercetarea publică la dovezile de pe gazdă — nu marketing mai zgomotos. Rulați scannerul, citiți JSON și mențineți Exchange plictisitor din nou.