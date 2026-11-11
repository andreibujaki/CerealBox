/*
  Turla Cereal pattern rules — defensive hunting only.
  Based on public ESET research (CerealLoader native entrypoint,
  CerealNeuron URI strings, config key, hijack filenames) and
  github.com/eset/malware-ioc turla sample hashes.
*/
import "pe"
import "hash"

private rule Cereal_DotNet
{
    condition:
        pe.is_pe and (pe.imports("mscoree.dll", "_CorDllMain") or pe.imports("mscoree.dll", "_CorExeMain"))
}

rule Cereal_KnownSha256
{
    meta:
        description = "Known Cereal-related SHA-256 from ESET IoC / VT-verified pairs"
        author = "CerealBox scanner"
        reference = "ESET Turla Cereal white paper + eset/malware-ioc"
        severity = "critical"
    condition:
        hash.sha256(0, filesize) == "13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0" or
        hash.sha256(0, filesize) == "241aac14756a0f29edd084b858623db259d59c77ea44889de93431c42ff10036" or
        hash.sha256(0, filesize) == "6119d25ae51d04264384f5d738c104e42596b0774609666b357a43608a48404c" or
        hash.sha256(0, filesize) == "41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651" or
        hash.sha256(0, filesize) == "d3b6065eb001d169421fcd146f64b087055dadebd973d8d69ae2bf97fbf288e2" or
        hash.sha256(0, filesize) == "44877a8bce6465f6f73cbe667bc9b3fe8dfae7921814ed92c52a4464cc7e2367" or
        hash.sha256(0, filesize) == "28a7f4e290b7cb090e0c4808271558c4816f2f37489638177951d52d1dc6d48e" or
        hash.sha256(0, filesize) == "12e2060236a9b2a2933dfdb92b571949f7595fbe884642de83fea2817f17b94f" or
        hash.sha256(0, filesize) == "0b6ad919625e64cba69ac9c282ec64f3aa22bff2d13c0e4080adde7c2921f547" or
        hash.sha256(0, filesize) == "739bebd15b29b43877471ea186587c013a2aa0e4017520f04b07ebeeda228d6c" or
        hash.sha256(0, filesize) == "f801aab6051a866f78c4b9ed34f6efea01f0880248e2d4d43cc0af0c29869793" or
        hash.sha256(0, filesize) == "a8a7780f2175634f08f2f535d569397b95a367b41d6a2afd7d03e873406198eb" or
        hash.sha256(0, filesize) == "c7b13ec4c2affcef4e0337936f8535a554c14259e881ab9e23931f08956c6c2d" or
        hash.sha256(0, filesize) == "8e2d96dba54941e891b4a4183e2e2ff8bcd2479da63b3a6e718b0b27cb4d8c8a" or
        hash.sha256(0, filesize) == "0cebbdb239afbe4116334d8043be2ec8957a024bd9320bb3de3499f7ed3fca04" or
        hash.sha256(0, filesize) == "2ccf0f05700ed3bc79d31f2541dda3b46ec4e958ba845cbe58977a58bcc78e86" or
        hash.sha256(0, filesize) == "77bb1fcf636cb9c42df7404ac5318bf0885e2042d3cbad25e15b5e192d9d04b7" or
        hash.sha256(0, filesize) == "4514195c893579961f5379fea4de28845663e54cb52cf923d0361e0db97391ea"
}

rule CerealLoader_NativeEntrypoint_DotNet
{
    meta:
        description = "CerealLoader-style mixed-mode .NET with COM descriptor (pair with scanner native-entrypoint check)"
        author = "CerealBox scanner"
        reference = "ESET Turla Cereal white paper"
        severity = "high"
    condition:
        Cereal_DotNet and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
        filesize < 2MB and
        pe.imports("mscoree.dll")
}

rule Cereal_SuspiciousFilenames
{
    meta:
        description = "Filenames used by CerealLoader masquerade / hijacks"
        severity = "medium"
    strings:
        $a = "ncobjapi.dll" nocase
        $b = "Microsoft.Exchange.Data.Transport.ni.dll" nocase
        $c = "Microsoft.Exchange.Search.Mdb.ni.dll" nocase
        $d = "Microsoft.Exchange.EdgeSyncSvc.ni.exe" nocase
        $e = "EdgeTransport.ni.exe" nocase
        $f = "FallbackLog.bin" nocase
        $g = "iph.dat" nocase
        $h = "Microsoft.Ceres.dll" nocase
        $i = "Microsoft.Search.Platform.dll" nocase
    condition:
        any of them
}

rule CerealNeuron_UriPrefixes
{
    meta:
        description = "CerealNeuron HttpListener URI path fragments"
        severity = "critical"
    strings:
        $s1 = "owa/sdds" nocase ascii wide
        $s2 = "AUTODISCOVER/MICROSOFT.EXCHANGE.PROXYSERVICE" nocase ascii wide
        $s3 = "AUTODISCOVER/INTEGRATED/API" nocase ascii wide
        $s4 = "AUTODISCOVER/PROXYSERVICE" nocase ascii wide
        $s5 = "MICROSOFT-SERVER-ACTIVESYNC/INTEGRATED/API" nocase ascii wide
        $s6 = "HttpListener" ascii wide
    condition:
        2 of ($s1,$s2,$s3,$s4,$s5) or ($s6 and 1 of ($s1,$s2,$s3,$s4,$s5))
}

rule Cereal_ConfigKey_MD5
{
    meta:
        description = "CerealNeuron/CerealBox configuration dictionary key observed by ESET"
        severity = "high"
    strings:
        $k1 = "B38C96AE6643D2AB5C0BFE823D9C9017" ascii wide nocase
        $k2 = { B3 8C 96 AE 66 43 D2 AB 5C 0B FE 82 3D 9C 90 17 }
    condition:
        any of them
}

rule Cereal_ExchangeTransport_Hooks
{
    meta:
        description = "Strings related to Exchange transport agent hijack (CerealBox)"
        severity = "high"
    strings:
        $a = "RoutingAgentFactory" ascii wide
        $b = "EdgeTransport" ascii wide
        $c = "Microsoft.Exchange.Transport" ascii wide
        $d = "mexRuntime" ascii wide
        $e = "factoryTable" ascii wide
        $f = "MimeDocument" ascii wide
    condition:
        3 of them
}

rule CerealSprinter_AmsiBypass_Mutex_Hints
{
    meta:
        description = "Hints seen around CerealSprinter (AMSI bypass field + logging)"
        severity = "medium"
    strings:
        $a = "amsiInitFailed" ascii wide
        $b = "FallbackLog.bin" ascii wide nocase
        $c = "ModuleVersionId" ascii wide
    condition:
        2 of them
}

rule Cereal_WbemHijack_Candidate
{
    meta:
        description = "PE that references wbem hijack paths used by CerealLoader"
        severity = "high"
    strings:
        $p1 = "System32\\wbem\\ncobjapi.dll" nocase ascii wide
        $p2 = "System32\\wbem\\wbemcomn.dll" nocase ascii wide
        $p3 = "ncobjapi.dll" nocase ascii wide
    condition:
        pe.is_pe and 2 of them
}
