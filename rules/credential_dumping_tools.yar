rule Credential_Dumping_Tools
{
    meta:
        description = "Detects known credential dumping tools"
        author = "SanSan Detection"
        platform = "cross‑platform"
        threat_type = "Credential Access"
        updated = "2025-08-05"

    strings:
        $mz1 = "mimikatz" nocase
        $mz2 = "sekurlsa::logonpasswords" nocase
        $lz1 = "LaZagne" nocase
        $lz2 = "credentials.db" nocase
        $lz3 = "dumpCreds" nocase

    condition:
        any of ($mz*) or any of ($lz*)
}
