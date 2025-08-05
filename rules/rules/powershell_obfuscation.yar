rule Powershell_Obfuscation
{
    meta:
        description = "Detects obfuscated or encoded PowerShell commands"
        author = "SanSan Detection"
        platform = "Windows"
        threat_type = "Execution / Evasion"
        updated = "2025-08-05"

    strings:
        $ps1 = "FromBase64String" nocase
        $ps2 = "New-Object IO.StreamReader" nocase
        $ps3 = "IEX" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "powershell -e" nocase

    condition:
        2 of ($ps*)
}
