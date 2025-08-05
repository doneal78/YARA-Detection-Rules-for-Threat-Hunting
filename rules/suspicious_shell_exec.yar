rule Suspicious_Shell_Exec
{
    meta:
        description = "Detects suspicious shell execution patterns"
        author = "SanSan Detection"
        platform = "cross-platform"
        threat_type = "Execution"
        updated = "2025-08-05"

    strings:
        $cmd1 = "curl " nocase
        $cmd2 = "wget " nocase
        $cmd3 = "bash -c" nocase
        $cmd4 = "/bin/sh -c" nocase
        $cmd5 = "Invoke-WebRequest" nocase
        $cmd6 = "Invoke-Expression" nocase
        $cmd7 = "powershell -enc" nocase

    condition:
        any of ($cmd*)
}
