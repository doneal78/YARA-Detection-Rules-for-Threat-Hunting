rule Persistence_Mechanisms
{
    meta:
        description = "Detects techniques used for persistence across OS platforms"
        author = "SanSan Detection"
        platform = "cross‑platform"
        threat_type = "Persistence"
        updated = "2025-08-05"

    strings:
        $win1 = "Run\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $win2 = "schtasks /create" nocase
        $mac1 = "Library/LaunchAgents" ascii
        $linux1 = "/etc/rc.local" ascii
        $linux2 = "crontab -e" ascii

    condition:
        any of ($win*) or $mac1 or any of ($linux*)
}