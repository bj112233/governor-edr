rule powershell_encoded_command {
    meta:
        description = "Detects PowerShell encoded command patterns in files"
        mitre = "T1059.001"
        severity = "high"
    strings:
        $enc1 = /-en[c(oded(command)?)?]?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $enc2 = /\[convert\]::frombase64string/ nocase
        $enc3 = /-executionpolicy\s+(bypass|unrestricted)/ nocase
    condition:
        any of ($enc*)
}

rule powershell_download_cradle {
    meta:
        description = "Detects PowerShell download cradle patterns"
        mitre = "T1059.001"
        mitre2 = "T1105"
        severity = "high"
    strings:
        $dl1 = /net\.webclient/ nocase
        $dl2 = /downloadstring/ nocase
        $dl3 = /downloadfile/ nocase
        $dl4 = /bitstransfer/ nocase
        $dl5 = /iex\s*\(/ nocase
        $dl6 = /invoke-expression/ nocase
    condition:
        2 of ($dl*)
}

rule suspicious_base64_payload {
    meta:
        description = "Large base64 blob that may hide encoded payload"
        mitre = "T1027"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64 and filesize < 1MB
}

rule web_shell_generic {
    meta:
        description = "Generic web shell patterns"
        mitre = "T1505.003"
        severity = "critical"
    strings:
        $s1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)/ nocase
        $s2 = /system\s*\(\s*\$(GET|POST|REQUEST)/ nocase
        $s3 = /passthru\s*\(\s*\$(GET|POST|REQUEST)/ nocase
        $s4 = /shell_exec\s*\(\s*\$(GET|POST|REQUEST)/ nocase
    condition:
        any of ($s*)
}

rule credential_dumper {
    meta:
        description = "Credential dumping tool patterns"
        mitre = "T1003"
        severity = "critical"
    strings:
        $s1 = "lsass" nocase
        $s2 = "procdump" nocase
        $s3 = /-ma\s+[0-9]+/ nocase
        $s4 = "sekurlsa::logonpasswords" nocase
        $s5 = "mimikatz" nocase
    condition:
        2 of ($s*)
}
