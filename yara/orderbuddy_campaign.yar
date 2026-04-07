/**
 * YARA Rules — OrderBuddy LinkedIn Malware (Campaign 40abc1fa2901)
 * SHA256: 2ac11f7302ea0e35e7626fb2bc4f4b68c047313c0fc5cc5681a850cf1b164047
 *
 * Opus Review: 2026-02-28 — Rules rewritten to match actual obfuscated byte
 * patterns present in the samples (not cleartext IOCs that only exist after
 * deobfuscation).
 */

rule OrderBuddy_Infostealer_TestJS {
    meta:
        description = "OrderBuddy test.js infostealer — Chrome/Edge/Opera/Brave credential theft"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "critical"
        hash = "d273e7fc22daa42d8cb20b833c52c0cddca1a967891c9bab4573d3a6a4b925d7"
    strings:
        $c2_b64_fragment = "E3NS4xMTc=NjYuMjM1Lj" ascii
        $victim_id       = "ryGnMe8" ascii
        $interval_hex    = "0x975e0" ascii
        $xor_key_30      = "0xd0,0x59,0x18" ascii
        $set_interval    = "setInterval" ascii
        $base64_enc      = "'base64'" ascii
        $buffer_from     = "Buffer" ascii
    condition:
        $c2_b64_fragment and $victim_id and $set_interval and
        ($interval_hex or $xor_key_30) and $base64_enc and $buffer_from
}

rule OrderBuddy_FileExfil_PJS {
    meta:
        description = "OrderBuddy p.js — file exfiltration module targeting sensitive files"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "critical"
        hash = "4b154b8e35e4cbb3f9851b503b8245bfec601b00330690ef3d2a66bf42c4077b"
    strings:
        $c2_b64_fragment = "E3NS4xMTc=NjYuMjM1Lj" ascii
        $victim_id       = "ryGnMe8" ascii
        $pat_new         = "pat_new" ascii
        $ex_str          = "ex_str" ascii
        $ex_files        = "ex_files" ascii
    condition:
        $c2_b64_fragment and $victim_id and $pat_new and ($ex_str or $ex_files)
}

rule OrderBuddy_SSH_RAT_NJS {
    meta:
        description = "OrderBuddy njs_ryGnMe8.js — SSH/FTP RAT with remote shell"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "critical"
        hash = "8efb64fb702476ff55e6ebf5be38ec0b53eec0d9e456695099a149c8810dac7d"
    strings:
        $c2_b64_fragment = "E3NS4xMTc=NjYuMjM1Lj" ascii
        $victim_id       = "ryGnMe8" ascii
        $ssh_upload      = "ssh_upl" ascii
        $ssh_cmd         = "ssh_cmd" ascii
        $ssh_obj         = "ssh_obj" ascii
        $storbin         = "storbin" ascii
        $basic_ftp       = "basic-f" ascii
        $keys_endpoint   = "/keys" ascii
        $port_1244       = "1244" ascii
        $ip_api          = "ip-api." ascii
    condition:
        $c2_b64_fragment and $victim_id and
        3 of ($ssh_upload, $ssh_cmd, $ssh_obj, $storbin, $basic_ftp) and
        $keys_endpoint and $port_1244 and $ip_api
}

rule OrderBuddy_Python_RAT {
    meta:
        description = "OrderBuddy main_ryGnMe8.py — Python reverse shell (outer layer decoded)"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "critical"
        hash = "7ddff976b79ef4010a2d1e14938bbd33b3749febe39c8757df987d8cf54acd3c"
    strings:
        $c2_b64_fragment = "E3NS4xMTc=NjYuMjM1Lj" ascii
        $port_assign     = "pt0=1244" ascii
        $zlib_import     = "zlib" ascii
        $exec_call       = "exec" ascii
        $b64_import      = "base64" ascii
        $lambda_pattern  = "lambda" ascii
    condition:
        $c2_b64_fragment and $port_assign and $zlib_import and $exec_call and $b64_import and $lambda_pattern
}

rule OrderBuddy_VSCode_Tasks {
    meta:
        description = "OrderBuddy .vscode/tasks.json — auto-exec on folder open"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "high"
    strings:
        $runOn       = "runOn" ascii
        $folderOpen  = "folderOpen" ascii
        $short_gy    = "short.gy" ascii
        $vercel      = "vercel.app" ascii
    condition:
        $folderOpen and $runOn and ($short_gy or $vercel)
}

rule OrderBuddy_Campaign_Generic {
    meta:
        description = "Generic detection for any OrderBuddy campaign artifact"
        author = "Forensics (Opus-reviewed)"
        date = "2026-02-28"
        severity = "high"
    strings:
        $c2_b64_fragment = "E3NS4xMTc=NjYuMjM1Lj" ascii
        $victim_id       = "ryGnMe8" ascii
        $campaign_id     = "40abc1fa2901" ascii
    condition:
        $c2_b64_fragment and ($victim_id or $campaign_id)
}
