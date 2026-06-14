/*
 * SIFT Sentinel — dataset-agnostic starter ruleset.
 *
 * These rules cover well-known generic forensic indicators ONLY. They
 * contain no environment-specific PIDs, paths, IPs, hashes, filenames,
 * or other artifacts of any particular evidence dataset. Adding such
 * specifics here would violate DATASET-AGNOSTIC ABSOLUTE.
 *
 * Calibration goal: high specificity, low false-positive rate on
 * legitimate Windows binaries. Three rules to start; future slots can
 * expand the set once Block 2 measures baseline hit/FP counts.
 */

rule UPX_Packed_Binary
{
    meta:
        author      = "SIFT Sentinel"
        category    = "packer"
        description = "PE binary packed with UPX (well-known compressor)"
        confidence  = "high"
        ttp         = "T1027.002"  // Software Packing
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $sig  = "UPX!" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Suspicious_Encoded_PowerShell
{
    meta:
        author      = "SIFT Sentinel"
        category    = "powershell"
        description = "PowerShell invocation with EncodedCommand + bypass markers"
        confidence  = "medium"
        ttp         = "T1059.001"  // PowerShell
    strings:
        $enc1   = "-EncodedCommand" ascii nocase
        $enc2   = " -enc " ascii nocase
        $iex1   = "Invoke-Expression" ascii nocase
        $iex2   = "IEX" ascii fullword
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
    condition:
        (any of ($enc1, $enc2)) and (any of ($iex1, $iex2, $bypass, $hidden))
}

rule Reflective_DLL_Loader_Signature
{
    meta:
        author      = "SIFT Sentinel"
        category    = "process_injection"
        description = "Reflective DLL loader symbol (Cobalt Strike, MSF, custom)"
        confidence  = "high"
        ttp         = "T1620"  // Reflective Code Loading
    strings:
        $rdl1 = "ReflectiveLoader" ascii
        $rdl2 = "_ReflectiveLoader@" ascii
    condition:
        any of them
}
