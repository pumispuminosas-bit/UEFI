/*
 * UEFI SCS Implant Detection Rules
 * Based on forensic analysis: reverse.txt, reverse_2.txt
 * Detects SCS (Steganographic Container Suite) UEFI implants
 */

rule SCS_Implant_Mullins_Marker {
    meta:
        description = "SCS Mullins variant implant marker"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI Rootkit"
    strings:
        $marker = "!SCSMullins" ascii wide
        $version = "V0.0.0.1" ascii wide
    condition:
        $marker and $version
}

rule SCS_Implant_Kabini_Marker {
    meta:
        description = "SCS Kabini variant implant marker"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI Rootkit"
    strings:
        $marker = "!SCSKABINI" ascii wide
        $version = "V0.0.0.1" ascii wide
    condition:
        $marker and $version
}

rule SCS_Control_Block {
    meta:
        description = "SCS implant runtime control block"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "HIGH"
        threat_type = "UEFI Rootkit"
    strings:
        $control = "8!SCSu,!}" ascii
    condition:
        $control
}

rule SCS_Generic_Marker {
    meta:
        description = "Generic SCS marker (any variant)"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI Rootkit"
    strings:
        $scs1 = "!SCS" ascii
        $scs2 = "SCS" ascii
    condition:
        any of ($scs*)
}

rule PE32_EFI_Boot_Driver {
    meta:
        description = "PE32 EFI boot service driver - potential implant"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "HIGH"
        threat_type = "UEFI Rootkit"
    strings:
        $pe_header = "MZ" 
        $pe_sig = "PE\x00\x00"
        $text_section = ".text" ascii
        $reloc_section = ".reloc" ascii
    condition:
        $pe_header at 0 and
        $pe_sig and 
        ($text_section or $reloc_section) and
        uint16(0x3c) < 0x200
}

rule Certificate_Steganography_PE_Payload {
    meta:
        description = "PE executable embedded in X.509 certificate"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "Certificate Steganography"
    strings:
        $cert_der = { 30 82 } // ASN.1 SEQUENCE, long form
        $pe_header = "MZ" nocase
        $pe_sig = "PE\x00\x00"
    condition:
        $cert_der and $pe_header and $pe_sig
}

rule UEFI_Network_Protocol_Abuse {
    meta:
        description = "Abuse of UEFI network protocols (potential C2)"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "HIGH"
        threat_type = "UEFI C2 Communication"
    strings:
        $protocol1 = "gEfiUdp4Protocol" ascii wide
        $protocol2 = "gEfiIp4Protocol" ascii wide
        $protocol3 = "gEfiPciIoProtocol" ascii wide
        $gateway = { 00 00 00 01 } // 0.0.0.1 in network byte order
    condition:
        ($protocol1 or $protocol2 or $protocol3) and $gateway
}

rule Fake_AGESA_Identifier {
    meta:
        description = "Fake or suspicious AGESA version string"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "MEDIUM"
        threat_type = "UEFI Rootkit"
    strings:
        $agesa = "AMD AGESA" ascii wide
        $fake_version = "V1.0.0.7" ascii wide  // Non-existent version
        $nano110 = "Nano110" ascii wide  // Server codebase on consumer device
    condition:
        ($agesa and $fake_version) or
        ($agesa and $nano110)
}

rule PEI_DXE_Implant_Pattern {
    meta:
        description = "Potential implant in PEI/DXE phase drivers"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "HIGH"
        threat_type = "UEFI Rootkit"
    strings:
        $pei_marker = "PEI" ascii wide
        $dxe_marker = "DXE" ascii wide
        $scs_marker = "!SCS" ascii wide
        $pe_header = "MZ"
    condition:
        ($pei_marker or $dxe_marker) and
        $scs_marker and
        $pe_header
}

rule SMM_Communication_Protocol {
    meta:
        description = "SMM communication protocol - potential SMM persistence"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI SMM Rootkit"
    strings:
        $smm_protocol = "SmmCommunication" ascii wide
        $smm_handler = "SmmHandler" ascii wide
        $scs_marker = "!SCS" ascii wide
    condition:
        ($smm_protocol or $smm_handler) and $scs_marker
}

rule Phoenix_Build_Path_Anomaly {
    meta:
        description = "Suspicious Phoenix build path suggesting build server compromise"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "MEDIUM"
        threat_type = "Supply Chain Compromise"
    strings:
        $phoenix_path = "D:\\BIOS\\CGX21" ascii wide
        $server_codebase = "Nano110" ascii wide  // Server code on consumer device
        $suspicious_char = "\\...\\" ascii  // Path traversal
    condition:
        $phoenix_path and ($server_codebase or $suspicious_char)
}

rule Network_C2_Endpoints {
    meta:
        description = "Known C2 command server endpoints"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI C2"
    strings:
        $c2_local = { 00 00 00 01 }  // 0.0.0.1 in network byte order
        $c2_remote = { 01 00 00 07 } // 1.0.0.7 in network byte order
    condition:
        any of them
}

rule Legitimate_Microsoft_UEFI_CA_Abuse {
    meta:
        description = "Legitimate Microsoft UEFI CA certificate used to bypass Secure Boot"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "HIGH"
        threat_type = "Secure Boot Bypass"
    strings:
        $ms_ca = "Microsoft UEFI CA 2011" ascii wide
        $scs_marker = "!SCS" ascii wide
        $pe_executable = "MZ"
    condition:
        $ms_ca and $scs_marker and $pe_executable
}

rule ESP32_Container_Anomaly {
    meta:
        description = "ESP32-like container at unusual firmware offset (potential obfuscation)"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "MEDIUM"
        threat_type = "UEFI Rootkit"
    strings:
        $esp32_magic = { E9 02 00 00 }  // ESP32 image magic
        $scs_marker = "!SCS" ascii wide
    condition:
        $esp32_magic and $scs_marker
}

rule Multiple_SCS_Variants {
    meta:
        description = "Multiple SCS implant variants in single firmware"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI Rootkit"
    strings:
        $mullins = "!SCSMullins" ascii
        $kabini = "!SCSKABINI" ascii
        $control = "8!SCSu,!}" ascii
    condition:
        2 of them
}

rule Steganographic_UEFI_Container {
    meta:
        description = "Steganographic container with embedded PE executable in UEFI structure"
        author = "UEFI Security Team"
        date = "2026-05-08"
        severity = "CRITICAL"
        threat_type = "UEFI Rootkit"
    strings:
        $asn1_seq = { 30 82 }  // ASN.1 SEQUENCE
        $asn1_set = { 31 82 }  // ASN.1 SET
        $pe_header = "MZ"
        $pe_signature = "PE\x00\x00"
        $scs = "!SCS" ascii
    condition:
        (any of ($asn1_seq, $asn1_set)) and
        $pe_header and
        $pe_signature and
        $scs
}
