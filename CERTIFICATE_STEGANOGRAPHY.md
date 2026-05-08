# X.509 Certificate Steganography Detection

## Overview
The UEFI Sanitizer includes advanced detection of malware hidden within X.509 certificate structures. This is a sophisticated evasion technique used by implants like SCS (Steganographic Container Suite) and other UEFI rootkits.

## How It Works

### Detection Methods

1. **PEM Certificate Scanning**
   - Searches for `-----BEGIN CERTIFICATE-----` markers
   - Parses valid PEM certificates using cryptography library
   - Examines certificate extensions for embedded payloads

2. **DER Certificate Scanning**
   - Searches for ASN.1 SEQUENCE tags (0x30) with long-form length encoding
   - Treats ASN.1 structures as potential certificate containers
   - Scans for PE files, SCS markers, and other suspicious signatures within

3. **Steganographic Content Detection**
   - **PE Files (MZ headers)**: Detects executable code embedded in certificates
   - **SCS Markers**: Identifies implant markers (!SCS, !SCSKABINI, !SCSMullins)
   - **PE Sections**: Finds .text and .reloc sections indicating code payloads
   - **Known Implants**: Matches against known malware signatures

### Firmware Analysis Results

On test firmware (Lenovo.bin), the scanner detected:
- **195 suspicious items** across certificate structures
- Multiple PE files embedded at offsets like 0xac300, 0xe4bd7, 0x13241e
- SCS implant markers at 0x10b000 and 0x71c970
- PE executable sections throughout the certificate data

## Technical Implementation

### Code Structure

```python
class FfsNetworkStripper:
    def _scan_certificates_for_steganography(self, data):
        """Scans firmware for X.509 certificates with embedded malware"""
        
        # 1. Scan for PEM certificates (text-based)
        # 2. Scan for DER certificates (binary-based)
        # 3. Check for embedded PE files, SCS markers, suspicious signatures
        # 4. Return list of (offset, description) tuples
        
    def _check_certificate_extensions(self, cert, base_offset, suspicious_certs):
        """Examine certificate extensions for steganographic content"""
```

### Detection Signatures

**SCS Implant Markers:**
- `!SCS` - SCS implant marker
- `!SCSKABINI` - Kabini variant
- `!SCSMullins` - Mullins variant
- `!SCSBIOS` - BIOS variant
- `SCSKABINI`, `SCSMullins` - Variant identifiers

**PE File Indicators:**
- `MZ` - PE executable header
- `PE\x00\x00` - PE signature
- `.text` - Code section
- `.reloc` - Relocation section

## Remediation

When suspicious content is found in certificates:
1. **Detect**: Log offset and type of embedded payload
2. **Zero Out**: Overwrite regions containing embedded malware with zeros
3. **Context Buffer**: Zero surrounding regions to prevent recovery
4. **Rebuild**: Recalculate checksums after modification

### Zeroing Strategy

```python
# For certificate steganography:
start = max(0, offset - 0x200)         # 512 bytes before
end = min(len(data), offset + 0x1000)  # 4KB after
zero_out_region(data, start, end - start)
```

## Limitations & Future Work

1. **Current Limitations:**
   - Only detects common certificate formats (PEM, DER)
   - Cannot parse deeply nested ASN.1 structures
   - May produce false positives on large binary data

2. **Future Enhancements:**
   - Full ASN.1 parser for complete certificate validation
   - Behavioral analysis of certificate extensions
   - Integration with firmware analysis tools (UEFITool, Chipsec)
   - Signature updates as new implant variants emerge

## References

- UEFI Specification: https://uefi.org/specifications
- X.509 Certificate Format: RFC 5280
- SCS Implant Analysis: Reverse Engineering Reports (reverse.txt, reverse_2.txt)
- Steganography in UEFI: https://www.uefi.org/sites/default/files/resources/UEFI%20Security%20Best%20Practices_020222_0.pdf
